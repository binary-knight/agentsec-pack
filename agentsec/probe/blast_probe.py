#!/usr/bin/env python3
"""Sandbox blast-radius probe.

Runs INSIDE the environment under test (a container, a bwrap sandbox, a bare
process) and measures what a process in that environment can reach. It is
stdlib-only so it runs in any image with a Python 3.8+ interpreter.

Non-exfiltrating by construction:
  * secrets are reported by NAME and location only, never by value, and
    home-directory paths are reported unexpanded so a report carries no
    operator username;
  * network probes connect only to the fixed list below, send nothing, and
    close immediately. When an egress proxy is configured, the probe also
    sends that proxy one CONNECT request per fixed target (plus PROXY_CANARY),
    reads the status line and closes: no TLS, nothing reaches the target;
  * the proxy's password is used only when AGENTSEC_PROBE_PROXY_AUTH=1, and
    then only in a Proxy-Authorization header to the proxy it came from. It
    is never recorded, and neither is the proxy's URL or host;
  * unix sockets are connected to and closed with nothing sent, to prove
    reachability rather than infer it from permission bits;
  * the only writes are zero-byte marker files, one per probed directory
    (see WRITE_PROBE_DIRS and PERSISTENCE_DIRS), each created and removed
    immediately. That is the writability test; it can trip file-integrity
    monitoring where present;
  * existing files in PERSISTENCE_FILES (shell startup files, the agent's own
    settings) are opened for append and closed WITHOUT writing a byte, so
    content and mtime are unchanged and nothing is created. A file watcher
    still sees a close-after-write event;
  * readability is proven by opening a file and reading zero bytes, never by
    reading its contents.

Output: one JSON document on stdout. Everything else goes to stderr.
"""
import errno
import json
import os
import re
import socket
import stat
import sys
import tempfile
import time

PROBE_VERSION = "0.6.0"
IS_DARWIN = sys.platform == "darwin"

# Fixed egress targets. Add nothing dynamic here; buyers read this list.
EGRESS_TARGETS = [
    {"name": "dns-google", "host": "dns.google", "port": 443},
    {"name": "pypi", "host": "pypi.org", "port": 443},
    {"name": "github", "host": "github.com", "port": 443},
    {"name": "cloudflare-dns-ip", "host": "1.1.1.1", "port": 53},
]
# Cloud instance-metadata endpoints. Reachability alone is a finding.
METADATA_TARGETS = [
    {"name": "cloud-metadata-169.254.169.254", "host": "169.254.169.254", "port": 80},
    {"name": "gcp-metadata-hostname", "host": "metadata.google.internal", "port": 80},
]
CONNECT_TIMEOUT = float(os.environ.get("AGENTSEC_PROBE_TIMEOUT", "2.0"))
# Variables an HTTP client consults for an egress proxy. When one is set, a
# refused direct connection says nothing about what the proxy lets through, so
# the probe also asks the proxy. Reported by NAME only: a proxy URL commonly
# carries a password.
PROXY_ENV_NAMES = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
# A host no egress allowlist has a reason to contain. A proxy that accepts it
# accepts anything; one that refuses it while accepting a target is filtering.
PROXY_CANARY = {"name": "canary-example.com", "host": "example.com", "port": 443}
# The proxy password is sent to the proxy it came from ONLY when this is set to
# 1. Without it, a proxy that demands authentication answers 407 and the
# network axis is reported as not measured. Never recorded either way.
PROXY_AUTH_OPT_IN = "AGENTSEC_PROBE_PROXY_AUTH"

# Matched on whole underscore-separated words, not as substrings or vendor
# prefixes. A prefix rule flags GH_PAGER and AWS_REGION, which are not secrets;
# a substring rule flags TOKENIZERS_PARALLELISM. Bare KEY flags GPG_KEY, which
# in the official python image is the release manager's PUBLIC key fingerprint.
# All three inflate the score with names that carry nothing, so KEY is only
# counted when a qualifier makes it a credential.
_SECRET_WORDS = (r"SECRET|SECRETS|TOKEN|TOKENS|PASSWORD|PASSWD|PASSPHRASE|APIKEY|"
                 r"CREDENTIAL|CREDENTIALS|PRIVATEKEY|PAT|JWT|BEARER|OAUTH|SIGNATURE")
SECRET_ENV_PATTERNS = [
    r"(^|_)(" + _SECRET_WORDS + r")(_|$)",
    r"(^|_)(API|ACCESS|PRIVATE|SECRET|SIGNING|ENCRYPTION|SESSION|MASTER|ROOT|SSH|"
    r"DEPLOY|CLIENT|APP|SERVICE|CONSUMER)_KEYS?(_|$)",
    r"^PG(PASSWORD|PASSFILE)$",
    r"^MYSQL_PWD$",
]
CREDENTIAL_PATHS = [
    "~/.aws/credentials", "~/.aws/config", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
    "~/.ssh/id_ecdsa", "~/.ssh/config", "~/.netrc", "~/.npmrc", "~/.pypirc",
    "~/.docker/config.json", "~/.kube/config", "~/.config/gcloud/credentials.db",
    "~/.config/gcloud/application_default_credentials.json", "~/.azure/accessTokens.json",
    "~/.git-credentials", "~/.gitconfig", "~/.config/gh/hosts.yml",
    "/run/secrets", "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/etc/shadow", "/etc/master.passwd",  # the account hash file on Linux and on macOS
    # Coding agents' own login credentials. For a tool about agent sandboxes,
    # the credential the agent itself runs on is the one most likely present.
    # Each path is cited to the vendor's docs or source, read 2026-11-03:
    #   https://code.claude.com/docs/en/iam  "On Linux, credentials are stored in
    #     ~/.claude/.credentials.json with file mode 0600."
    #   https://learn.chatgpt.com/docs/auth (from developers.openai.com/codex/auth)
    #     "Codex caches login details locally in a plaintext file at ~/.codex/auth.json"
    #   github.com/google-gemini/gemini-cli packages/core/src/config/storage.ts
    #     OAUTH_FILE = 'oauth_creds.json' under the global .gemini directory
    #   Antigravity CLI (agy): https://antigravity.google/docs/install/ says it keeps
    #     tokens in the OS keyring; its changelog (v1.1.3, 2026-07-16) says it "bypasses
    #     the keyring when no D-Bus session bus is present", and v1.4.7 that such tokens
    #     go to "the CLI's private secrets file". agy 1.4.12 keeps that file at the path
    #     below (observed on the measuring host, 2026-11-04; no doc names it).
    "~/.claude/.credentials.json", "~/.codex/auth.json", "~/.gemini/oauth_creds.json",
    "~/.gemini/antigravity-cli/antigravity-oauth-token",
]
# Container runtime sockets. A socket that answers is root on the host (or the
# user's whole container estate, for a rootless engine).
SOCKET_PATHS = ["/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock"]
# Rootless engines put theirs in the user's runtime directory, and Docker
# Desktop in the home directory. Both locations are resolved from the
# environment AND from the uid / passwd entry, so clearing XDG_RUNTIME_DIR or
# moving HOME cannot hide a socket that is still there.
RUNTIME_SOCKETS = ["docker.sock", "podman/podman.sock"]
HOME_SOCKETS = ["~/.docker/desktop/docker.sock", "~/.docker/run/docker.sock"]

# Files that run, or configure what runs, OUTSIDE the sandbox: the next shell
# the user opens, the next ssh login, the next git command, the next session of
# the agent itself. Writing one is a way out of the sandbox that waits for the
# user. Opened for append and closed without writing; never created.
PERSISTENCE_FILES = [
    ("~/.bashrc", "shell-startup"), ("~/.bash_profile", "shell-startup"), ("~/.profile", "shell-startup"),
    ("~/.zshrc", "shell-startup"), ("~/.zprofile", "shell-startup"),
    ("~/.ssh/authorized_keys", "ssh-login"), ("~/.gitconfig", "git-config"),
    # The agent's own configuration, user and project level. An agent that can
    # rewrite these can turn its own sandbox off, or add a hook or MCP server
    # that runs unsandboxed, for its next session. Cited 2026-11-03:
    #   https://code.claude.com/docs/en/settings  (~/.claude/settings.json,
    #     .claude/settings.json, .claude/settings.local.json)
    #   https://code.claude.com/docs/en/mcp  (.mcp.json at the project root)
    #   https://learn.chatgpt.com/docs/config-file/config-basic  (~/.codex/config.toml;
    #     project .codex/config.toml, loaded only for trusted projects)
    #   gemini-cli packages/core/src/config/storage.ts  (~/.gemini/settings.json,
    #     <workspace>/.gemini/settings.json)
    #   https://antigravity.google/docs/settings?app=cli  (~/.gemini/antigravity-cli/settings.json)
    #   https://antigravity.google/docs/sandbox?tab=cli and the hooks/MCP docs it links:
    #     global ~/.gemini/config/hooks.json and mcp_config.json, workspace
    #     <workspace>/.agents/hooks.json and mcp_config.json
    ("~/.claude/settings.json", "agent-config"), ("~/.codex/config.toml", "agent-config"),
    ("~/.gemini/settings.json", "agent-config"),
    ("./.claude/settings.json", "agent-config"), ("./.claude/settings.local.json", "agent-config"),
    ("./.mcp.json", "agent-config"), ("./.codex/config.toml", "agent-config"),
    ("./.gemini/settings.json", "agent-config"),
    ("~/.gemini/antigravity-cli/settings.json", "agent-config"),
    ("~/.gemini/config/hooks.json", "agent-config"), ("~/.gemini/config/mcp_config.json", "agent-config"),
    ("./.agents/hooks.json", "agent-config"), ("./.agents/mcp_config.json", "agent-config"),
]
# Directories where a NEW file runs outside the sandbox. Tested the same way as
# WRITE_PROBE_DIRS: one zero-byte marker, created and removed at once.
PERSISTENCE_DIRS = [("~", "home"), ("./.git/hooks", "git-hooks"), ("~/.config/autostart", "desktop-autostart"),
                    # macOS: launchd starts every agent plist here at the user's next login.
                    ("~/Library/LaunchAgents", "desktop-autostart"),
                    # Where an agent's hook and MCP files are created if they do not exist
                    # yet (Antigravity, global and workspace; Codex also protects .agents).
                    ("~/.gemini/config", "agent-config"), ("./.agents", "agent-config")]
# Filesystems whose contents do not outlive the sandbox. A write there is not a
# way out: a container's own /root/.bashrc lives on its overlay and dies with it.
EPHEMERAL_FSTYPES = ("overlay", "tmpfs", "ramfs", "devtmpfs")
WRITE_PROBE_DIRS = ["/", "/etc", "/usr/bin", "/usr/local/bin", "/root", "/home", "/var", "/opt", "/tmp", "/dev/shm",
                    # Homebrew's prefix on Apple silicon is owned by the user and sits early on PATH:
                    # a binary planted there runs in place of the real one, outside any sandbox.
                    "/opt/homebrew/bin"]
# The working directory is probed separately: sandboxes that grant a single
# writable workspace (an agent's "workspace-write" mode) differ from fully
# read-only ones only here, and a fixed list would miss it.

# Linux capability bit names (from linux/capability.h). Index = bit number.
CAP_NAMES = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
    "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
    "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
]


def log(msg):
    sys.stderr.write("[blast_probe] %s\n" % msg)


def decode_caps(hexmask):
    try:
        mask = int(hexmask, 16)
    except (TypeError, ValueError):
        return []
    return [CAP_NAMES[i] if i < len(CAP_NAMES) else "CAP_%d" % i for i in range(64) if mask >> i & 1]


def read_text(path, limit=65536):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except Exception:
        return None


def probe_identity():
    info = {"uid": os.getuid(), "gid": os.getgid(), "euid": os.geteuid(), "pid": os.getpid(),
            "hostname": socket.gethostname(), "cwd": os.getcwd()}
    status = read_text("/proc/self/status") or ""
    caps = {}
    for line in status.splitlines():
        if line.startswith(("CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:")):
            k, v = line.split(":", 1)
            caps[k] = decode_caps(v.strip())
        elif line.startswith("Seccomp:"):
            info["seccomp_mode"] = int(line.split(":", 1)[1].strip() or 0)
        elif line.startswith("NoNewPrivs:"):
            info["no_new_privs"] = int(line.split(":", 1)[1].strip() or 0)
    info["capabilities"] = caps
    if IS_DARWIN:
        # No seccomp, capabilities or user namespaces on macOS. Seatbelt is the
        # syscall-level sandbox there, and this asks the kernel whether it applies.
        info["seatbelt"] = _darwin_seatbelt()
    info["ptrace_scope"] = (read_text("/proc/sys/kernel/yama/ptrace_scope") or "").strip()
    info["in_user_namespace"] = _in_user_namespace()
    info["cgroup"] = (read_text("/proc/self/cgroup") or "").strip()[:200]
    info["container_markers"] = {
        "dockerenv": os.path.exists("/.dockerenv"),
        "containerenv": os.path.exists("/run/.containerenv"),
    }
    return info


def _darwin_seatbelt():
    """1 if this process runs under a Seatbelt profile, 0 if not, None if macOS will not say.

    sandbox_check(pid, NULL, SANDBOX_FILTER_NONE) is the call macOS itself uses to
    ask whether a process is sandboxed; it lives in libsystem_sandbox, which
    libSystem re-exports. Called through ctypes, so the probe stays stdlib-only.
    """
    try:
        import ctypes
        f = ctypes.CDLL("/usr/lib/libSystem.B.dylib").sandbox_check
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        return 1 if f(os.getpid(), None, 0) else 0
    except Exception:
        return None


def _darwin_process_count():
    """(count, error): processes this one can see, from sysctl(KERN_PROC_ALL).

    macOS has no /proc. A sandbox profile can refuse the sysctl, which is
    itself the answer, so a refusal is reported and not treated as zero.
    """
    try:
        import ctypes
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        mib = (ctypes.c_int * 4)(1, 14, 0, 0)  # CTL_KERN, KERN_PROC, KERN_PROC_ALL
        size = ctypes.c_size_t(0)
        if libc.sysctl(mib, 3, None, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
            return None, errno.errorcode.get(ctypes.get_errno(), "sysctl")
        buf = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
            return None, errno.errorcode.get(ctypes.get_errno(), "sysctl")
        return size.value // 648, None  # sizeof(struct kinfo_proc) on 64-bit macOS
    except Exception as e:
        return None, type(e).__name__


def _root_read_only():
    """Is / mounted read-only? statvfs answers on Linux and macOS alike."""
    try:
        return bool(os.statvfs("/").f_flag & os.ST_RDONLY)
    except Exception:
        return None


def _in_user_namespace():
    uid_map = read_text("/proc/self/uid_map") or ""
    # Root namespace maps "0 0 4294967295".
    return uid_map.split() != ["0", "0", "4294967295"] if uid_map else None


def proxy_env_names(environ=None):
    """Names of the proxy variables that are set and non-empty, either case. Never values."""
    environ = os.environ if environ is None else environ
    return sorted(k for k in environ
                  if k.upper() in PROXY_ENV_NAMES and (environ.get(k) or "").strip())


def _proxy_url(environ):
    """(variable name, url) of the proxy an HTTPS client would use, or (None, None)."""
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"):
        v = (environ.get(name) or "").strip()
        if v:
            return name, v
    return None, None


def _no_proxy_matches(host, no_proxy):
    """Would a client send `host` direct, bypassing the proxy, under NO_PROXY?"""
    import ipaddress
    for entry in (e.strip().lower() for e in (no_proxy or "").split(",")):
        if not entry:
            continue
        if entry == "*":
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                return True
            continue
        except ValueError:
            pass
        e = entry.lstrip(".")
        if host == e or host.endswith("." + e):
            return True
    return False


def _connect_via_proxy(phost, pport, host, port, auth_header):
    """Ask the proxy to open a tunnel to host:port. Send the CONNECT request and
    nothing else, read the status line, close. No TLS, no bytes to the target."""
    r = {"status": None}
    try:
        s = socket.create_connection((phost, pport), timeout=CONNECT_TIMEOUT)
    except Exception as e:
        r["error"] = _err(e)
        return r
    try:
        s.settimeout(CONNECT_TIMEOUT)
        req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
        if auth_header:
            req += "Proxy-Authorization: " + auth_header + "\r\n"
        s.sendall((req + "\r\n").encode("ascii"))
        buf = b""
        while b"\r\n" not in buf and len(buf) < 1024:
            chunk = s.recv(256)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
            r["status"] = int(parts[1])
        else:
            r["error"] = "no HTTP status line"
    except Exception as e:
        r["error"] = _err(e)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return r


def probe_proxy(environ=None, targets=None):
    """What the configured egress proxy agrees to tunnel to.

    Records the variable name, the scheme, whether the proxy is on loopback,
    and a status code per fixed target. Never the proxy's URL, host or
    credentials.
    """
    import base64
    from urllib.parse import urlsplit, unquote
    environ = os.environ if environ is None else environ
    var, url = _proxy_url(environ)
    if not var:
        return {"configured": False}
    out = {"configured": True, "source": var, "measured": False}
    try:
        u = urlsplit(url if "://" in url else "http://" + url)
        scheme, phost, pport = (u.scheme or "http").lower(), u.hostname, u.port or 80
    except ValueError:
        out["reason"] = "proxy URL could not be parsed"
        return out
    out["scheme"] = scheme
    if scheme != "http" or not phost:
        out["reason"] = "only http:// proxies are measured; this one is %s://" % scheme
        return out
    out["proxy_loopback"] = phost in ("localhost", "::1") or phost.startswith("127.")
    has_creds = u.username is not None
    use_auth = has_creds and environ.get(PROXY_AUTH_OPT_IN) == "1"
    out["auth"] = "used" if use_auth else ("available, not used" if has_creds else "none")
    header = None
    if use_auth:
        cred = "%s:%s" % (unquote(u.username or ""), unquote(u.password or ""))
        header = "Basic " + base64.b64encode(cred.encode("utf-8")).decode("ascii")
    no_proxy = environ.get("NO_PROXY") or environ.get("no_proxy") or ""
    results = []
    for t in (targets if targets is not None else EGRESS_TARGETS + METADATA_TARGETS + [PROXY_CANARY]):
        r = {"name": t["name"], "host": t["host"], "port": t["port"]}
        if _no_proxy_matches(t["host"], no_proxy):
            r["bypassed"] = "NO_PROXY"  # a client goes direct; the direct test covers it
        else:
            r.update(_connect_via_proxy(phost, pport, t["host"], t["port"], header))
        results.append(r)
    out["targets"] = results
    out["measured"] = True
    return out


def probe_network():
    results = []
    blocked = 0
    for t in EGRESS_TARGETS + METADATA_TARGETS:
        r = {"name": t["name"], "host": t["host"], "port": t["port"], "resolved": None, "connect": False, "ms": None}
        start = time.time()
        try:
            addr = socket.getaddrinfo(t["host"], t["port"], socket.AF_INET, socket.SOCK_STREAM)[0][4]
            r["resolved"] = addr[0]
        except Exception as e:
            r["resolve_error"] = type(e).__name__
            if type(e).__name__ in ("PermissionError", "OSError") and "Operation not permitted" in str(e):
                blocked += 1
            results.append(r)
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as e:
            # A seccomp filter or LSM can refuse socket() itself. That is a
            # containment result, not a probe failure.
            r["socket_error"] = type(e).__name__
            blocked += 1
            results.append(r)
            continue
        s.settimeout(CONNECT_TIMEOUT)
        try:
            s.connect(addr)
            r["connect"] = True
        except Exception as e:
            r["connect_error"] = type(e).__name__
        finally:
            try:
                s.close()
            except Exception:
                pass
        r["ms"] = int((time.time() - start) * 1000)
        results.append(r)
    ifaces = []
    try:
        for name in os.listdir("/sys/class/net"):
            ifaces.append(name)
    except Exception:
        try:
            ifaces = [n for _i, n in socket.if_nameindex()]  # macOS has no /sys
        except Exception:
            pass
    return {"targets": results, "interfaces": sorted(ifaces), "proxy_env": proxy_env_names(),
            "proxy": probe_proxy(),
            "socket_syscall_blocked": blocked == len(results) and blocked > 0,
            "connect_refused_all": bool(results) and not any(r.get("connect") for r in results),
            "any_egress": any(x["connect"] for x in results if not x["name"].startswith(("cloud-metadata", "gcp-metadata"))),
            "metadata_reachable": any(x["connect"] for x in results if x["name"].startswith(("cloud-metadata", "gcp-metadata")))}


def _control_unix_socket():
    """Can this process connect to a unix socket it created itself?

    Without this control, a refused connection to the container socket is
    ambiguous: it could be a path-scoped rule, or a filter that refuses every
    unix-domain socket operation. The control separates the two, and records
    which call was refused so the report can say so precisely.
    """
    import tempfile as _tf
    last = {"supported": False, "connected": False, "stage": "setup", "error": "no writable directory"}
    for base in (os.environ.get("TMPDIR"), "/tmp", "/dev/shm", os.getcwd()):
        if not base or not os.path.isdir(base):
            continue
        d = None
        stage = "mkdtemp"
        srv = cli = None
        try:
            d = _tf.mkdtemp(prefix=".agentsec_ctl_", dir=base)
            path = os.path.join(d, "s")
            stage = "socket"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stage = "bind"
            srv.bind(path)
            stage = "listen"
            srv.listen(1)
            stage = "connect"
            cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cli.settimeout(CONNECT_TIMEOUT)
            try:
                cli.connect(path)
                return {"supported": True, "connected": True, "stage": "connect", "where": base}
            except Exception as e:
                return {"supported": True, "connected": False, "stage": "connect",
                        "error": type(e).__name__, "where": base}
        except Exception as e:
            last = {"supported": False, "connected": False, "stage": stage,
                    "error": type(e).__name__, "where": base}
        finally:
            for s in (cli, srv):
                try:
                    if s is not None:
                        s.close()
                except Exception:
                    pass
            if d:
                try:
                    for f in os.listdir(d):
                        os.unlink(os.path.join(d, f))
                    os.rmdir(d)
                except Exception:
                    pass
    return last


def _control_unix_connect_nonexistent():
    """Fallback control that needs no writable directory.

    Connecting to a path that does not exist should fail with FileNotFoundError
    if unix-domain connect is permitted at all. A PermissionError instead means
    the call was refused before the path was ever consulted, which is evidence
    the filter is not path-scoped.
    """
    path = "/nonexistent-agentsec-control-%d.sock" % os.getpid()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except Exception as e:
        return {"stage": "socket", "error": type(e).__name__, "verdict": "socket() refused"}
    try:
        s.settimeout(CONNECT_TIMEOUT)
        s.connect(path)
        return {"stage": "connect", "error": None, "verdict": "unexpected success"}
    except FileNotFoundError:
        return {"stage": "connect", "error": "FileNotFoundError", "verdict": "connect permitted"}
    except PermissionError:
        return {"stage": "connect", "error": "PermissionError", "verdict": "connect refused before path lookup"}
    except Exception as e:
        return {"stage": "connect", "error": type(e).__name__, "verdict": "inconclusive"}
    finally:
        try:
            s.close()
        except Exception:
            pass


def _home_dirs():
    """Every directory that is plausibly this account's home, and how we know.

    $HOME is an environment variable, so anything inside the sandbox can change
    it. Pointing it at an empty directory used to clear the credential finding
    and drop the score fifteen points while every one of those files stayed
    readable at its real path. A score that can be lowered by concealment is
    worse than no score, so the passwd entry is consulted too; that one comes
    from the kernel's view of the uid and the environment cannot forge it.
    """
    homes = []
    env_home = os.environ.get("HOME")
    if env_home:
        homes.append((env_home, "HOME"))
    try:
        import pwd
        pw_home = pwd.getpwuid(os.getuid()).pw_dir
        if pw_home:
            homes.append((pw_home, "passwd"))
    except (ImportError, KeyError, OSError):
        # A uid with no passwd entry is normal in a container. Not an error.
        pass
    out, seen = [], set()
    for h, src in homes:
        key = os.path.normpath(h)
        if key not in seen:
            seen.add(key)
            out.append((h, src))
    return out


def _candidate_paths(p):
    """Every place a credential path might actually live, with its provenance."""
    if not p.startswith("~"):
        return [(p, "absolute")]
    return [(os.path.join(h, p[2:]) if p.startswith("~/") else h, src)
            for h, src in _home_dirs()]


def _err(e):
    """'EROFS' rather than 'OSError': read-only and permission-denied are different answers."""
    return errno.errorcode.get(getattr(e, "errno", None) or -1, type(e).__name__)


def _masked(path):
    """True when the path is a device node standing in for a file.

    Some sandboxes hide a file by bind-mounting /dev/null over it. Opening it
    then succeeds, for reading and for writing, and touches nothing; counting
    that as a readable credential or a writable rc file would report a breach
    that is not there.
    """
    try:
        m = os.stat(path).st_mode
    except OSError:
        return False
    return stat.S_ISCHR(m) or stat.S_ISBLK(m)


def _can_read(path):
    """Prove readability by opening, not by permission bits. Reads zero bytes.

    os.access() answers from the mode bits and the real uid; a seccomp filter,
    Landlock or an LSM can still refuse the open() itself. O_NONBLOCK keeps a
    FIFO planted at a credential path from hanging the probe.
    """
    try:
        if os.path.isdir(path):
            os.listdir(path)
        else:
            os.close(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)))
        return True, None
    except Exception as e:
        return False, _err(e)


def _can_append(path):
    """Open an EXISTING file for append and close it without writing a byte.

    No O_CREAT, so a missing file stays missing. Nothing is written, so content
    and mtime are unchanged, but the close is still a close-after-write event to
    inotify, which a settings watcher may notice.
    """
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NONBLOCK", 0)))
        return True, None
    except Exception as e:
        return False, _err(e)


def _can_create_in(d):
    try:
        fd, path = tempfile.mkstemp(prefix=".agentsec_probe_", dir=d)
        os.close(fd)
        os.unlink(path)
        return True, None
    except Exception as e:
        return False, _err(e)


def _unescape_mountinfo(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def parse_mountinfo(text):
    """[(mount_point, fstype)] from /proc/self/mountinfo text."""
    out = []
    for line in (text or "").splitlines():
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        lf, rf = left.split(), right.split()
        if len(lf) >= 5 and rf:
            out.append((_unescape_mountinfo(lf[4]), rf[0]))
    return out


def fstype_of(path, mounts):
    """Filesystem type of the mount that holds `path` (longest matching mount point, last wins)."""
    best, fstype = -1, None
    for mp, fs in mounts:
        if path == mp or path.startswith(mp.rstrip("/") + "/") or mp == "/":
            if len(mp) >= best:
                best, fstype = len(mp), fs
    return fstype


def _local_candidates(p):
    """'./x' resolves against the working directory; '~' forms against every home."""
    if p.startswith("./"):
        return [(os.path.join(os.getcwd(), p[2:]), "cwd")]
    return _candidate_paths(p)


def probe_persistence():
    """What the sandbox lets the agent leave behind for the world outside it."""
    mounts = parse_mountinfo(read_text("/proc/self/mountinfo", 400000))
    out, seen = [], set()
    for items, is_dir in ((PERSISTENCE_FILES, False), (PERSISTENCE_DIRS, True)):
        for p, kind in items:
            for path, via in _local_candidates(p):
                if not os.path.exists(path) or (os.path.isdir(path) != is_dir):
                    continue
                real = os.path.realpath(path)
                if real in seen:
                    continue
                seen.add(real)
                entry = {"path": p, "kind": kind, "via": via, "is_dir": is_dir}
                if _masked(path):
                    entry.update(masked=True, writable=False)
                else:
                    ok, err = (_can_create_in if is_dir else _can_append)(path)
                    entry["writable"] = ok
                    if err:
                        entry["error"] = err
                fs = fstype_of(real, mounts)
                entry["fstype"] = fs
                entry["host_backed"] = None if fs is None else fs not in EPHEMERAL_FSTYPES
                out.append(entry)
    return out


def _runtime_dirs():
    """The user's runtime directory, from the environment and from the uid."""
    dirs = []
    env = os.environ.get("XDG_RUNTIME_DIR")
    if env:
        dirs.append((env, "XDG_RUNTIME_DIR"))
    dirs.append(("/run/user/%d" % os.getuid(), "uid"))
    out, seen = [], set()
    for d, src in dirs:
        k = os.path.normpath(d)
        if k not in seen and os.path.isdir(d):
            seen.add(k)
            out.append((d, src))
    return out


def _socket_candidates():
    """(reported_path, real_path, kind, via). Reported paths carry no username."""
    c = [(p, p, "container", "absolute") for p in SOCKET_PATHS]
    for d, src in _runtime_dirs():
        for name in RUNTIME_SOCKETS:
            c.append(("$XDG_RUNTIME_DIR/" + name, os.path.join(d, name), "container", src))
    for p in HOME_SOCKETS:
        for path, via in _candidate_paths(p):
            c.append((p, path, "container", via))
    ssh = os.environ.get("SSH_AUTH_SOCK")
    if ssh:
        c.append(("$SSH_AUTH_SOCK", ssh, "ssh-agent", "SSH_AUTH_SOCK"))
    return c


def _connect_unix(path):
    """Connect, send nothing, close. Proves reachability instead of inferring it."""
    entry = {"connected": False}
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except Exception as e:
        entry["socket_error"] = type(e).__name__
        return entry
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect(path)
        entry["connected"] = True
    except Exception as e:
        entry["connect_error"] = type(e).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass
    return entry


def probe_secrets():
    env_hits = []
    for k in os.environ:
        for pat in SECRET_ENV_PATTERNS:
            if re.search(pat, k, re.IGNORECASE):
                env_hits.append({"name": k, "length": len(os.environ.get(k, ""))})  # name and length only, never the value
                break
    files = []
    seen_real = {}
    for p in CREDENTIAL_PATHS:
        for path, via in _candidate_paths(p):
            if not os.path.exists(path):
                continue
            try:
                real = os.path.realpath(path)
            except OSError:
                real = path
            if real in seen_real:
                # Same file found under two homes: record both routes, not two rows.
                prev = seen_real[real]
                if via not in prev["via"]:
                    prev["via"] = prev["via"] + "+" + via
                continue
            # Report the unexpanded form: portable across hosts and free of the
            # operator's username. `via` says which home resolved it, so a
            # redirected HOME is visible instead of silently hiding the file.
            entry = {"path": p, "resolved_under_home": p.startswith("~"), "via": via,
                     "access_bits": os.access(path, os.R_OK), "is_dir": os.path.isdir(path)}
            if _masked(path):
                entry.update(masked=True, readable=False)
            else:
                ok, err = _can_read(path)
                entry["readable"] = ok
                if err:
                    entry["read_error"] = err
            try:
                st = os.stat(path)
                entry["mode"] = oct(stat.S_IMODE(st.st_mode))
                entry["size"] = st.st_size
            except Exception:
                pass
            seen_real[real] = entry
            files.append(entry)
    sockets, seen_sock = [], set()
    for shown, sp, kind, via in _socket_candidates():
        if not os.path.exists(sp):
            continue
        real = os.path.realpath(sp)
        if real in seen_sock:
            continue
        seen_sock.add(real)
        try:
            is_sock = stat.S_ISSOCK(os.stat(sp).st_mode)
        except OSError:
            is_sock = None
        entry = {"path": shown, "kind": kind, "via": via, "is_socket": is_sock,
                 "writable": os.access(sp, os.W_OK), "connected": False}
        if is_sock is False:
            entry["masked"] = _masked(sp)
        else:
            entry.update(_connect_unix(sp))
        sockets.append(entry)
    pid1_environ_readable = read_text("/proc/1/environ", 1) is not None
    homes = _home_dirs()
    return {"env_secret_names": env_hits, "credential_files": files, "container_sockets": sockets,
            "home_dirs": [{"source": s, "differs_from_env": (s != "HOME" and len(homes) > 1)} for _h, s in homes],
            "home_env_matches_passwd": len(homes) < 2,
            "unix_control": _control_unix_socket(),
            "unix_control_nopath": _control_unix_connect_nonexistent(),
            "pid1_environ_readable": pid1_environ_readable, "env_var_count": len(os.environ)}


def probe_filesystem():
    writable = []
    cwd_writable = None
    try:
        fd, path = tempfile.mkstemp(prefix=".agentsec_probe_", dir=os.getcwd())
        os.close(fd)
        os.unlink(path)
        cwd_writable = True
    except Exception:
        cwd_writable = False
    for d in WRITE_PROBE_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            fd, path = tempfile.mkstemp(prefix=".agentsec_probe_", dir=d)
            os.close(fd)
            os.unlink(path)
            writable.append(d)
        except Exception:
            pass
    mounts = []
    for line in (read_text("/proc/mounts", 200000) or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        src, dst, fstype, opts = parts[0], parts[1], parts[2], parts[3]
        if fstype in ("proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "tmpfs", "devtmpfs", "securityfs", "pstore", "bpf", "debugfs", "tracefs", "configfs", "fusectl", "hugetlbfs", "binfmt_misc", "autofs", "nsfs", "overlay", "squashfs"):
            continue
        mounts.append({"source": src, "target": dst, "fstype": fstype, "rw": "rw" in opts.split(",")})
    if os.path.exists("/proc/mounts"):
        root_rw = "rw" in next((l.split()[3] for l in (read_text("/proc/mounts", 200000) or "").splitlines() if len(l.split()) > 3 and l.split()[1] == "/"), "").split(",")
    else:
        ro = _root_read_only()
        root_rw = None if ro is None else not ro
    setuid = []
    for d in ("/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin"):
        try:
            for name in os.listdir(d):
                p = os.path.join(d, name)
                try:
                    st = os.stat(p)
                except Exception:
                    continue
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    setuid.append(p)
        except Exception:
            pass
    return {"writable_dirs": writable, "cwd_writable": cwd_writable, "root_rw": root_rw, "bind_mounts": mounts[:50], "setuid_binaries": sorted(set(setuid))[:50],
            "persistence": probe_persistence(),
            "proc_sysrq_writable": os.access("/proc/sysrq-trigger", os.W_OK),
            "host_root_visible": os.path.exists("/host") or os.path.exists("/hostfs")}


def probe_process():
    if IS_DARWIN:
        count, err = _darwin_process_count()
        out = {"visible_pid_count": count or 0, "visible_uids": [], "pid1_is_self": os.getpid() == 1,
               "pid1_cmdline": "", "method": "sysctl(KERN_PROC_ALL)"}
        if err:
            out["error_detail"] = err
        return out
    procs = []
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                procs.append(int(pid))
    except Exception:
        pass
    other_users = set()
    for pid in procs[:500]:
        st = read_text("/proc/%d/status" % pid, 2000) or ""
        for line in st.splitlines():
            if line.startswith("Uid:"):
                try:
                    other_users.add(int(line.split()[1]))
                except Exception:
                    pass
                break
    return {"visible_pid_count": len(procs), "visible_uids": sorted(other_users)[:20], "pid1_is_self": os.getpid() == 1,
            "pid1_cmdline": (read_text("/proc/1/cmdline", 200) or "").replace("\0", " ").strip()[:120]}


def probe_resources():
    limits = {}
    for path, key in (("/sys/fs/cgroup/memory.max", "memory_max"), ("/sys/fs/cgroup/cpu.max", "cpu_max"), ("/sys/fs/cgroup/pids.max", "pids_max"),
                      ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "memory_limit_v1")):
        v = read_text(path, 100)
        if v is not None:
            limits[key] = v.strip()
    return limits


def main():
    started = time.time()
    out = {"probe_version": PROBE_VERSION, "timestamp": int(started), "python": sys.version.split()[0], "platform": sys.platform}
    for name, fn in (("identity", probe_identity), ("network", probe_network), ("secrets", probe_secrets),
                     ("filesystem", probe_filesystem), ("process", probe_process), ("resources", probe_resources)):
        try:
            out[name] = fn()
        except Exception as e:
            out[name] = {"error": "%s: %s" % (type(e).__name__, e)}
            log("%s failed: %s" % (name, e))
    out["duration_ms"] = int((time.time() - started) * 1000)
    sys.stdout.write(json.dumps(out, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
