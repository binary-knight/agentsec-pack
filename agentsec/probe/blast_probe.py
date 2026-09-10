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
    close immediately;
  * unix sockets are connected to and closed with nothing sent, to prove
    reachability rather than infer it from permission bits;
  * the only writes are zero-byte marker files, one per probed directory
    (see WRITE_PROBE_DIRS), each created and removed immediately. That is the
    writability test; it can trip file-integrity monitoring where present.

Output: one JSON document on stdout. Everything else goes to stderr.
"""
import json
import os
import re
import socket
import stat
import sys
import tempfile
import time

PROBE_VERSION = "0.1.0"

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
    "/etc/shadow",
]
SOCKET_PATHS = ["/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock"]
WRITE_PROBE_DIRS = ["/", "/etc", "/usr/bin", "/usr/local/bin", "/root", "/home", "/var", "/opt", "/tmp", "/dev/shm"]
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
    info["ptrace_scope"] = (read_text("/proc/sys/kernel/yama/ptrace_scope") or "").strip()
    info["in_user_namespace"] = _in_user_namespace()
    info["cgroup"] = (read_text("/proc/self/cgroup") or "").strip()[:200]
    info["container_markers"] = {
        "dockerenv": os.path.exists("/.dockerenv"),
        "containerenv": os.path.exists("/run/.containerenv"),
    }
    return info


def _in_user_namespace():
    uid_map = read_text("/proc/self/uid_map") or ""
    # Root namespace maps "0 0 4294967295".
    return uid_map.split() != ["0", "0", "4294967295"] if uid_map else None


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
        pass
    return {"targets": results, "interfaces": sorted(ifaces),
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
                     "readable": os.access(path, os.R_OK), "is_dir": os.path.isdir(path)}
            try:
                st = os.stat(path)
                entry["mode"] = oct(stat.S_IMODE(st.st_mode))
                entry["size"] = st.st_size
            except Exception:
                pass
            seen_real[real] = entry
            files.append(entry)
    sockets = []
    for sp in SOCKET_PATHS:
        if not os.path.exists(sp):
            continue
        entry = {"path": sp, "writable": os.access(sp, os.W_OK), "connected": False}
        # Prove reachability rather than inferring it from permissions: connect, send nothing, close.
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except Exception as e:
            entry["socket_error"] = type(e).__name__
            sockets.append(entry)
            continue
        s.settimeout(CONNECT_TIMEOUT)
        try:
            s.connect(sp)
            entry["connected"] = True
        except Exception as e:
            entry["connect_error"] = type(e).__name__
        finally:
            try:
                s.close()
            except Exception:
                pass
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
    root_rw = "rw" in next((l.split()[3] for l in (read_text("/proc/mounts", 200000) or "").splitlines() if len(l.split()) > 3 and l.split()[1] == "/"), "").split(",")
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
            "proc_sysrq_writable": os.access("/proc/sysrq-trigger", os.W_OK),
            "host_root_visible": os.path.exists("/host") or os.path.exists("/hostfs")}


def probe_process():
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
