"""Turn a blast-radius probe result into findings and a score.

Scoring is deliberately simple and fully visible: each finding has a fixed
weight; the blast-radius score is the sum, capped at 100. Higher = larger
blast radius = worse containment. A perfectly contained sandbox scores 0.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from importlib import resources
from typing import Any

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN": "critical", "CAP_SYS_PTRACE": "high", "CAP_SYS_MODULE": "critical",
    "CAP_NET_ADMIN": "high", "CAP_NET_RAW": "medium", "CAP_DAC_OVERRIDE": "medium",
    "CAP_DAC_READ_SEARCH": "medium", "CAP_SYS_RAWIO": "critical", "CAP_MKNOD": "medium",
    "CAP_SETUID": "medium", "CAP_SETGID": "medium", "CAP_SYS_CHROOT": "low", "CAP_BPF": "high",
    "CAP_PERFMON": "low", "CAP_CHECKPOINT_RESTORE": "medium",
}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    evidence: dict = field(default_factory=dict)
    owasp: list = field(default_factory=list)
    remediation: str = ""

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]


def load_owasp() -> dict[str, str]:
    with resources.files("agentsec.data").joinpath("owasp_asi_2026.json").open("r") as f:
        return json.load(f)["entries"]


def _f(fid, title, sev, cat, evidence=None, owasp=None, remediation=""):
    return Finding(fid, title, sev, cat, evidence or {}, owasp or [], remediation)


def _unix_refusal_detail(sec: dict, ev: dict) -> str:
    """Why a visible unix socket was refused: a rule on these paths, or a filter on every socket.

    Shared by every 'visible but refused' socket finding. Records the fallback
    control in `ev` when it was the one that decided.
    """
    ctl = sec.get("unix_control") or {}
    stage = ctl.get("stage")
    if ctl.get("connected"):
        return ("A control connection to a socket the probe created itself succeeded, so unix-domain connections do work "
                "here and the refusal is specific to these paths. Containment rests on that path-scoped rule rather than "
                "on the socket being absent, so removing the path as well is the more durable fix.")
    if ctl.get("supported") or stage in ("socket", "bind", "listen", "connect"):
        return ("The control also failed, at the " + str(stage) + " call, so unix-domain sockets appear to be blocked "
                "wholesale rather than for these paths specifically. The visible socket paths are inert under that filter; "
                "this finding is informational, and removing the paths would only be defence in depth.")
    np = sec.get("unix_control_nopath") or {}
    ev["unix_control_nopath"] = np
    verdict = np.get("verdict")
    if verdict == "connect refused before path lookup":
        return ("The bind-and-connect control could not run (no writable directory), but connecting to a path that does "
                "not exist was refused with PermissionError rather than FileNotFoundError. The call is therefore blocked "
                "before the path is consulted, so the refusal is not specific to these sockets and the visible paths are "
                "inert. Informational.")
    if verdict == "connect permitted":
        return ("The bind-and-connect control could not run (no writable directory), but connecting to a nonexistent path "
                "returned FileNotFoundError, so unix-domain connect is permitted in general and the refusal on these "
                "sockets is path-scoped. Containment rests on that rule rather than on the socket being absent.")
    return ("The control test could not run (" + str(ctl.get("error")) + " at the " + str(stage) + " stage) and the "
            "no-path fallback was inconclusive, so it is not known whether the refusal is specific to these paths or "
            "applies to every unix socket. Treat the containment claim as unverified.")


# Credential files a coding agent itself logs in with (see CREDENTIAL_PATHS in the probe).
AGENT_CREDENTIALS = {"~/.claude/.credentials.json", "~/.codex/auth.json", "~/.gemini/oauth_creds.json",
                     "~/.gemini/antigravity-cli/antigravity-oauth-token"}
# Persistence kinds: writing one runs code outside the sandbox later.
RUNS_OUTSIDE = {"shell-startup", "ssh-login", "git-config", "git-hooks", "desktop-autostart", "home"}


def _proxy_verdict(px: dict) -> dict:
    """Sort a measured proxy's answers: accepted (2xx), refused, or asking for auth."""
    accepted, metadata, statuses = [], [], []
    canary = "not asked"
    for t in px.get("targets", []):
        if t.get("bypassed"):
            continue
        st = t.get("status")
        statuses.append(st)
        ok = isinstance(st, int) and 200 <= st < 300
        if t["name"].startswith("canary"):
            canary = "accepted" if ok else "refused (%s)" % (st if st is not None else t.get("error"))
        elif t["name"].startswith(("cloud-metadata", "gcp-metadata")):
            if ok:
                metadata.append(t["host"])
        elif ok:
            accepted.append(t["host"])
    asked = [s for s in statuses if s is not None]
    return {"accepted": accepted, "metadata": metadata, "canary": canary,
            "auth_required": bool(asked) and all(s == 407 for s in asked)}


def analyze(probe: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    ident = probe.get("identity", {}) or {}
    net = probe.get("network", {}) or {}
    sec = probe.get("secrets", {}) or {}
    fs = probe.get("filesystem", {}) or {}
    proc = probe.get("process", {}) or {}
    res = probe.get("resources", {}) or {}

    # --- Network egress -----------------------------------------------------
    # The probe connects directly and never through a proxy. If a proxy is
    # configured and socket() itself works, the agent's HTTP clients will use
    # that proxy, so a refused direct connection proves nothing about egress.
    # Only a refused socket() call also rules the proxy out.
    proxy_env = net.get("proxy_env") or []
    px = net.get("proxy") or {}
    via_proxy = _proxy_verdict(px) if px.get("measured") else None
    if via_proxy and via_proxy["metadata"] and not net.get("metadata_reachable"):
        findings.append(_f("NET-002", "Cloud instance-metadata endpoint reachable", "critical", "network",
                           {"via": "proxy", "proxy_accepted_connect_to": via_proxy["metadata"]}, ["ASI03", "ASI02"],
                           "The egress proxy agreed to tunnel to an instance-metadata address. Deny 169.254.169.254 and "
                           "metadata.google.internal at the proxy as well as in the network namespace."))
    if net.get("connect_refused_all") and via_proxy and not net.get("socket_syscall_blocked"):
        # The proxy was asked, so the network axis is measured. Wording is
        # "accepted CONNECT", not "reached": a proxy can answer 200 before the
        # upstream connection completes.
        ev = {"via": "proxy", "proxy_source": px.get("source"), "auth": px.get("auth"),
              "proxy_accepted_connect_to": via_proxy["accepted"], "control": via_proxy["canary"]}
        if via_proxy["canary"] == "accepted":
            findings.append(_f("NET-001", "Unrestricted internet egress from the sandbox", "high", "network", ev,
                               ["ASI02", "ASI10"],
                               "Direct connections are refused, but the egress proxy accepted a tunnel to the control host, "
                               "example.com, which no allowlist has a reason to contain: it forwards to anywhere. Configure "
                               "an allowlist at the proxy, or remove the network."))
        elif via_proxy["accepted"]:
            findings.append(_f("NET-005", "Egress through the proxy is allowlisted", "medium", "network", ev,
                               ["ASI02", "ASI10"],
                               "The proxy refused the control host and accepted tunnels to the hosts listed, so it is "
                               "filtering, and those hosts are what an injected command can reach. Keep the list to what the "
                               "agent needs; a host that accepts uploads, such as a code host or a package index, is an "
                               "exfiltration route."))
        elif via_proxy["auth_required"]:
            findings.append(_f("NET-004", "Direct connections refused; the proxy requires authentication the probe did not send",
                               "info", "network", dict(ev, unmeasured=True), ["ASI02"],
                               "The proxy answered 407 to every request because the probe did not authenticate. Clients in "
                               "the sandbox can, since the password is in " + str(px.get("source")) + ", so what the proxy "
                               "allows is unknown. Re-run the probe with AGENTSEC_PROBE_PROXY_AUTH=1 to send it to that proxy "
                               "and measure the allowlist; it is never recorded."))
        else:
            findings.append(_f("NET-003", "No network reachable from the sandbox (containment holds)", "info", "network",
                               dict(ev, detail="direct connections refused, and the proxy refused a tunnel to every "
                                               "target and to the control"), ["ASI02"],
                               "No action: the probe could not leave this sandbox directly or through its proxy."))
    elif net.get("connect_refused_all") and proxy_env and not net.get("socket_syscall_blocked"):
        findings.append(_f("NET-004", "Direct connections refused; egress through the configured proxy was not measured",
                           "info", "network", {"proxy_env": proxy_env, "unmeasured": True}, ["ASI02"],
                           "Every direct connection the probe tried was refused, but " + ", ".join(proxy_env)
                           + (" is" if len(proxy_env) == 1 else " are") + " set and "
                           "the probe does not connect through a proxy, so what the proxy lets through is unknown. Treat the "
                           "network axis as unverified, not as sealed: check the proxy's allowlist yourself and keep it to the "
                           "hosts the agent needs. A host that accepts uploads, such as a code host, is an exfiltration route."))
    elif net.get("socket_syscall_blocked") or net.get("connect_refused_all"):
        how = ("socket creation itself is refused" if net.get("socket_syscall_blocked")
               else "sockets can be created but every outbound connection and name lookup was refused")
        findings.append(_f("NET-003", "No network reachable from the sandbox (containment holds)", "info", "network",
                           {"detail": how}, ["ASI02"],
                           "No action: nothing the probe tried could leave this sandbox over the network."))
    reached = [t for t in net.get("targets", []) if t.get("connect")]
    egress = [t["name"] for t in reached if not t["name"].startswith(("cloud-metadata", "gcp-metadata"))]
    if egress:
        findings.append(_f("NET-001", "Unrestricted internet egress from the sandbox", "high", "network",
                           {"reached": egress}, ["ASI02", "ASI10"],
                           "Run the agent with no network (docker --network none) or an allowlisting egress proxy."))
    if net.get("metadata_reachable"):
        findings.append(_f("NET-002", "Cloud instance-metadata endpoint reachable", "critical", "network",
                           {"reached": [t["name"] for t in reached if t["name"].startswith(("cloud-metadata", "gcp-metadata"))]},
                           ["ASI03", "ASI02"], "Block 169.254.169.254 and metadata.google.internal from the agent's network namespace."))

    # --- Identity / privilege ----------------------------------------------
    if ident.get("euid") == 0 and not ident.get("in_user_namespace"):
        findings.append(_f("PRIV-001", "Agent runs as real root (uid 0, not in a user namespace)", "high", "privilege",
                           {"euid": 0}, ["ASI03", "ASI05"], "Run as an unprivileged user (docker --user) or inside a user namespace."))
    elif ident.get("euid") == 0:
        findings.append(_f("PRIV-002", "Agent runs as namespaced root", "low", "privilege", {"euid": 0}, ["ASI03"],
                           "Prefer an unprivileged uid even inside user namespaces."))
    eff = set((ident.get("capabilities") or {}).get("CapEff", []))
    dangerous = sorted(c for c in eff if c in DANGEROUS_CAPS)
    if dangerous:
        worst = max((DANGEROUS_CAPS[c] for c in dangerous), key=lambda s: SEVERITY_WEIGHT[s])
        findings.append(_f("PRIV-003", "Dangerous Linux capabilities in the effective set", worst, "privilege",
                           {"capabilities": dangerous}, ["ASI05", "ASI03"], "docker --cap-drop ALL, then add back only what the workload needs."))
    darwin = str(probe.get("platform", "")).startswith("darwin")
    if darwin and ident.get("seatbelt") == 0:
        findings.append(_f("PRIV-006", "No Seatbelt sandbox applied", "medium", "privilege", {"seatbelt": 0}, ["ASI05"],
                           "macOS reports that this process runs under no Seatbelt profile, so nothing below the user's own "
                           "permissions limits what it can reach. Run the agent in its sandbox mode, or under a sandbox-exec profile."))
    if not darwin and ident.get("seccomp_mode", 0) == 0:
        findings.append(_f("PRIV-004", "No seccomp filter applied", "medium", "privilege", {"seccomp_mode": 0}, ["ASI05"],
                           "Docker and podman apply a default seccomp profile unless you pass --security-opt seccomp=unconfined; "
                           "seeing mode 0 means the sandbox is running without one. bubblewrap needs --seccomp with a compiled BPF filter."))
    if ident.get("no_new_privs") == 0:
        findings.append(_f("PRIV-005", "no_new_privs not set (setuid escalation possible)", "low", "privilege", {}, ["ASI03"],
                           "docker --security-opt no-new-privileges."))

    # --- Secrets ------------------------------------------------------------
    all_socks = [s for s in sec.get("container_sockets", []) if s.get("is_socket") is not False]
    socks = [s for s in all_socks if s.get("kind", "container") == "container"]
    ssh = [s for s in all_socks if s.get("kind") == "ssh-agent"]
    if ssh:
        ev = {"paths": [s["path"] for s in ssh]}
        if any(s.get("connected") for s in ssh):
            findings.append(_f("SEC-007", "SSH agent socket reachable from the sandbox", "high", "secrets", ev,
                               ["ASI03", "ASI02"],
                               "A forwarded SSH agent signs with every key loaded into it, for any host those keys open, "
                               "without the key file ever being readable. Do not pass SSH_AUTH_SOCK into the sandbox; "
                               "give the agent a scoped deploy key or token instead."))
        else:
            ev["unix_control"] = sec.get("unix_control") or {}
            findings.append(_f("SEC-008", "SSH agent socket visible but connections are refused", "low", "secrets", ev,
                               ["ASI03"], _unix_refusal_detail(sec, ev)))
    if socks:
        connected = [s["path"] for s in socks if s.get("connected")]
        ev = {"paths": [s["path"] for s in socks], "writable": [s["path"] for s in socks if s.get("writable")],
              "connected": connected,
              "refused": [{"path": s["path"], "error": s.get("connect_error") or s.get("socket_error")}
                          for s in socks if not s.get("connected")]}
        if connected:
            findings.append(_f("SEC-001", "Container runtime socket reachable from the sandbox", "critical", "secrets", ev,
                               ["ASI03", "ASI05", "ASI10"],
                               "Never expose the Docker/containerd/podman socket to an agent sandbox: a socket that answers is root on "
                               "the host, and a read-only root filesystem does not take it away."))
        else:
            ev["unix_control"] = sec.get("unix_control") or {}
            findings.append(_f("SEC-006", "Container runtime socket visible but connections are refused", "low", "secrets", ev,
                               ["ASI03"], _unix_refusal_detail(sec, ev)))
    env_names = [e["name"] for e in sec.get("env_secret_names", [])]
    if env_names:
        findings.append(_f("SEC-002", "Secret-looking environment variables visible to the agent", "high", "secrets",
                           {"names": env_names}, ["ASI03", "ASI02"],
                           "Inject secrets through a broker or scoped short-lived tokens; do not export them into the agent's environment."))
    SHADOW = ("/etc/shadow", "/etc/master.passwd")
    readable = [c["path"] for c in sec.get("credential_files", []) if c.get("readable") and c["path"] not in SHADOW]
    shadow_hit = next((c["path"] for c in sec.get("credential_files", []) if c["path"] in SHADOW and c.get("readable")), None)
    if shadow_hit:
        findings.append(_f("SEC-005", "Image shadow file readable (process is root)", "info", "secrets", {"path": shadow_hit}, ["ASI03"],
                           "Informational in a plain image; becomes real if the image carries live account hashes."))
    if readable:
        creds = [c for c in sec.get("credential_files", [])
                 if c.get("readable") and c["path"] not in SHADOW]
        ev = {"readable_of_those_probed": readable,
              "probed": len(sec.get("credential_files", [])) or None,
              "via": sorted({c.get("via", "unknown") for c in creds})}
        detail = ("Do not mount home-directory credentials into the sandbox.")
        agent_creds = sorted(p for p in readable if p in AGENT_CREDENTIALS)
        if agent_creds:
            ev["agent_credentials"] = agent_creds
            detail += (" Among them is a coding agent's own login credential. A sandboxed command that can open "
                       "it can put the token in its output, and from there in a transcript or a commit; the agent "
                       "process needs it, the commands it runs do not.")
        if not sec.get("home_env_matches_passwd", True):
            ev["home_env_matches_passwd"] = False
            detail += (" Note: $HOME does not point at this account's home directory. That is a legitimate "
                       "hardening technique and is not scored against you, but these files were still reached "
                       "through the passwd entry, so the redirection is not containing them.")
        findings.append(_f("SEC-003",
                           "Credential files readable among those probed", "high", "secrets",
                           ev, ["ASI03"], detail))
    if sec.get("pid1_environ_readable") and not proc.get("pid1_is_self"):
        findings.append(_f("SEC-004", "PID 1 environment readable (host or supervisor secrets exposed)", "medium", "secrets", {}, ["ASI03"],
                           "Run the agent in its own PID namespace."))

    # --- Filesystem ---------------------------------------------------------
    w = [d for d in fs.get("writable_dirs", []) if d not in ("/tmp", "/dev/shm")]
    if w:
        findings.append(_f("FS-001", "System paths writable from the sandbox", "high" if any(d in ("/", "/etc", "/usr/bin", "/usr/local/bin") for d in w) else "medium",
                           "filesystem", {"writable": w}, ["ASI05", "ASI04"], "docker --read-only with explicit tmpfs for scratch."))
    if fs.get("cwd_writable") and not w:
        findings.append(_f("FS-007", "Working directory writable, system paths not", "info", "filesystem",
                           {"cwd_writable": True}, ["ASI05"],
                           "Expected for a workspace-write style sandbox: the agent can edit its project and nothing else. "
                           "Informational, not a defect."))
    pers = [p for p in fs.get("persistence", []) if p.get("writable") and not p.get("masked")]
    # host_backed None means the mount could not be resolved: count it, rather
    # than let an unreadable mountinfo make a real write disappear.
    lasting = [p for p in pers if p.get("host_backed") is not False]
    local = [p for p in pers if p.get("host_backed") is False]

    def _ev(items):
        return [{"path": p["path"], "kind": p["kind"], "fstype": p.get("fstype")} for p in items]

    runs_out = [p for p in lasting if p["kind"] in RUNS_OUTSIDE]
    if runs_out:
        findings.append(_f("FS-008", "Files that run outside the sandbox are writable from inside it", "high", "filesystem",
                           {"writable": _ev(runs_out)}, ["ASI05", "ASI10"],
                           "A shell startup file, git hook, ssh authorized_keys or a new file in the home directory runs "
                           "the next time the user opens a shell, runs git or logs in, with none of the sandbox's limits: "
                           "a way out that only has to wait. These are on host-backed storage (the fstype in the "
                           "evidence), so they outlive the sandbox. Mount the home directory and .git read-only, or deny "
                           "these paths explicitly."))
    agent_cfg = [p for p in lasting if p["kind"] == "agent-config"]
    if agent_cfg:
        findings.append(_f("FS-009", "The agent's own configuration is writable from inside its sandbox", "high", "filesystem",
                           {"writable": _ev(agent_cfg)}, ["ASI05", "ASI03"],
                           "An agent that can rewrite its settings or MCP configuration can turn its own sandbox off, "
                           "widen its permissions, or add a hook or server that runs unsandboxed, all of which take effect "
                           "in its next session. Deny writes to these paths from inside the sandbox."))
    if local:
        findings.append(_f("FS-010", "Startup or configuration files writable, but only on storage that dies with the sandbox",
                           "info", "filesystem", {"writable": _ev(local)}, ["ASI05"],
                           "These live on " + ", ".join(sorted({str(p.get('fstype')) for p in local})) + ", which does not "
                           "outlive the sandbox (a container's overlay, a tmpfs), so writing them changes nothing outside it. "
                           "Informational; it becomes FS-008 or FS-009 if the same path is ever bind-mounted from the host."))
    if fs.get("root_rw") and not w:
        findings.append(_f("FS-002", "Root filesystem mounted read-write", "low", "filesystem", {}, ["ASI05"], "docker --read-only."))
    # Docker always binds resolv.conf, hostname and hosts read-write; they are not host reach.
    STANDARD_BINDS = {"/", "/tmp", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts"}
    rw_binds = [m for m in fs.get("bind_mounts", []) if m.get("rw") and m.get("target") not in STANDARD_BINDS]
    if rw_binds:
        findings.append(_f("FS-003", "Read-write bind mounts from the host", "medium", "filesystem",
                           {"mounts": [m["target"] for m in rw_binds][:20]}, ["ASI02", "ASI05"],
                           "Mount only the working tree, read-only where possible; never mount the host root."))
    if fs.get("host_root_visible"):
        findings.append(_f("FS-004", "Host root filesystem appears mounted", "critical", "filesystem", {}, ["ASI05", "ASI10"], "Remove the host root mount."))
    if fs.get("proc_sysrq_writable"):
        findings.append(_f("FS-005", "/proc/sysrq-trigger writable", "critical", "filesystem", {}, ["ASI05"], "Mask /proc/sysrq-trigger; do not run privileged."))
    if len(fs.get("setuid_binaries", [])) > 0 and ident.get("no_new_privs") == 0:
        findings.append(_f("FS-006", "setuid binaries present and usable", "low", "filesystem",
                           {"count": len(fs.get("setuid_binaries", []))}, ["ASI03"], "Strip setuid bits in the image or set no-new-privileges."))

    # --- Process visibility -------------------------------------------------
    if proc.get("visible_pid_count", 0) > 50 and not proc.get("pid1_is_self"):
        findings.append(_f("PROC-001", "Host or sibling processes visible (shared PID namespace)", "medium", "process",
                           {"visible_pid_count": proc.get("visible_pid_count"), "visible_uids": proc.get("visible_uids")}, ["ASI07", "ASI03"],
                           "Give the agent its own PID namespace (default in Docker; avoid --pid=host)."))

    # --- Resources ----------------------------------------------------------
    if res and res.get("memory_max", "max") == "max" and res.get("pids_max", "max") == "max":
        findings.append(_f("RES-001", "No memory or PID limits on the sandbox", "low", "resources", dict(res), ["ASI08"],
                           "docker --memory and --pids-limit."))
    return findings


def raw_score(findings: list[Finding]) -> int:
    """Uncapped sum of finding weights. Distinguishes two sandboxes that both cap out."""
    return sum(f.weight for f in findings)


def score(findings: list[Finding]) -> int:
    """Capped 0-100, for budgets and gates. Use raw_score to rank the very worst."""
    return min(100, raw_score(findings))


def summarize(probe: dict[str, Any]) -> dict[str, Any]:
    findings = analyze(probe)
    return {"score": score(findings), "raw_score": raw_score(findings), "finding_count": len(findings),
            "by_severity": {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_WEIGHT},
            "recommended_flags": recommended_flags(findings),
            "findings": [asdict(f) for f in findings]}


# Minimum container flags that close each finding. Deterministic, so a report can
# print "add these" without guessing. Some will break workloads that legitimately
# need the capability or the network; that is the operator's call.
FINDING_FLAGS = {
    "NET-001": ["--network none"],
    "NET-002": ["--network none"],
    "NET-005": ["(keep the proxy allowlist to the hosts the agent needs)"],
    "PRIV-001": ["--user 65534:65534"],
    "PRIV-002": ["--user 65534:65534"],
    "PRIV-003": ["--cap-drop ALL"],
    "PRIV-004": ["(do not disable the engine's default seccomp profile)"],
    "PRIV-005": ["--security-opt no-new-privileges"],
    "SEC-001": ["(remove the container socket mount)"],
    "SEC-002": ["(inject secrets through a broker, not the environment)"],
    "SEC-003": ["(remove the credential mount)"],
    "SEC-004": ["(own PID namespace: avoid --pid=host)"],
    "SEC-007": ["(do not pass SSH_AUTH_SOCK into the sandbox)"],
    "FS-008": ["(mount the home directory and .git read-only)"],
    "FS-009": ["(deny writes to the agent's own settings from inside the sandbox)"],
    "FS-001": ["--read-only", "--tmpfs /tmp"],
    "FS-002": ["--read-only", "--tmpfs /tmp"],
    "FS-003": ["(mount the working tree only, :ro where possible)"],
    "FS-004": ["(remove the host root mount)"],
    "FS-005": ["(do not run --privileged)"],
    "FS-006": ["--security-opt no-new-privileges"],
    "PROC-001": ["(own PID namespace: avoid --pid=host)"],
    "RES-001": ["--pids-limit 256", "--memory 512m"],
}


def recommended_flags(findings: list[Finding]) -> list[str]:
    """Ordered, de-duplicated flag suggestions closing the observed findings."""
    out: list[str] = []
    for f in findings:
        for flag in FINDING_FLAGS.get(f.id, []):
            if flag not in out:
                out.append(flag)
    return out
