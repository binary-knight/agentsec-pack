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


def analyze(probe: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    ident = probe.get("identity", {}) or {}
    net = probe.get("network", {}) or {}
    sec = probe.get("secrets", {}) or {}
    fs = probe.get("filesystem", {}) or {}
    proc = probe.get("process", {}) or {}
    res = probe.get("resources", {}) or {}

    # --- Network egress -----------------------------------------------------
    if net.get("socket_syscall_blocked"):
        findings.append(_f("NET-003", "Network syscalls blocked outright (containment holds)", "info", "network",
                           {"detail": "every network probe was refused before a connection could be attempted"}, ["ASI02"],
                           "No action: the sandbox refuses socket creation, which is stronger than blocking routes."))
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
    if ident.get("seccomp_mode", 0) == 0:
        findings.append(_f("PRIV-004", "No seccomp filter applied", "medium", "privilege", {"seccomp_mode": 0}, ["ASI05"],
                           "Docker and podman apply a default seccomp profile unless you pass --security-opt seccomp=unconfined; "
                           "seeing mode 0 means the sandbox is running without one. bubblewrap needs --seccomp with a compiled BPF filter."))
    if ident.get("no_new_privs") == 0:
        findings.append(_f("PRIV-005", "no_new_privs not set (setuid escalation possible)", "low", "privilege", {}, ["ASI03"],
                           "docker --security-opt no-new-privileges."))

    # --- Secrets ------------------------------------------------------------
    socks = sec.get("container_sockets", [])
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
            findings.append(_f("SEC-006", "Container runtime socket visible but connections are refused", "low", "secrets", ev,
                               ["ASI03"],
                               "The socket path is present in the sandbox's view of the filesystem, but a connect attempt was refused "
                               "(a seccomp filter or LSM). Containment currently holds; it rests on that filter rather than on the "
                               "socket being absent, so removing the path as well is the more durable fix."))
    env_names = [e["name"] for e in sec.get("env_secret_names", [])]
    if env_names:
        findings.append(_f("SEC-002", "Secret-looking environment variables visible to the agent", "high", "secrets",
                           {"names": env_names}, ["ASI03", "ASI02"],
                           "Inject secrets through a broker or scoped short-lived tokens; do not export them into the agent's environment."))
    readable = [c["path"] for c in sec.get("credential_files", []) if c.get("readable") and c["path"] != "/etc/shadow"]
    if any(c["path"] == "/etc/shadow" and c.get("readable") for c in sec.get("credential_files", [])):
        findings.append(_f("SEC-005", "Image shadow file readable (process is root)", "info", "secrets", {"path": "/etc/shadow"}, ["ASI03"],
                           "Informational in a plain image; becomes real if the image carries live account hashes."))
    if readable:
        findings.append(_f("SEC-003", "Credential files readable from the sandbox", "high", "secrets",
                           {"paths": readable}, ["ASI03"], "Do not mount home-directory credentials into the sandbox."))
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
    "PRIV-001": ["--user 65534:65534"],
    "PRIV-002": ["--user 65534:65534"],
    "PRIV-003": ["--cap-drop ALL"],
    "PRIV-004": ["(do not disable the engine's default seccomp profile)"],
    "PRIV-005": ["--security-opt no-new-privileges"],
    "SEC-001": ["(remove the container socket mount)"],
    "SEC-002": ["(inject secrets through a broker, not the environment)"],
    "SEC-003": ["(remove the credential mount)"],
    "SEC-004": ["(own PID namespace: avoid --pid=host)"],
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
