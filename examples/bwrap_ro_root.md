# Sandbox blast radius: bwrap_ro_root

**Score: 86 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 6 (critical 1, high 3, medium 2, low 0)

## Target (reproduce with this)
> A common lightweight pattern: the whole host filesystem read-only, own PID namespace, network still shared. Shows what read-only alone does and does not buy. No named agent is claimed to use this; it is a configuration, not a citation.

- kind: `command`
- template: `bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --unshare-pid --die-with-parent python3 {probe}`
- command: `bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --unshare-pid --die-with-parent python3 <agentsec probe>`
- preset: `bwrap-ro-root`
- probe version: `0.1.0`, python `3.12.3`, uid `1000`, seccomp `0`, user namespace `True`

## Findings
### NET-001 · HIGH · Unrestricted internet egress from the sandbox
- evidence: `{'reached': ['dns-google', 'pypi', 'github', 'cloudflare-dns-ip']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI10 Rogue Agents
- fix: Run the agent with no network (docker --network none) or an allowlisting egress proxy.

### PRIV-004 · MEDIUM · No seccomp filter applied
- evidence: `{'seccomp_mode': 0}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Docker and podman apply a default seccomp profile unless you pass --security-opt seccomp=unconfined; seeing mode 0 means the sandbox is running without one. bubblewrap needs --seccomp with a compiled BPF filter.

### SEC-001 · CRITICAL · Container runtime socket reachable from the sandbox
- evidence: `{'paths': ['/var/run/docker.sock', '/run/docker.sock', '/run/containerd/containerd.sock'], 'writable': ['/var/run/docker.sock', '/run/docker.sock'], 'connected': ['/var/run/docker.sock', '/run/docker.sock']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI05 Unexpected Code Execution, ASI10 Rogue Agents
- fix: Never expose the Docker/containerd/podman socket to an agent sandbox: a writable socket is root on the host, and a read-only root filesystem does not take it away.

### SEC-002 · HIGH · Secret-looking environment variables visible to the agent
- evidence: `{'names': ['<redacted>']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI02 Tool Misuse & Exploitation
- fix: Inject secrets through a broker or scoped short-lived tokens; do not export them into the agent's environment.

### SEC-003 · HIGH · Credential files readable from the sandbox
- evidence: `{'paths': ['~/.ssh/config', '~/.gitconfig', '~/.config/gh/hosts.yml']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Do not mount home-directory credentials into the sandbox.

### SEC-004 · MEDIUM · PID 1 environment readable (host or supervisor secrets exposed)
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Run the agent in its own PID namespace.

## Equivalent controls (written as the container engine flags; translate for your launcher)

This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
--network none
(do not disable the engine's default seccomp profile)
(remove the container socket mount)
(inject secrets through a broker, not the environment)
(remove the credential mount)
(own PID namespace: avoid --pid=host)
```

## What the probe does not do
It never reads secret values, sends no data to the egress targets, and writes only a zero-byte temp marker that it removes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
