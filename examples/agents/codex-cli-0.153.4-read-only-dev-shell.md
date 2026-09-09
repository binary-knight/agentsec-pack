# Sandbox blast radius: codex-cli-0.153.4-read-only-dev-shell

**Score: 41 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 5 (critical 0, high 2, medium 1, low 1)

## Target (reproduce with this)
- kind: `captured`
- label: `codex-cli-0.153.4-read-only-dev-shell`
- how: `the same command WITHOUT env -i: launched from a developer shell that had already exported credentials (here a Claude Code session's own token). Recorded to show that the launching shell's environment is inherited into the sandbox and is part of the measured blast radius.`
- note: `Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec.`
- probe version: `0.1.0`, python `3.12.3`, uid `1000`, seccomp `2`, user namespace `True`

## Findings
### NET-003 · INFO · No network reachable from the sandbox (containment holds)
- evidence: `{'detail': 'sockets can be created but every outbound connection and name lookup was refused'}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation
- fix: No action: nothing the probe tried could leave this sandbox over the network.

### SEC-006 · LOW · Container runtime socket visible but connections are refused
- evidence: `{'paths': ['/var/run/docker.sock', '/run/docker.sock', '/run/containerd/containerd.sock'], 'writable': ['/var/run/docker.sock', '/run/docker.sock'], 'connected': [], 'refused': [{'path': '/var/run/docker.sock', 'error': 'PermissionError'}, {'path': '/run/docker.sock', 'error': 'PermissionError'}, {'path': '/run/containerd/containerd.sock', 'error': 'PermissionError'}], 'unix_control': {'connected': False, 'error': 'OSError', 'stage': 'mkdtemp', 'supported': False, 'where': '/tmp/codexmeasure'}, 'unix_control_nopath': {'error': 'PermissionError', 'stage': 'connect', 'verdict': 'connect refused before path lookup'}}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: The bind-and-connect control could not run (no writable directory), but connecting to a path that does not exist was refused with PermissionError rather than FileNotFoundError. The call is therefore blocked before the path is consulted, so the refusal is not specific to these sockets and the visible paths are inert. Informational.

### SEC-002 · HIGH · Secret-looking environment variables visible to the agent
- evidence: `{'names': ['CLAUDE_CODE_MESSAGING_TOKEN']}`
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
(inject secrets through a broker, not the environment)
(remove the credential mount)
(own PID namespace: avoid --pid=host)
```

## What the probe does not do
It never reads secret values, sends no data to the egress targets, and writes only a zero-byte temp marker that it removes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
