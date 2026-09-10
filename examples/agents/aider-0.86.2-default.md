# Sandbox blast radius: aider-0.86.2-default

**Score: 100 / 100** (capped; raw 103) (0 = fully contained; higher = larger blast radius)  
Findings: 11 (critical 1, high 3, medium 3, low 3)

## Target (reproduce with this)
- kind: `captured`
- label: `aider-0.86.2-default`
- how: `aider ships no sandbox. `aider --help` offers no sandbox, container or isolation option, and aider/run_cmd.py:62 executes commands with subprocess.Popen(shell=True, cwd=...) on the host with the inherited environment; aider/commands.py:964 does the same for /run. The probe was executed through that exact call shape, from aider's own interpreter, so the measurement is of the environment an aider-run command actually gets.`
- note: `Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec.`
- probe version: `0.1.0`, python `3.12.3`, uid `1000`, seccomp `0`, user namespace `False`

## Findings
### NET-001 · HIGH · Unrestricted internet egress from the sandbox
- evidence: `{'reached': ['dns-google', 'pypi', 'github', 'cloudflare-dns-ip']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI10 Rogue Agents
- fix: Run the agent with no network (docker --network none) or an allowlisting egress proxy.

### PRIV-004 · MEDIUM · No seccomp filter applied
- evidence: `{'seccomp_mode': 0}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Docker and podman apply a default seccomp profile unless you pass --security-opt seccomp=unconfined; seeing mode 0 means the sandbox is running without one. bubblewrap needs --seccomp with a compiled BPF filter.

### PRIV-005 · LOW · no_new_privs not set (setuid escalation possible)
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: docker --security-opt no-new-privileges.

### SEC-001 · CRITICAL · Container runtime socket reachable from the sandbox
- evidence: `{'paths': ['/var/run/docker.sock', '/run/docker.sock', '/run/containerd/containerd.sock'], 'writable': ['/var/run/docker.sock', '/run/docker.sock'], 'connected': ['/var/run/docker.sock', '/run/docker.sock'], 'refused': [{'path': '/run/containerd/containerd.sock', 'error': 'PermissionError'}]}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI05 Unexpected Code Execution, ASI10 Rogue Agents
- fix: Never expose the Docker/containerd/podman socket to an agent sandbox: a socket that answers is root on the host, and a read-only root filesystem does not take it away.

### SEC-002 · HIGH · Secret-looking environment variables visible to the agent
- evidence: `{'names': ['<redacted>']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI02 Tool Misuse & Exploitation
- fix: Inject secrets through a broker or scoped short-lived tokens; do not export them into the agent's environment.

### SEC-003 · HIGH · Credential files readable among those probed
- evidence: `{'readable_of_those_probed': ['~/.ssh/config', '~/.gitconfig', '~/.config/gh/hosts.yml'], 'probed': 4, 'via': ['HOME']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Do not mount home-directory credentials into the sandbox.

### FS-007 · INFO · Working directory writable, system paths not
- evidence: `{'cwd_writable': True}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Expected for a workspace-write style sandbox: the agent can edit its project and nothing else. Informational, not a defect.

### FS-002 · LOW · Root filesystem mounted read-write
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: docker --read-only.

### FS-003 · MEDIUM · Read-write bind mounts from the host
- evidence: `{'mounts': ['/sys/firmware/efi/efivars', '/boot', '/boot/efi', '/data', '/run/user/1000/doc']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI05 Unexpected Code Execution
- fix: Mount only the working tree, read-only where possible; never mount the host root.

### FS-006 · LOW · setuid binaries present and usable
- evidence: `{'count': 46}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Strip setuid bits in the image or set no-new-privileges.

### PROC-001 · MEDIUM · Host or sibling processes visible (shared PID namespace)
- evidence: `{'visible_pid_count': 431, 'visible_uids': [0, 101, 103, 109, 112, 113, 115, 117, 120, 121, 991, 992, 997, 998, 1000]}`
- OWASP agentic: ASI07 Insecure Inter-Agent Communication, ASI03 Agent Identity & Privilege Abuse
- fix: Give the agent its own PID namespace (default in Docker; avoid --pid=host).

## Equivalent controls (written as the container engine flags; translate for your launcher)

This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
--network none
(do not disable the engine's default seccomp profile)
--security-opt no-new-privileges
(remove the container socket mount)
(inject secrets through a broker, not the environment)
(remove the credential mount)
--read-only
--tmpfs /tmp
(mount the working tree only, :ro where possible)
(own PID namespace: avoid --pid=host)
```

## What the probe does not do
It never reads secret values, sends no data to the egress targets, and writes only a zero-byte temp marker that it removes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
