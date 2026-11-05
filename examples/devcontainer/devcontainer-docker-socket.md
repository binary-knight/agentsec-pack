# Sandbox blast radius: devcontainer-docker-socket

**Score: 60 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 9 (critical 1, high 1, medium 1, low 4)

## Target (reproduce with this)
- kind: `captured`
- label: `devcontainer-docker-socket`
- how: `devcontainer CLI 0.90.0, mcr.microsoft.com/devcontainers/python@sha256:79a80515d78783e761af1db255e92767c4e887a2d56dbeb85e7753da8c12dc16, the host's Docker socket mounted into the container. devcontainer up, then the probe through devcontainer exec, on a GitHub-hosted ubuntu-latest machine. Run by scripts/measure_devcontainer.sh. The CLI was used, not an editor, so nothing an editor forwards into the container is included.`
- note: `Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec.`
- probe version: `0.6.0`, python `3.12.16`, uid `1001`, seccomp `2`, user namespace `False`

## Findings
### NET-001 · HIGH · Unrestricted internet egress from the sandbox
- evidence: `{'reached': ['dns-google', 'pypi', 'github', 'cloudflare-dns-ip']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI10 Rogue Agents
- fix: Run the agent with no network (docker --network none) or an allowlisting egress proxy.

### NET-002 · CRITICAL · Cloud instance-metadata endpoint reachable
- evidence: `{'reached': ['cloud-metadata-169.254.169.254']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI02 Tool Misuse & Exploitation
- fix: Block 169.254.169.254 and metadata.google.internal from the agent's network namespace.

### PRIV-005 · LOW · no_new_privs not set (setuid escalation possible)
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: docker --security-opt no-new-privileges.

### SEC-006 · LOW · Container runtime socket visible but connections are refused
- evidence: `{'paths': ['/var/run/docker.sock'], 'writable': [], 'connected': [], 'refused': [{'path': '/var/run/docker.sock', 'error': 'PermissionError'}], 'unix_control': {'connected': True, 'stage': 'connect', 'supported': True, 'where': '/tmp'}}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: A control connection to a socket the probe created itself succeeded, so unix-domain connections do work here and the refusal is specific to these paths. Containment rests on that path-scoped rule rather than on the socket being absent, so removing the path as well is the more durable fix.

### FS-007 · INFO · Working directory writable, system paths not
- evidence: `{'cwd_writable': True}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Expected for a workspace-write style sandbox: the agent can edit its project and nothing else. Informational, not a defect.

### FS-010 · INFO · Startup or configuration files writable, but only on storage that dies with the sandbox
- evidence: `{'writable': [{'path': '~/.bashrc', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~/.profile', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~/.zshrc', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~/.zprofile', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~', 'kind': 'home', 'fstype': 'overlay'}]}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: These live on overlay, which does not outlive the sandbox (a container's overlay, a tmpfs), so writing them changes nothing outside it. Informational; it becomes FS-008 or FS-009 if the same path is ever bind-mounted from the host.

### FS-002 · LOW · Root filesystem mounted read-write
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: docker --read-only.

### FS-003 · MEDIUM · Read-write bind mounts from the host
- evidence: `{'mounts': ['/workspaces/docker-socket']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI05 Unexpected Code Execution
- fix: Mount only the working tree, read-only where possible; never mount the host root.

### FS-006 · LOW · setuid binaries present and usable
- evidence: `{'count': 30}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Strip setuid bits in the image or set no-new-privileges.

## Equivalent controls (written as the container engine flags; translate for your launcher)

This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
--network none
--security-opt no-new-privileges
--read-only
--tmpfs /tmp
(mount the working tree only, :ro where possible)
```

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets; when an egress proxy is configured it sends that proxy one CONNECT request per fixed target and a control host, reads the status line and closes, and uses the proxy's password only when AGENTSEC_PROBE_PROXY_AUTH=1, never recording it. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
