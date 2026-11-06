# Sandbox blast radius: modal-sandbox-cidr-allowlist

**Score: 100 / 100** (capped; raw 105) (0 = fully contained; higher = larger blast radius)  
Findings: 12 (critical 1, high 3, medium 4, low 1)

## Target (reproduce with this)
- kind: `captured`
- label: `modal-sandbox-cidr-allowlist`
- how: `modal client 1.5.3, modal.Sandbox.create with Image.debian_slim(python_version=3.12), outbound_cidr_allowlist=[1.1.1.1/32]. The probe ran through Sandbox.exec, by scripts/measure_modal.py. No agent was involved, and the container holds no personal credentials. Modal runs this under gVisor, so privilege, capability, seccomp, /proc and resource findings describe gVisor's kernel, not the host's, and escaping gVisor was not tested.`
- note: `Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec.`
- probe version: `0.7.0`, python `3.12.10`, uid `0`, seccomp `0`, user namespace `False`

## Findings
### NET-005 · MEDIUM · Egress is allowlisted
- evidence: `{'reached': ['cloudflare-dns-ip'], 'control': {'detail': 'OSError', 'name': 'canary-example.com', 'reached': False}}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI10 Rogue Agents
- fix: These hosts were reached directly and the control host, example.com, was not, so the network is filtered and these are what an injected command can reach at least. Keep the list to what the agent needs; a host that accepts uploads, such as a code host or a package index, is an exfiltration route.

### PRIV-007 · INFO · The kernel seen here is a user-space kernel
- evidence: `{'kernel': 'gvisor'}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation
- fix: Privilege, capability, seccomp, /proc and resource findings in this report describe what the process gets from this kernel, not from the host's. The score still counts them, so it overstates what they show. This probe does not test whether a process can leave this kernel.

### PRIV-001 · HIGH · Agent runs as real root (uid 0, not in a user namespace)
- evidence: `{'euid': 0}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI05 Unexpected Code Execution
- fix: Run as an unprivileged user (docker --user) or inside a user namespace.

### PRIV-003 · HIGH · Dangerous Linux capabilities in the effective set
- evidence: `{'capabilities': ['CAP_DAC_OVERRIDE', 'CAP_MKNOD', 'CAP_SETGID', 'CAP_SETUID', 'CAP_SYS_CHROOT', 'CAP_SYS_PTRACE']}`
- OWASP agentic: ASI05 Unexpected Code Execution, ASI03 Agent Identity & Privilege Abuse
- fix: docker --cap-drop ALL, then add back only what the workload needs.

### PRIV-004 · MEDIUM · No seccomp filter applied
- evidence: `{'seccomp_mode': 0}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Docker and podman apply a default seccomp profile unless you pass --security-opt seccomp=unconfined; seeing mode 0 means the sandbox is running without one. bubblewrap needs --seccomp with a compiled BPF filter.

### SEC-005 · INFO · Image shadow file readable (process is root)
- evidence: `{'path': '/etc/shadow'}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Informational in a plain image; becomes real if the image carries live account hashes.

### SEC-004 · MEDIUM · PID 1 environment readable (host or supervisor secrets exposed)
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Run the agent in its own PID namespace.

### FS-001 · HIGH · System paths writable from the sandbox
- evidence: `{'writable': ['/', '/etc', '/usr/bin', '/usr/local/bin', '/root', '/home', '/var', '/opt']}`
- OWASP agentic: ASI05 Unexpected Code Execution, ASI04 Agentic Supply Chain Compromise
- fix: docker --read-only with explicit tmpfs for scratch.

### FS-010 · INFO · Startup or configuration files writable, but only on storage that dies with the sandbox
- evidence: `{'writable': [{'path': '~/.bashrc', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~/.profile', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~', 'kind': 'home', 'fstype': 'overlay'}]}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: These live on overlay, which does not outlive the sandbox (a container's overlay, a tmpfs), so writing them changes nothing outside it. Informational; it becomes FS-008 or FS-009 if the same path is ever bind-mounted from the host.

### FS-003 · MEDIUM · Read-write bind mounts from the host
- evidence: `{'mounts': ['/dev', '/__modal/mounts']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI05 Unexpected Code Execution
- fix: Mount only the working tree, read-only where possible; never mount the host root.

### FS-005 · CRITICAL · /proc/sysrq-trigger writable
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Mask /proc/sysrq-trigger; do not run privileged.

### RES-001 · LOW · No memory or PID limits on the sandbox
- evidence: `{'memory_limit_v1': '728677150720'}`
- OWASP agentic: ASI08 Cascading Agent Failures
- fix: docker --memory and --pids-limit.

## Equivalent controls (written as the container engine flags; translate for your launcher)

This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
(keep the proxy allowlist to the hosts the agent needs)
--user 65534:65534
--cap-drop ALL
(do not disable the engine's default seccomp profile)
(own PID namespace: avoid --pid=host)
--read-only
--tmpfs /tmp
(mount the working tree only, :ro where possible)
(do not run --privileged)
--pids-limit 256
--memory 512m
```

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets; when an egress proxy is configured it sends that proxy one CONNECT request per fixed target and a control host, reads the status line and closes, and uses the proxy's password only when AGENTSEC_PROBE_PROXY_AUTH=1, never recording it. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
