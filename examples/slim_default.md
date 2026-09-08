# Sandbox blast radius: slim_default

**Score: 59 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 7 (critical 0, high 3, medium 1, low 2)

## Target (reproduce with this)
- kind: `docker`
- image: `python:3.12-slim`
- flags: `[]`
- python: `python3`
- command: `docker run --rm -v /home/jknight/agentsec-pack/agentsec/probe/blast_probe.py:/agentsec_probe.py:ro python:3.12-slim python3 /agentsec_probe.py`
- probe version: `0.1.0`, python `3.12.14`, uid `0`, seccomp `2`, user namespace `False`

## Findings
### NET-001 · HIGH · Unrestricted internet egress from the sandbox
- evidence: `{'reached': ['dns-google', 'pypi', 'github', 'cloudflare-dns-ip']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI10 Rogue Agents
- fix: Run the agent with no network (docker --network none) or an allowlisting egress proxy.

### PRIV-001 · HIGH · Agent runs as real root (uid 0, not in a user namespace)
- evidence: `{'euid': 0}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI05 Unexpected Code Execution
- fix: Run as an unprivileged user (docker --user) or inside a user namespace.

### PRIV-003 · MEDIUM · Dangerous Linux capabilities in the effective set
- evidence: `{'capabilities': ['CAP_DAC_OVERRIDE', 'CAP_MKNOD', 'CAP_NET_RAW', 'CAP_SETGID', 'CAP_SETUID', 'CAP_SYS_CHROOT']}`
- OWASP agentic: ASI05 Unexpected Code Execution, ASI03 Agent Identity & Privilege Abuse
- fix: docker --cap-drop ALL, then add back only what the workload needs.

### PRIV-005 · LOW · no_new_privs not set (setuid escalation possible)
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: docker --security-opt no-new-privileges.

### SEC-005 · INFO · Image shadow file readable (process is root)
- evidence: `{'path': '/etc/shadow'}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Informational in a plain image; becomes real if the image carries live account hashes.

### FS-001 · HIGH · System paths writable from the sandbox
- evidence: `{'writable': ['/', '/etc', '/usr/bin', '/usr/local/bin', '/root', '/home', '/var', '/opt']}`
- OWASP agentic: ASI05 Unexpected Code Execution, ASI04 Agentic Supply Chain Compromise
- fix: docker --read-only with explicit tmpfs for scratch.

### FS-006 · LOW · setuid binaries present and usable
- evidence: `{'count': 24}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Strip setuid bits in the image or set no-new-privileges.

## What the probe does not do
It never reads secret values, sends no data to the egress targets, and writes only a zero-byte temp marker that it removes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
