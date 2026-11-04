# Sandbox blast radius: claude-code-2.1.317-sandbox-auto-mode

**Score: 41 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 6 (critical 0, high 2, medium 1, low 1)

## Target (reproduce with this)
- kind: `captured`
- label: `claude-code-2.1.317-sandbox-auto-mode`
- how: `From inside a Claude Code 2.1.317 session (model claude-opus-5-5, auto permission mode) on 2026-11-04, through its Bash tool, which runs each command in its own bubblewrap sandbox with egress through a local filtering proxy. No allowed_domains were passed for this command, so the per-command egress allowlist held only the session defaults. Command: python3 agentsec/probe/blast_probe.py > $TMPDIR/probe.json (probe 0.3.0), then agentsec score --redact.`
- note: `Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec.`
- probe version: `0.3.0`, python `3.12.3`, uid `1000`, seccomp `2`, user namespace `True`

## Findings
### NET-004 · INFO · Direct connections refused; egress through the configured proxy was not measured
- evidence: `{'proxy_env': ['ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY', 'all_proxy', 'http_proxy', 'https_proxy'], 'unmeasured': True}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation
- fix: Every direct connection the probe tried was refused, but ALL_PROXY, HTTPS_PROXY, HTTP_PROXY, all_proxy, http_proxy, https_proxy are set and the probe does not connect through a proxy, so what the proxy lets through is unknown. Treat the network axis as unverified, not as sealed: check the proxy's allowlist yourself and keep it to the hosts the agent needs. A host that accepts uploads, such as a code host, is an exfiltration route.

### SEC-006 · LOW · Container runtime socket visible but connections are refused
- evidence: `{'paths': ['/var/run/docker.sock', '/run/containerd/containerd.sock'], 'writable': ['/var/run/docker.sock'], 'connected': [], 'refused': [{'path': '/var/run/docker.sock', 'error': 'PermissionError'}, {'path': '/run/containerd/containerd.sock', 'error': 'PermissionError'}], 'unix_control': {'connected': False, 'error': 'PermissionError', 'stage': 'socket', 'supported': False, 'where': '~/agentsec'}}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: The control also failed, at the socket call, so unix-domain sockets appear to be blocked wholesale rather than for these paths specifically. The visible socket paths are inert under that filter; this finding is informational, and removing the paths would only be defence in depth.

### SEC-002 · HIGH · Secret-looking environment variables visible to the agent
- evidence: `{'names': ['<redacted>', '<redacted>']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI02 Tool Misuse & Exploitation
- fix: Inject secrets through a broker or scoped short-lived tokens; do not export them into the agent's environment.

### SEC-003 · HIGH · Credential files readable among those probed
- evidence: `{'readable_of_those_probed': ['~/.ssh/config', '~/.gitconfig', '~/.config/gh/hosts.yml', '~/.claude/.credentials.json', '~/.codex/auth.json'], 'probed': 6, 'via': ['HOME'], 'agent_credentials': ['~/.claude/.credentials.json', '~/.codex/auth.json']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Do not mount home-directory credentials into the sandbox. Among them is a coding agent's own login credential. A sandboxed command that can open it can put the token in its output, and from there in a transcript or a commit; the agent process needs it, the commands it runs do not.

### FS-007 · INFO · Working directory writable, system paths not
- evidence: `{'cwd_writable': True}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Expected for a workspace-write style sandbox: the agent can edit its project and nothing else. Informational, not a defect.

### FS-003 · MEDIUM · Read-write bind mounts from the host
- evidence: `{'mounts': ['~/.npm/_logs', '~/agentsec', '/tmp/claude-1000']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI05 Unexpected Code Execution
- fix: Mount only the working tree, read-only where possible; never mount the host root.

## Equivalent controls (written as the container engine flags; translate for your launcher)

This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
(inject secrets through a broker, not the environment)
(remove the credential mount)
(mount the working tree only, :ro where possible)
```

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
