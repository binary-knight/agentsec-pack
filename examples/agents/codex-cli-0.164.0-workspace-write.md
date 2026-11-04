# Sandbox blast radius: codex-cli-0.164.0-workspace-write

**Score: 34 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 6 (critical 0, high 1, medium 2, low 1)

## Target (reproduce with this)
- kind: `captured`
- label: `codex-cli-0.164.0-workspace-write`
- how: `codex exec -m gpt-6-astra -c model_reasoning_effort=low -c service_tier=default --sandbox workspace-write --skip-git-repo-check --json, asked to run python3 <probe> and nothing else. Probe 0.4.0, launched with env -i (HOME, PATH, TERM, USER, SHELL, LANG only), on 2026-11-04, in a throwaway git repository holding an empty .codex/config.toml so the persistence check had project files to test. The probe's stdout was taken from codex's --json event stream (the command_execution item's aggregated_output), not retyped by the model.`
- note: `Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec.`
- probe version: `0.4.0`, python `3.12.3`, uid `1000`, seccomp `2`, user namespace `True`

## Findings
### NET-003 · INFO · No network reachable from the sandbox (containment holds)
- evidence: `{'detail': 'sockets can be created but every outbound connection and name lookup was refused'}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation
- fix: No action: nothing the probe tried could leave this sandbox over the network.

### SEC-006 · LOW · Container runtime socket visible but connections are refused
- evidence: `{'paths': ['/var/run/docker.sock', '/run/containerd/containerd.sock'], 'writable': ['/var/run/docker.sock'], 'connected': [], 'refused': [{'path': '/var/run/docker.sock', 'error': 'PermissionError'}, {'path': '/run/containerd/containerd.sock', 'error': 'PermissionError'}], 'unix_control': {'connected': False, 'error': 'OSError', 'stage': 'bind', 'supported': False, 'where': '/tmp/claude-1000/-home-<redacted>-agentsec/faa22197-f3dd-4639-b010-2d11003057b6/scratchpad/codex/proj'}}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: The control also failed, at the bind call, so unix-domain sockets appear to be blocked wholesale rather than for these paths specifically. The visible socket paths are inert under that filter; this finding is informational, and removing the paths would only be defence in depth.

### SEC-003 · HIGH · Credential files readable among those probed
- evidence: `{'readable_of_those_probed': ['~/.ssh/config', '~/.gitconfig', '~/.config/gh/hosts.yml', '~/.claude/.credentials.json', '~/.codex/auth.json'], 'probed': 6, 'via': ['HOME'], 'agent_credentials': ['~/.claude/.credentials.json', '~/.codex/auth.json']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Do not mount home-directory credentials into the sandbox. Among them is a coding agent's own login credential. A sandboxed command that can open it can put the token in its output, and from there in a transcript or a commit; the agent process needs it, the commands it runs do not.

### SEC-004 · MEDIUM · PID 1 environment readable (host or supervisor secrets exposed)
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Run the agent in its own PID namespace.

### FS-007 · INFO · Working directory writable, system paths not
- evidence: `{'cwd_writable': True}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Expected for a workspace-write style sandbox: the agent can edit its project and nothing else. Informational, not a defect.

### FS-003 · MEDIUM · Read-write bind mounts from the host
- evidence: `{'mounts': ['/tmp/claude-1000/-home-<redacted>-agentsec/faa22197-f3dd-4639-b010-2d11003057b6/scratchpad/codex/proj']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI05 Unexpected Code Execution
- fix: Mount only the working tree, read-only where possible; never mount the host root.

## Equivalent controls (written as the container engine flags; translate for your launcher)

This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
(remove the credential mount)
(own PID namespace: avoid --pid=host)
(mount the working tree only, :ro where possible)
```

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets; when an egress proxy is configured it sends that proxy one CONNECT request per fixed target and a control host, reads the status line and closes, and uses the proxy's password only when AGENTSEC_PROBE_PROXY_AUTH=1, never recording it. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
