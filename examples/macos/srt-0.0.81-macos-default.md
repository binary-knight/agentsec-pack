# Sandbox blast radius: srt-0.0.81-macos-default

**Score: 38 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 4 (critical 0, high 2, medium 1, low 0)

## Target (reproduce with this)
- kind: `captured`
- label: `srt-0.0.81-macos-default`
- how: `@anthropic-ai/sandbox-runtime 0.0.81: srt -- python probe.py, no settings file, from a throwaway git repository holding empty project config files for Claude Code, Codex and Antigravity, launched with env -i and AGENTSEC_PROBE_PROXY_AUTH=1 so the probe could ask srt's local proxy about each target, on a GitHub-hosted macos-latest machine`
- note: `Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec.`
- probe version: `0.7.0`, python `3.12.10`, uid `501`, seccomp `None`, user namespace `None`

## Findings
### NET-003 · INFO · No network reachable from the sandbox (containment holds)
- evidence: `{'via': 'proxy', 'proxy_source': 'HTTPS_PROXY', 'auth': 'used', 'proxy_accepted_connect_to': [], 'control': 'refused (403)', 'detail': 'direct connections refused, and the proxy refused a tunnel to every target and to the control'}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation
- fix: No action: the probe could not leave this sandbox directly or through its proxy.

### SEC-002 · HIGH · Secret-looking environment variables visible to the agent
- evidence: `{'names': ['<redacted>']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI02 Tool Misuse & Exploitation
- fix: Inject secrets through a broker or scoped short-lived tokens; do not export them into the agent's environment.

### SEC-003 · HIGH · Credential files readable among those probed
- evidence: `{'readable_of_those_probed': ['~/.gitconfig'], 'probed': 2, 'via': ['HOME']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Do not mount home-directory credentials into the sandbox.

### PROC-001 · MEDIUM · Host or sibling processes visible (shared PID namespace)
- evidence: `{'visible_pid_count': 487, 'visible_uids': []}`
- OWASP agentic: ASI07 Insecure Inter-Agent Communication, ASI03 Agent Identity & Privilege Abuse
- fix: Give the agent its own PID namespace (default in Docker; avoid --pid=host).

## Equivalent controls (written as the container engine flags; translate for your launcher)

This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
(inject secrets through a broker, not the environment)
(remove the credential mount)
(own PID namespace: avoid --pid=host)
```

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets; when an egress proxy is configured it sends that proxy one CONNECT request per fixed target and a control host, reads the status line and closes, and uses the proxy's password only when AGENTSEC_PROBE_PROXY_AUTH=1, never recording it. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
