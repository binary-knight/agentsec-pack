# Sandbox blast radius: macos-gha-no-sandbox

**Score: 76 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 6 (critical 0, high 4, medium 2, low 0)

## Target (reproduce with this)
- kind: `self`
- python: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python`
- proxy_auth: `False`
- label: `macos-gha-no-sandbox`
- how: `GitHub-hosted macos-latest machine, agentsec probe launched with env -i, no sandbox`
- probe version: `0.6.0`, python `3.12.10`, uid `501`, seccomp `None`, user namespace `None`

## Findings
### NET-001 · HIGH · Unrestricted internet egress from the sandbox
- evidence: `{'reached': ['dns-google', 'pypi', 'github', 'cloudflare-dns-ip']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI10 Rogue Agents
- fix: Run the agent with no network (docker --network none) or an allowlisting egress proxy.

### PRIV-006 · MEDIUM · No Seatbelt sandbox applied
- evidence: `{'seatbelt': 0}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: macOS reports that this process runs under no Seatbelt profile, so nothing below the user's own permissions limits what it can reach. Run the agent in its sandbox mode, or under a sandbox-exec profile.

### SEC-003 · HIGH · Credential files readable among those probed
- evidence: `{'readable_of_those_probed': ['~/.gitconfig'], 'probed': 2, 'via': ['HOME']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Do not mount home-directory credentials into the sandbox.

### FS-001 · HIGH · System paths writable from the sandbox
- evidence: `{'writable': ['/usr/local/bin', '/opt/homebrew/bin']}`
- OWASP agentic: ASI05 Unexpected Code Execution, ASI04 Agentic Supply Chain Compromise
- fix: docker --read-only with explicit tmpfs for scratch.

### FS-008 · HIGH · Files that run outside the sandbox are writable from inside it
- evidence: `{'writable': [{'path': '~/.bashrc', 'kind': 'shell-startup', 'fstype': None}, {'path': '~/.bash_profile', 'kind': 'shell-startup', 'fstype': None}, {'path': '~/.gitconfig', 'kind': 'git-config', 'fstype': None}, {'path': '~', 'kind': 'home', 'fstype': None}, {'path': './.git/hooks', 'kind': 'git-hooks', 'fstype': None}, {'path': '~/Library/LaunchAgents', 'kind': 'desktop-autostart', 'fstype': None}]}`
- OWASP agentic: ASI05 Unexpected Code Execution, ASI10 Rogue Agents
- fix: A shell startup file, git hook, ssh authorized_keys or a new file in the home directory runs the next time the user opens a shell, runs git or logs in, with none of the sandbox's limits: a way out that only has to wait. These are on host-backed storage (the fstype in the evidence), so they outlive the sandbox. Mount the home directory and .git read-only, or deny these paths explicitly.

### PROC-001 · MEDIUM · Host or sibling processes visible (shared PID namespace)
- evidence: `{'visible_pid_count': 459, 'visible_uids': []}`
- OWASP agentic: ASI07 Insecure Inter-Agent Communication, ASI03 Agent Identity & Privilege Abuse
- fix: Give the agent its own PID namespace (default in Docker; avoid --pid=host).

## Equivalent controls (written as the container engine flags; translate for your launcher)

This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
--network none
(remove the credential mount)
--read-only
--tmpfs /tmp
(mount the home directory and .git read-only)
(own PID namespace: avoid --pid=host)
```

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets; when an egress proxy is configured it sends that proxy one CONNECT request per fixed target and a control host, reads the status line and closes, and uses the proxy's password only when AGENTSEC_PROBE_PROXY_AUTH=1, never recording it. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
