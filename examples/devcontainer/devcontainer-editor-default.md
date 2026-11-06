# Sandbox blast radius: devcontainer-editor-default

**Score: 87 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 10 (critical 1, high 3, medium 1, low 3)

## Target (reproduce with this)
- kind: `captured`
- label: `devcontainer-editor-default`
- how: `VS Code 1.145.1 with ms-vscode-remote.remote-containers@0.469.0, mcr.microsoft.com/devcontainers/python@sha256:79a80515d78783e761af1db255e92767c4e887a2d56dbeb85e7753da8c12dc16, no other settings. The folder was opened in the container under a virtual display, and a task that runs on opening the folder ran the probe, on a GitHub-hosted ubuntu-latest machine with a throwaway SSH agent and git identity. Run by scripts/measure_devcontainer_editor.sh. The machine holds no personal credentials, so this shows what is forwarded, not what a person's forwarded credentials could do.`
- note: `Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec.`
- probe version: `0.7.0`, python `3.12.16`, uid `1001`, seccomp `2`, user namespace `False`

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

### SEC-007 · HIGH · SSH agent socket reachable from the sandbox
- evidence: `{'paths': ['$SSH_AUTH_SOCK']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse, ASI02 Tool Misuse & Exploitation
- fix: A forwarded SSH agent signs with every key loaded into it, for any host those keys open, without the key file ever being readable. Do not pass SSH_AUTH_SOCK into the sandbox; give the agent a scoped deploy key or token instead.

### SEC-003 · HIGH · Credential files readable among those probed
- evidence: `{'readable_of_those_probed': ['~/.gitconfig'], 'probed': 2, 'via': ['HOME']}`
- OWASP agentic: ASI03 Agent Identity & Privilege Abuse
- fix: Do not mount home-directory credentials into the sandbox.

### FS-007 · INFO · Working directory writable, system paths not
- evidence: `{'cwd_writable': True}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: Expected for a workspace-write style sandbox: the agent can edit its project and nothing else. Informational, not a defect.

### FS-010 · INFO · Startup or configuration files writable, but only on storage that dies with the sandbox
- evidence: `{'writable': [{'path': '~/.bashrc', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~/.profile', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~/.zshrc', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~/.zprofile', 'kind': 'shell-startup', 'fstype': 'overlay'}, {'path': '~/.gitconfig', 'kind': 'git-config', 'fstype': 'overlay'}, {'path': '~', 'kind': 'home', 'fstype': 'overlay'}]}`
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: These live on overlay, which does not outlive the sandbox (a container's overlay, a tmpfs), so writing them changes nothing outside it. Informational; it becomes FS-008 or FS-009 if the same path is ever bind-mounted from the host.

### FS-002 · LOW · Root filesystem mounted read-write
- OWASP agentic: ASI05 Unexpected Code Execution
- fix: docker --read-only.

### FS-003 · MEDIUM · Read-write bind mounts from the host
- evidence: `{'mounts': ['/vscode', '/workspaces/project']}`
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
(do not pass SSH_AUTH_SOCK into the sandbox)
(remove the credential mount)
--read-only
--tmpfs /tmp
(mount the working tree only, :ro where possible)
```

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets; when an egress proxy is configured it sends that proxy one CONNECT request per fixed target and a control host, reads the status line and closes, and uses the proxy's password only when AGENTSEC_PROBE_PROXY_AUTH=1, never recording it. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
