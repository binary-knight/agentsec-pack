# Sandbox blast radius: slim_hardened

**Score: 0 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 1 (critical 0, high 0, medium 0, low 0)

## Target (reproduce with this)
> Every control at once: no network, immutable root, no capabilities, unprivileged user, resource limits. The reference point a real agent sandbox should be measured against.

- kind: `container`
- engine: `docker`
- image: `python:3.12-slim`
- digest: `python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9`
- flags: `['--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--pids-limit', '256', '--memory', '512m', '--tmpfs', '/tmp']`
- python: `python3`
- command: `docker run --rm -v '<agentsec probe>:/agentsec_probe.py:ro' --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --pids-limit 256 --memory 512m --tmpfs /tmp python:3.12-slim python3 /agentsec_probe.py`
- preset: `docker-hardened`
- probe version: `0.4.0`, python `3.12.14`, uid `65534`, seccomp `2`, user namespace `False`

## Findings
### NET-003 · INFO · No network reachable from the sandbox (containment holds)
- evidence: `{'detail': 'sockets can be created but every outbound connection and name lookup was refused'}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation
- fix: No action: nothing the probe tried could leave this sandbox over the network.

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets; when an egress proxy is configured it sends that proxy one CONNECT request per fixed target and a control host, reads the status line and closes, and uses the proxy's password only when AGENTSEC_PROBE_PROXY_AUTH=1, never recording it. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
