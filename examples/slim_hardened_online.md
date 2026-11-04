# Sandbox blast radius: slim_hardened_online

**Score: 15 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 1 (critical 0, high 1, medium 0, low 0)

## Target (reproduce with this)
- kind: `container`
- engine: `docker`
- image: `python:3.12-slim`
- digest: `python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9`
- flags: `['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--tmpfs', '/tmp', '--pids-limit', '256', '--memory', '512m']`
- python: `python3`
- command: `docker run --rm -v '<agentsec probe>:/agentsec_probe.py:ro' --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --tmpfs /tmp --pids-limit 256 --memory 512m python:3.12-slim python3 /agentsec_probe.py`
- probe version: `0.4.0`, python `3.12.14`, uid `65534`, seccomp `2`, user namespace `False`

## Findings
### NET-001 · HIGH · Unrestricted internet egress from the sandbox
- evidence: `{'reached': ['dns-google', 'pypi', 'github', 'cloudflare-dns-ip']}`
- OWASP agentic: ASI02 Tool Misuse & Exploitation, ASI10 Rogue Agents
- fix: Run the agent with no network (docker --network none) or an allowlisting egress proxy.

## Minimum flag set that closes the findings above

A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.

```
--network none
```

## What the probe does not do
It never reads secret values: readability is proven by opening a file and reading zero bytes. It sends no data to the egress targets; when an egress proxy is configured it sends that proxy one CONNECT request per fixed target and a control host, reads the status line and closes, and uses the proxy's password only when AGENTSEC_PROBE_PROXY_AUTH=1, never recording it. Its only writes are zero-byte markers, one per probed directory, each removed at once; existing startup and agent-settings files are opened for append and closed without writing, so nothing in them changes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
