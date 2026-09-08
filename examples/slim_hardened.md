# Sandbox blast radius: slim_hardened

**Score: 0 / 100** (0 = fully contained; higher = larger blast radius)  
Findings: 0 (critical 0, high 0, medium 0, low 0)

## Target (reproduce with this)
> Every control at once: no network, immutable root, no capabilities, unprivileged user, resource limits. The reference point a real agent sandbox should be measured against.

- kind: `container`
- engine: `docker`
- image: `python:3.12-slim`
- digest: `python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`
- flags: `['--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--pids-limit', '256', '--memory', '512m', '--tmpfs', '/tmp']`
- python: `python3`
- command: `docker run --rm -v '<agentsec probe>:/agentsec_probe.py:ro' --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --pids-limit 256 --memory 512m --tmpfs /tmp python:3.12-slim python3 /agentsec_probe.py`
- preset: `docker-hardened`
- probe version: `0.1.0`, python `3.12.14`, uid `65534`, seccomp `2`, user namespace `False`

## Findings
None. The probe could not reach the network, secrets, host filesystem or extra privileges from inside this sandbox.
## What the probe does not do
It never reads secret values, sends no data to the egress targets, and writes only a zero-byte temp marker that it removes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.
