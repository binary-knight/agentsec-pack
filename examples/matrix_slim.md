# Sandbox blast radius across 11 configurations

Image: `python:3.12-slim`
Digest: `python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9`
Probe version `0.4.0`, measured 2026-11-04.

| Configuration | Score | Findings | Worst finding |
|---|---:|---:|---|
| `bwrap-ro-root` | 71 | 5 | SEC-001 Container runtime socket reachable from the sandbox |
| `docker-default` | 59 | 8 | NET-001 Unrestricted internet egress from the sandbox |
| `bwrap-unshare-all` | 56 | 5 | SEC-001 Container runtime socket reachable from the sandbox |
| `bwrap-unshare-all-clearenv` | 56 | 5 | SEC-001 Container runtime socket reachable from the sandbox |
| `bwrap-workdir-net` | 54 | 5 | NET-001 Unrestricted internet egress from the sandbox |
| `codex-cli-0.153.4-bwrap-layer` | 48 | 4 | SEC-001 Container runtime socket reachable from the sandbox |
| `podman-rootless-default` | 47 | 8 | NET-001 Unrestricted internet egress from the sandbox |
| `docker-no-network` | 44 | 8 | PRIV-001 Agent runs as real root (uid 0, not in a user namespace) |
| `docker-readonly` | 44 | 6 | NET-001 Unrestricted internet egress from the sandbox |
| `docker-hardened` | 0 | 1 | NET-003 No network reachable from the sandbox (containment holds) |
| `podman-rootless-hardened` | 0 | 1 | NET-003 No network reachable from the sandbox (containment holds) |

Sandboxes that bind the host filesystem (the bwrap rows) are scored against **this host**: what they expose depends on what the machine has. A host with no container socket and no credentials in the home directory scores lower on the same configuration. Container rows are properties of the image and flags, and travel.

0 means the probe could reach nothing from inside: no network, no secrets, no writable system paths, no extra privileges. Higher is a larger blast radius. Scores are the sum of fixed per-finding weights, capped at 100.

## What each configuration is
- **bwrap-ro-root** — A common lightweight pattern: the whole host filesystem read-only, own PID namespace, network still shared. Shows what read-only alone does and does not buy. No named agent is claimed to use this; it is a configuration, not a citation.
- **docker-default** — A container run the way most quick-start docs show it: root inside, full network, writable root filesystem, default capability set.
- **bwrap-unshare-all** — The same, with every namespace unshared, so the network is gone. The environment is still inherited from the parent.
- **bwrap-unshare-all-clearenv** — Adds --clearenv. Compare against bwrap-unshare-all to see exactly what the parent's environment was handing the agent.
- **bwrap-workdir-net** — System directories read-only, one writable working directory, network left on so the agent can fetch packages. A plausible coding-agent sandbox shape, composed here rather than taken from any named product.
- **codex-cli-0.153.4-bwrap-layer** — The bubblewrap layer of OpenAI Codex CLI 0.153.4 --sandbox read-only, copied verbatim from the live process argv (see source). It reproduces ONE of the two layers. Codex then execs its own helper with --apply-seccomp-then-exec and a --permission-profile, and that second layer is what refuses unix-domain bind and connect. Running this preset therefore scores HIGHER than the real sandbox, and the difference is the seccomp filter. Use it to see what bubblewrap alone buys, not as a stand-in for Codex.
- **podman-rootless-default** — Rootless podman with default flags: the container's root is a namespaced root mapped to an unprivileged host uid, which changes what 'runs as root' costs.
- **docker-no-network** — The single cheapest control: an agent that cannot open a socket cannot exfiltrate, whatever it is talked into doing.
- **docker-readonly** — Immutable root filesystem with scratch space, so a compromised agent cannot persist changes into the image layer.
- **docker-hardened** — Every control at once: no network, immutable root, no capabilities, unprivileged user, resource limits. The reference point a real agent sandbox should be measured against.
- **podman-rootless-hardened** — The hardened flag set under rootless podman, for teams that cannot give the agent a docker socket at all.
