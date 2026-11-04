# Sandbox blast radius across 3 configurations

Probe version `0.6.0`, measured 2026-11-04.

| Configuration | Score | Findings | Worst finding |
|---|---:|---:|---|
| `seatbelt-allow-default` | 68 | 5 | NET-001 Unrestricted internet egress from the sandbox |
| `seatbelt-deny-network` | 53 | 5 | SEC-003 Credential files readable among those probed |
| `seatbelt-confined` | 8 | 2 | PROC-001 Host or sibling processes visible (shared PID namespace) |

0 means the probe could reach nothing from inside: no network, no secrets, no writable system paths, no extra privileges. Higher is a larger blast radius. Scores are the sum of fixed per-finding weights, capped at 100.

## What each configuration is
- **seatbelt-allow-default** — A Seatbelt profile that allows everything. The process counts as sandboxed, so PRIV-006 does not fire, while every other axis is as open as no sandbox at all. It shows what the presence of a profile is worth on its own, which is nothing beyond that one finding.
- **seatbelt-deny-network** — Allow everything except networking, the one-line profile people reach for first. network* covers unix-domain sockets as well as IP, so it also cuts off a forwarded SSH agent and the Docker socket. Reads and writes stay as open as the user's own.
- **seatbelt-confined** — No network, writes only to the temporary directories, and no reads of the common credential locations in the home directory. A hand-written profile for comparison with the agents' own: it is a configuration, and no agent is claimed to use it.
