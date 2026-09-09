# agentsec-pack (working name)

Adversarial tests for AI agent deployments, built to answer two questions a CI owner cannot see from a transcript:

1. **Sandbox blast radius** — what can the agent reach from inside the environment you run it in? Network, secrets, host filesystem, privileges, sibling processes.
2. **Verifier integrity** (planned) — did the agent do the task, or did it edit the tests, the fixtures or the grader?

This repository is at the first milestone: the blast-radius probe, a runner, a scorer and reports. `agentsec-pack` is a placeholder name.

## Quick start

```bash
uv venv .venv && uv pip install -e '.[dev]' && source .venv/bin/activate
# or, without installing: python -m agentsec.cli ...
# baseline: the same Python, no sandbox
agentsec blast-radius local --print-findings
# a container as most people run it
agentsec blast-radius docker python:3.12-slim --print-findings
# the same image, hardened
agentsec blast-radius docker python:3.12-slim --label hardened --print-findings -- \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 65534:65534 --pids-limit 256 --memory 512m --tmpfs /tmp
agentsec compare reports/*.json

# all ten shipped configurations at once, one comparison table
agentsec matrix python:3.12-slim
agentsec presets -v

# CI gate: exit 2 if the sandbox is looser than the budget
agentsec blast-radius preset docker-hardened --image myagent:latest --max-score 10
```

Each run writes `reports/<label>.json` (machine-readable, schema_version 1) and `reports/<label>.md`. The JSON records the exact image and flags, so anyone can reproduce the number. Review a report before publishing it: it carries the sandbox's hostname, working directory and the *names* of secret-looking environment variables. Pass `--redact` to scrub those while leaving every score, finding and flag intact; the examples in this repo were generated that way. `reports/` is git-ignored; `examples/` holds the two container reports from the README demo.

## What it found on the first run

Ten sandbox configurations, one image (`python:3.12-slim`), measured on one Linux host:

| Configuration | Score | Worst finding |
|---|---:|---|
| `bwrap-ro-root` | 86 | container runtime socket reachable |
| `bwrap-unshare-all` | 71 | container runtime socket reachable |
| `bwrap-workdir-net` | 69 | unrestricted internet egress |
| `docker-default` | 59 | unrestricted internet egress |
| `bwrap-unshare-all-clearenv` | 56 | container runtime socket reachable |
| `podman-rootless-default` | 47 | unrestricted internet egress |
| `docker-no-network` | 44 | runs as real root |
| `docker-readonly` | 44 | unrestricted internet egress |
| `docker-hardened` | **0** | none |
| `podman-rootless-hardened` | **0** | none |

The result worth arguing about is the top row. The lightweight "read-only host root" bubblewrap pattern scores **worse than a plain Docker container**, because a read-only root filesystem still hands the agent the host's container socket and every credential file in the home directory. Read-only is not containment. Scores for host-binding sandboxes depend on the host; container rows depend only on the image and flags.

Reproduce: `agentsec matrix python:3.12-slim`. Full table in `examples/matrix_slim.md`.

## Measuring an agent's own sandbox

A container you can wrap from outside. An agent's sandbox you cannot: it is entered by the agent. So you ask the agent to run the probe inside it and score what comes back (`docs/CAPTURING.md`, `agentsec score`).

Measured on Ubuntu 24.04 with bubblewrap 0.9.0 present, 8-9 September 2026:

| Sandbox | Score | Contained | Still reachable |
|---|---:|---|---|
| Codex CLI 0.153.4 `--sandbox read-only` | 26 | root filesystem read-only, working directory not writable, DNS fails, direct-IP connects refused, container sockets refused | the invoking user's home directory: `~/.ssh/config`, `~/.gitconfig`, `~/.config/gh/hosts.yml`, PID 1's environment |
| Codex CLI 0.153.4 `--sandbox workspace-write` | 34 | as above | as above, plus a writable working directory (expected, scored informational) and read-write bind mounts from the host |
| the same two, launched from a developer shell | 41 / 49 | as above | as above, plus one secret-shaped environment variable the shell had already exported |

**The launcher is part of the blast radius, so the environment is part of the measurement.** The sandbox inherits the shell it was started from. Launched from a shell with a token exported, both scores rise by 15 points for a secret that has nothing to do with Codex. The first two rows minimise the environment with `env -i` and are the intrinsic figures; the third row is the same sandbox started the way people actually start it. Shipping the pair is the point: a single number would have hidden which half you can fix by changing your own shell.

**This is a design boundary, not a vulnerability, and the report says so.** The vendor documents read-only mode as "the agent can inspect files", so an agent reading your `gh` credentials file is the boundary working as written. The number is useful anyway: it says that on the write and network axes this sandbox is genuinely strong, and that what remains inside the blast radius is *read* access to whatever secrets live in the home directory of the user who launched it. That distinction matters because no filesystem or network sandbox can constrain what an agent does with what it has already read: whatever the agent can read can appear in the text it produces. This tool does not measure that path, and makes no claim about any particular product's handling of it.

**Why the socket finding is only informational here.** Both Codex modes show `/var/run/docker.sock` in the filesystem and refuse every connection to it. Permission bits alone cannot tell you whether that refusal is a rule about those paths or a filter on the call itself, so the probe runs a control. It binds a unix socket it created itself and connects to it, and, where there is no writable directory, it connects to a path that does not exist: `PermissionError` instead of `FileNotFoundError` means the call was refused before the path was ever consulted. Under Codex both controls are refused, so the visible socket paths are inert and the report says that rather than guessing.


**Which layer is doing the work.** Codex's sandbox is two layers, and the live process argv shows both: `bwrap --as-pid-1 --new-session --die-with-parent --ro-bind / / --dev /dev --unshare-user --unshare-pid --unshare-ipc --unshare-net --proc /proc --cap-drop ALL`, and then its own helper re-execs the command with `--apply-seccomp-then-exec` under a permission profile. The `codex-cli-0.153.4-bwrap-layer` preset reproduces the first layer only, so running it measures what the second one contributes:

| Run | Score | Container socket | Seccomp |
|---|---:|---|---|
| Codex CLI 0.153.4 `--sandbox read-only` | 26 | visible, every connect refused | mode 2 |
| `codex-cli-0.153.4-bwrap-layer` preset | 48 | **reachable: the connect succeeds** | none |

`--unshare-net` removes the network but does nothing to unix-domain sockets, so under bubblewrap alone the probe connects to `/var/run/docker.sock` for real and the control confirms unix connect is permitted. The seccomp filter is what closes it. Two differences are expected rather than defects: the preset has no seccomp layer by construction, and `--as-pid-1` makes the probe itself PID 1, so the PID 1 environment finding cannot fire the way it does in the real sandbox. The preset is a way to see what bubblewrap alone buys. It is not a stand-in for Codex, and its rationale says so.

Full reports with provenance: `examples/agents/`. Entries in `agentsec/data/measured_profiles.json` may only be added from an actual measurement, never from documentation, and each cites the vendor's own docs. Before publishing anything that contradicts a vendor's documentation, tell the vendor first.

## Alongside a red-team run

Promptfoo measures what the agent does. This measures what the agent's sandbox would let a successful attack reach. Run both and join them:

```bash
# 1. measure the sandbox
agentsec blast-radius preset docker-default --image youragent:tag --out reports
# 2. run your promptfoo suite with the containment row (examples/promptfoo/promptfooconfig.yaml)
AGENTSEC_REPORT=reports/docker-default_youragent_tag.json   npx promptfoo@0.122.2 eval -c promptfooconfig.yaml -o out.json
# 3. join them
agentsec combine --promptfoo out.json --sandbox reports/docker-default_youragent_tag.json   --deployed-in docker-default
```

The assertion adds `blast_radius` to promptfoo's `namedScores` and never runs the probe itself; it reads a report you generated earlier, because promptfoo calls assertions once per test row. Attach it to one dedicated row rather than `defaultTest`, or a single loose sandbox fails your whole suite for one environmental cause.

`combine` reports the overlap: an OWASP agentic category where a test failed *and* the sandbox has a matching finding. The plugin-to-category table is promptfoo's own published mapping, cached in `agentsec/data/promptfoo_plugin_asi.json` with its URL and fetch date; plugin ids of the form `owasp:agentic:asi05` are parsed directly.

**`--deployed-in` is required and is your claim, not a derived fact.** Neither file knows whether the agent promptfoo tested runs in the sandbox that was measured. The report prints that assumption at the top and conditions every conclusion on it. Example output: `examples/promptfoo/combined_example.md`.

**Tested against:** a real `promptfoo eval` run (fixture captured 2026-09-08, and an end-to-end test that shells out to `npx promptfoo@0.122.2`). The plugin-id join is exercised against a hand-written fixture in promptfoo's schema, **not** against a live red-team run, because that needs a target and credentials this repo does not have. In red-team output, `success: false` means the attack landed.

## How it works

`agentsec/probe/blast_probe.py` is a single stdlib-only file. The runner bind-mounts it read-only into the target (or launches it through any command template that can run `python3`) and reads one JSON line back. `agentsec/scoring.py` turns the JSON into findings with fixed severities and a 0–100 score: 0 means the probe could reach nothing; higher means a larger blast radius. Findings map to the OWASP Top 10 for Agentic Applications (2026); the mapping lives in `agentsec/data/owasp_asi_2026.json` with its source.

## What the probe will not do

Read the probe before you run it somewhere you care about. It reports the names of secret-looking environment variables and the paths of credential files, never their contents. Its network checks resolve and connect to a fixed list of hosts, send nothing, and close. Its only writes are zero-byte marker files, one per probed system directory, each created and removed at once; that is how writability is measured, and it can trip file-integrity monitoring where you have it. Tests in `tests/test_probe.py` assert the redaction and the fixed target list.

## Status

- [x] blast-radius probe, runner (docker / podman / local / command template), scorer, JSON + Markdown reports
- [x] ten launcher presets, `matrix` comparison table, `--max-score` CI gate, recommended-flag output, image digests
- [x] promptfoo integration: containment assertion, `combine` report, OWASP category overlap
- [x] measured profiles of named agents' sandboxes, captured by running the probe inside them
- [ ] more agents; a launcher preset per agent where the sandbox can be reproduced standalone
- [ ] verifier-integrity test class
- [ ] hosted history and CI gate

## License

MIT.
