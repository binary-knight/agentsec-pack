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
- [ ] presets that reproduce named agents' own sandboxes (only after reading each one's source)
- [ ] verifier-integrity test class
- [ ] hosted history and CI gate

## License

MIT.
