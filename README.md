# agentsec-pack (working name)

Adversarial tests for AI agent deployments, built to answer two questions a CI owner cannot see from a transcript:

1. **Sandbox blast radius** — what can the agent reach from inside the environment you run it in? Network, secrets, host filesystem, privileges, sibling processes.
2. **Verifier integrity** (planned) — did the agent do the task, or did it edit the tests, the fixtures or the grader?

This repository is at the first milestone: the blast-radius probe, a runner, a scorer and reports. `agentsec-pack` is a placeholder name.

## Quick start

```bash
pip install -e .   # or run as: python -m agentsec.cli ...
# baseline: the same Python, no sandbox
agentsec blast-radius local --print-findings
# a container as most people run it
agentsec blast-radius docker python:3.12-slim --print-findings
# the same image, hardened
agentsec blast-radius docker python:3.12-slim --label hardened --print-findings -- \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 65534:65534 --pids-limit 256 --memory 512m --tmpfs /tmp
agentsec compare reports/*.json
```

Each run writes `reports/<label>.json` (machine-readable, schema_version 1) and `reports/<label>.md`. The JSON records the exact image and flags, so anyone can reproduce the number.

## How it works

`agentsec/probe/blast_probe.py` is a single stdlib-only file. The runner bind-mounts it read-only into the target (or launches it through any command template that can run `python3`) and reads one JSON line back. `agentsec/scoring.py` turns the JSON into findings with fixed severities and a 0–100 score: 0 means the probe could reach nothing; higher means a larger blast radius. Findings map to the OWASP Top 10 for Agentic Applications (2026); the mapping lives in `agentsec/data/owasp_asi_2026.json` with its source.

## What the probe will not do

Read the probe before you run it somewhere you care about. It reports the names of secret-looking environment variables and the paths of credential files, never their contents. Its network checks resolve and connect to a fixed list of hosts, send nothing, and close. Its only write is a zero-byte temp marker it removes. Tests in `tests/test_probe.py` assert the redaction and the fixed target list.

## Status

- [x] blast-radius probe, runner (docker / local / command template), scorer, JSON + Markdown reports
- [ ] launcher presets for common agent sandboxes
- [ ] Promptfoo plugin / reporter
- [ ] verifier-integrity test class
- [ ] hosted history and CI gate

## License

MIT.
