# Antigravity sandbox boundary checks

These records come from `scripts/check_sandbox_boundaries.py`, which tests what a
report's mount table and a proxy's status line only suggest. Run inside the
sandbox it tries a write in each directory and sends real requests through any
configured proxy; run again on the host with `--host-check` it reports which of
those writes are visible outside the sandbox and runs the one file it left in
`~/.cargo/bin`, then removes them all. Unlike the probe, it leaves files behind
and makes requests that complete, so it is for a disposable machine only.

Each configuration has two files: `<label>.json` (from inside the sandbox) and
`<label>.host.json` (from the host afterward). Captured on `agy` 1.5.2,
`ubuntu-22.04`, 2026-11-07, through `.github/workflows/stubbed-agent-measure.yml`.
The `skip-permissions` run has only the host file: its inside check did not
return because the agent went idle waiting on a background task.
