# Changelog

What changed in each release of `agentsec-pack`, newest first. Probe versions
are listed separately because a report records the probe version that took it,
and two reports are only comparable when it matches or the difference is known.

## Unreleased

- Probe **0.5.0**: Google's Antigravity CLI paths, its login token and its own settings, hooks and MCP files, user and workspace level.
- Antigravity CLI 1.4.12 measured: on stock Ubuntu its terminal sandbox cannot start, `--sandbox` has no effect, and an approved command runs unsandboxed with nothing printed in print mode. Score 100.
- `agentsec chart`: many runs as one color-coded SVG chart or Markdown table. The README now opens its results with two generated charts and a table, and the long write-ups moved to `docs/MEASUREMENTS.md`.
- The README rewritten in the maintainer's voice, with three factual errors corrected. (#18)
- `agentsec probe`: measure and score the sandbox the command runs in, in one
  step. (#13)
- Every published number re-measured with probe 0.4.0. The bubblewrap rows of
  the `python:3.12-slim` matrix fell by 15 when launched with a minimal
  environment, and the README now says why. Codex CLI 0.164.0 and Claude Code
  2.1.318 with `denyRead` were measured. (#14)
- A GitHub Action for the gate (`action.yml`). The regression gate no longer
  fails a sandbox that was tightened. (#15)
- `docs/ROADMAP.md`. (#12)

## 0.1.0 — 2026-11-04

First release on PyPI. Probe **0.4.0**.

**Measuring**
- A stdlib-only probe that runs inside the sandbox under test and reports what
  it can reach across five axes: network, secrets, filesystem, privilege and
  processes. It reports names and paths, never values. Readability is proven by
  opening a file and reading zero bytes. Writability is proven with zero-byte
  markers removed at once.
- Network egress is measured directly and, when an egress proxy is configured,
  through the proxy: one CONNECT request per fixed target plus a control host,
  with the proxy's password sent only on opt-in (`AGENTSEC_PROBE_PROXY_AUTH=1`).
  (#4, #9)
- Agents' own login credentials, a forwarded SSH agent, rootless and desktop
  container sockets, and writes that would persist outside the sandbox (shell
  startup files, git hooks, the agent's own settings) are checked. Writes on
  storage that dies with the sandbox are informational. (#5)
- Launchers: docker, podman, bubblewrap, any command template, and ten
  presets; `matrix`; `score` for probe output captured inside an agent's own
  sandbox; `assert` for pass or fail on specific paths.

**Gating and reporting**
- `--max-score` budget gate; `--baseline` and `agentsec diff`, which fail on
  anything worse than an accepted report. (#6)
- JSON, Markdown and self-contained HTML reports; a localhost console;
  `--redact` for publishing.
- Promptfoo integration: a containment assertion and a `combine` report.

**Measured profiles**
- Claude Code 2.1.266 and 2.1.317, Codex CLI 0.153.4, Aider 0.86.2, each with
  version, date, host, capture method, environment and the vendor's own
  documentation.

**Fixed before release**
- The HTML template was missing from the wheel, so `agentsec report` and
  `agentsec ui` failed on any install from PyPI. (#7)
- A refused direct connection was reported as containment when traffic went
  through a proxy the probe did not test. (#4)
