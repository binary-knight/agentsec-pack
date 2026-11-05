# Changelog

What changed in each release of `agentsec-pack`, newest first. Probe versions
are listed separately because a report records the probe version that took it,
and two reports are only comparable when it matches or the difference is known.

## Unreleased

- `agentsec submit` prepares one measurement for a public dataset: it prints the exact record, asks at the terminal, and opens a pre-filled issue that the person posts. The record holds the agent, version, sandbox mode and settings, OS family, probe version, axis states, finding ids and score, and refuses words that look like a path, a variable name, or this machine's names. There is no default dataset, so `--to` is required.

## 0.3.0 — 2026-11-05

Probe **0.6.0**, which adds macOS. On Linux, the stricter proxy rule below changes no published score.

**Checking an agent's work**
- `agentsec verify` compares two commits and asks whether the change passed its tests or changed them. It reports changes to tests, fixtures, test configuration and CI, and tests that were removed, skipped or lost assertions, then runs the new code with the old tests put back. Exits 2 unless the verdict is `verified`, and `--strict` also fails a passing change that edited its tests. It reads the repository from git objects so hooks, filters and `export-ignore` cannot affect it, and it clears symlinks before restoring a path. (#30)
- `verify --junit PATH` compares the runs test by test. It separates a failure that predates the change (new verdict `already-failing`), a suite that never started (`unverified`), a regression (`failing`), and tests that pass only with the change's own edits. A run that writes no results is `unverified`, and a results file committed to the repository is cleared before each run. Each run gets its own home directory. (#33)
- `verify` recognizes a test that moved or was renamed, and still reports one that lost assertions or gained a skip on the way. A parameterized case whose id changes between runs, for example through `uuid4()`, is no longer reported as a test that stopped running. (#31, #34)
- `verify` is early. It has been run on 16 public agent pull requests and has not yet reached `verified` on real agent output, because all 16 were chosen for editing their tests. A change can still special-case the tests in its own code or write its own results file. Results are in `docs/MEASUREMENTS.md`. (#34)
- `scripts/survey_agent_prs.py` runs the static checks over public agent pull requests, and `regrade.yml` re-grades them on disposable machines. (#31, #32)

**Measuring**
- Probe 0.6.0 runs on macOS. It reads Seatbelt confinement through `sandbox_check()`, process visibility through `sysctl`, and a read-only root through `statvfs`, and it skips the Linux-only checks. PRIV-006 reports a process under no Seatbelt profile. `~/Library/LaunchAgents` and `/opt/homebrew/bin` are checked. CI runs the suite on `macos-latest`. (#23)
- Three `seatbelt-*` presets run the probe under macOS `sandbox-exec`: a profile that allows everything, one that denies the network, and a confined profile. (#24)
- A proxy that gave no clear answer no longer counts as containment. NET-003 now needs a refusal from every destination asked about. A timeout, a failed connection, a gateway error or a proxy without `CONNECT` support reports NET-004, not measured, and lists those destinations. (#28)

**Measured profiles**
- macOS from a GitHub-hosted machine: no sandbox 76, the Seatbelt presets 68, 53 and 8, and Codex CLI 0.164.0's own sandbox through `codex sandbox`, 15 in read-only and 30 in `workspace-write`. On macOS, Codex hides other processes and leaves Claude Code's project config writable inside its workspace. (#24)
- Claude Code 2.1.318 on macOS in full headless sessions: no sandbox 100, sandbox on 53, sandbox with `denyRead` 38. Claude Code protects its own project config and leaves Codex's and Antigravity's writable, the mirror of the Codex result. Sandboxed commands can see `ANTHROPIC_API_KEY` by name. (#25, #26, #27)
- Public Terminal-Bench tasks through real Harbor with a no-model agent. Four tasks drawn by a repeatable rule score 67, and `/tests` and `/solution` are absent from the agent's container. A fifth needs a GPU and was not measured. `docs/MEASUREMENTS.md` explains why 67 is not comparable with plain Docker's 59. (#29)

**Fixed**
- `agentsec.__version__` said `0.0.1` in every release so far. It now matches the package version.

## 0.2.0 — 2026-11-04

Probe **0.5.0**. Reports from probe 0.4.0 still score the same, and the new paths only add findings where those files exist.

**Measuring**
- `agentsec probe` measures and scores the sandbox the command runs in, in one step. `--proxy-auth` is the explicit opt-in for sending a configured proxy its own password. (#13)
- Probe 0.5.0 checks Google's Antigravity CLI: its login token, its settings, and its hooks and MCP files at user and workspace level. (#19)

**Gating and reporting**
- A GitHub Action for the gate, in `action.yml`, which installs agentsec from its own checkout and fails the job with the CLI's exit code. (#15)
- The regression gate no longer fails a sandbox that was tightened. A new informational finding is noted unless it records an axis that could not be measured. (#15)
- `agentsec chart` draws many runs as one color-coded SVG chart, or as a Markdown table when the output name ends in `.md`. (#19)

**Measured profiles**
- Every published number re-measured with probe 0.4.0, with Codex CLI 0.164.0 and Claude Code 2.1.318 with `denyRead` added. The bubblewrap rows of the `python:3.12-slim` matrix fell by 15 when launched with a minimal environment, and the README says why. (#14)
- Antigravity CLI 1.4.12: on stock Ubuntu its terminal sandbox cannot start, `--sandbox` has no effect, and an approved command runs unsandboxed with nothing printed in print mode. Score 100. (#19)

**Documentation**
- The README opens with two generated charts and a table of every measurement, and the long write-ups moved to `docs/MEASUREMENTS.md`. (#19)
- README copy rewritten, with three factual errors corrected: a broken `agentsec report` example, a budget example whose numbers did not add up, and a wrong figure in the Claude Code 2.1.266 profile. (#18, #21)
- `docs/ROADMAP.md`, with an opt-in community benchmark added as item 8. (#12, #20)

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
