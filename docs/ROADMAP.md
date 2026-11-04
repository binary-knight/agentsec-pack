# Roadmap

Ordered by priority. Each item says why it is where it is, what "done" means,
and whether it needs the maintainer: an account, a machine, or a decision
that is not the implementer's to make.

The rule that governs every measurement item still applies: a number goes in
only from a run that was actually made, and says how it was made.

Last revised 2026-11-04, after 0.1.0.

## Now: toward 0.2.0

### 1. One command to measure where you are: `agentsec probe`

**Why first:** every measurement below, and every user following `AGENTS.md`,
currently copies the probe to a temp path, runs it, and scores the output in
three steps. One command makes each measurement in item 2 a single line, and
lowers the cost of the most important use case: measuring a sandbox from
inside it.

**Done when:** `agentsec probe --label ... --how ...` runs the bundled probe
in the current process environment, scores it, writes the report, and
supports `--redact`, `--max-score`, `--baseline` and the proxy-auth opt-in as
an explicit flag. `AGENTS.md` Task A and `docs/CAPTURING.md` use it. The
three-step form stays documented for read-only sandboxes, where the output has
to come back through a transcript.

### 2. Bring every published number up to probe 0.4.0

**Why second:** the README publishes numbers taken by probe 0.1.0, which
could not see proxy egress, agents' own credentials, or persistence. A
measurement tool whose own tables are stale undermines the one thing it sells.

**Done when**, each from a real run:
- **Codex CLI** (installed: 0.164.0) in `read-only` and `workspace-write`. The
  open question is whether `workspace-write` lets the agent write
  `.git/hooks` or its own `.codex/config.toml`, which would be a way out of
  the sandbox that waits for the user. *Needs the maintainer's go-ahead to run
  Codex on their account.*
- **Claude Code with `sandbox.filesystem.denyRead`** set as the vendor
  documents, to show what the documented remedy for readable credentials
  buys. Uses `--settings`, so no settings file is changed. *Needs the go-ahead
  to run a headless Claude Code session on the maintainer's account.*
- **The `python:3.12-slim` matrix** (`agentsec matrix python:3.12-slim`),
  re-run so the README table and the 59 / 15 / 0 figures in `AGENTS.md` are
  current. *Needs Docker, which is on the maintainer's host but not reachable
  from an agent sandbox.*
- **Gemini CLI:** the probe already checks its credential and settings paths,
  but it is not installed here. *Needs the maintainer to install it and
  approve its use.*

Any result that contradicts a vendor's documentation is raised with the
vendor before or at the time it is published (SECURITY.md).

### 3. A GitHub Action for the gate

**Why third:** `--max-score` and `--baseline` are the CI story, and a CI story
that needs a page of YAML gets skipped. An action makes it a few lines.

**Done when:** `uses: binary-knight/agentsec-pack@v0` runs a preset or image
against a budget and/or a committed baseline, uploads the JSON, Markdown and
HTML reports as artifacts, and fails the job with exit code 2. It is
documented in the README with one complete workflow example and tested in
this repository's own CI.

### 4. Release hygiene

**Why here:** cheap, and it is what people look for first.

**Done when:** `CHANGELOG.md` exists and is kept per release, v0.1.0 has a
GitHub Release with notes, and the release workflow points to the changelog.

### 5. Say only what exists

**Why:** the README pitches two test classes and one is built. Until
verifier integrity exists, the pitch is blast radius.

**Done when:** the README opens with what the tool does today, and verifier
integrity sits under "Later" on this page rather than in the first lines of
the README.

## Next: 0.3.0

### 6. macOS

**Why it matters most after 0.2.0:** most developers run these agents on
macOS, where Claude Code and Codex sandbox with Seatbelt rather than
bubblewrap. The probe reads `/proc` and assumes Linux, so on a Mac today it
would report a missing seccomp filter and empty resource limits that mean
nothing.

**Done when:** every probe section either works on macOS or reports
`not applicable on darwin` rather than a finding; the network, credential,
socket and persistence checks, which are portable, run there; Seatbelt
confinement is detected; and Claude Code and Codex are measured on a Mac.
*Needs a Mac.*

### 7. Hosted agent sandboxes

Presets or capture recipes for the sandboxes agents are increasingly deployed
into: devcontainers, E2B, Modal, Daytona, Docker's own sandboxes. Each preset
must say what it does not reproduce, and each recipe must come from a live
run.

## Later

### 8. History across runs

Score and findings per image or agent over time, so drift is visible before
it crosses a gate. The `--baseline` gate covers the CI case; this is the
trend view.

### 9. Verifier integrity

The second test class from `docs/DESIGN.md`: did the agent pass CI by editing
the tests, the fixtures or the grader? Run a verifier the agent never saw on
the agent's diff, and diff the tests themselves. Kept on the roadmap,
deliberately out of the pitch until it exists.

## Done

- Blast-radius probe, runner, scorer, JSON, Markdown and HTML reports, local
  console.
- Launcher presets for docker, podman and bubblewrap; `matrix`; `--max-score`.
- Promptfoo integration.
- Measured profiles of Claude Code, Codex CLI and Aider.
- Probe 0.2.0 to 0.4.0: proxy egress measured with a control host and opt-in
  credentials; agents' own credentials; SSH agent and rootless sockets;
  persistence; readability proven by opening.
- `--baseline` and `agentsec diff` regression gate.
- PyPI release workflow; agentsec-pack 0.1.0 published 2026-11-04.
