# Roadmap

Ordered by priority. Each item says why it is where it is, what "done" means,
and whether it needs the maintainer: an account, a machine, or a decision
that is not the implementer's to make.

The rule that governs every measurement item still applies: a number goes in
only from a run that was actually made, and says how it was made.

Last revised 2026-11-05, after 0.3.0.

## Next

### 1. Verifier integrity, past what it has been shown to do

**Why first:** `agentsec verify` is the newest part of the tool and the least
proven. It works on the scenarios in its tests, and the one trial on real work
produced no `verified` verdict. Three things are left.

**`verified` on real agent output.** All 16 pull requests in
`docs/MEASUREMENTS.md` were chosen for editing their tests, and 6 produced no
result. Done when a sample that was not chosen that way has been re-graded and
read by hand, with the verdicts reported whichever way they fall.

**A forged result.** With `--junit`, a change that exits 0 when the tests
import it is caught, because the run writes no results. A change can still
write a results file of its own. Done when a run can show that the tests
executed, for example with a test that must fail planted in the suite, so a
results file that reports success anyway is caught.
`test_known_limit_code_that_writes_its_own_results_still_passes` pins the gap
until then.

**Other kinds of grader.** Done when a benchmark's verifier, which is not a
plain test command in the repository, can be checked the same way. Public
harnesses and tasks only, with their commits recorded.

### 2. Measurements still missing

**Why:** each of these is a gap in the published results, and each waits on
something outside this repository.

**Done when**, each from a real run:
- **Gemini CLI:** the probe already checks its credential and settings paths,
  but it is not installed here. *Needs the maintainer to install it and
  approve its use.*
- **Antigravity CLI's sandbox:** it cannot start on stock Ubuntu, so only the
  unsandboxed result is published. *Needs a host that allows unprivileged user
  namespaces.*
- **A developer's Mac:** every macOS number comes from a GitHub-hosted machine.
  *Needs a Mac.*

Any result that contradicts a vendor's documentation is raised with the
vendor before or at the time it is published (SECURITY.md).

### 3. Hosted agent sandboxes

Presets or capture recipes for the sandboxes agents are increasingly deployed
into: devcontainers, E2B, Modal, Daytona, Docker's own sandboxes. Each preset
must say what it does not reproduce, and each recipe must come from a live
run.

### 4. A community benchmark from opt-in submissions

**Why:** every number in this repository comes from one machine. Results that
other people capture on their own hosts would show how agents and sandbox
settings behave in practice, and the chart code in `agentsec chart` can already
draw a leaderboard from them.

**What it ranks:** agents, sandbox modes and settings, and hosts. Blast radius
is a property of the sandbox, and every measured profile records that the model
choice does not change it. Ranking models needs a behavioral test, such as how
often a model is prompt-injected or tries to leave its sandbox, which belongs
with the promptfoo integration and item 1.

**Done when:**
- `agentsec submit <report>` sends a result only when a person runs it. Nothing
  is sent automatically, and the probe's rule that it never transmits what it
  finds stays true.
- The command prints the exact record before sending and asks for confirmation.
  The record holds the agent and version, the sandbox mode and settings, the OS
  family, the probe version, the axis states, the finding ids and the score. It
  never holds a hostname, a path, a variable name or a mount point, because
  those carry usernames and project names.
- The first version needs no server. The command opens a pre-filled issue in a
  public dataset repository, where every submission is visible and can be
  moderated. A hosted endpoint waits until volume calls for one, along with the
  privacy policy, abuse protection and hosting cost it brings.
- Published figures are aggregates, and a configuration appears only after
  enough independent submissions that no single one can be picked out of it.
- Results reproduced by the maintainer or a known harness are shown apart from
  community submissions, and every figure states how many runs it rests on, so
  that one person cannot move a vendor's ranking with invented reports.

*Needs the maintainer to decide on the dataset repository and its license, and
on the threshold for publishing a configuration.*

## Later

### 5. History across runs

Score and findings per image or agent over time, so drift is visible before
it crosses a gate. The `--baseline` gate covers the CI case; this is the
trend view.

## Done

**0.3.0, published 2026-11-05**
- `agentsec verify`: tampering, weakening and re-grading between two commits,
  with moved and renamed tests recognized and a test-by-test comparison through
  `--junit`.
- A survey of 99 public agent pull requests and a re-grade of the 16 that edited
  their tests.
- Probe 0.6.0 runs on macOS, with Seatbelt presets. The presets, Codex CLI and
  Claude Code are measured on a GitHub-hosted machine.
- Public Terminal-Bench tasks measured through real Harbor.
- A proxy that gives no clear answer no longer counts as containment.

**0.2.0, published 2026-11-04**
- `agentsec probe`: measure and score the sandbox the command runs in, in one
  step.
- A GitHub Action for the gate.
- Every published number brought up to probe 0.4.0, with Codex CLI and Claude
  Code with `denyRead` added.
- Probe 0.5.0 and a measurement of Antigravity CLI.
- `agentsec chart`, `CHANGELOG.md` and release notes built from it.
- A README that opens with what the tool does today.

**0.1.0, published 2026-11-04**
- Blast-radius probe, runner, scorer, JSON, Markdown and HTML reports, local
  console.
- Launcher presets for docker, podman and bubblewrap; `matrix`; `--max-score`.
- Promptfoo integration.
- Measured profiles of Claude Code, Codex CLI and Aider.
- Probe 0.2.0 to 0.4.0: proxy egress measured with a control host and opt-in
  credentials; agents' own credentials; SSH agent and rootless sockets;
  persistence; readability proven by opening.
- `--baseline` and `agentsec diff` regression gate.
- PyPI release workflow.
