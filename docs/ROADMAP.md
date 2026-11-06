# Roadmap

Ordered by priority. Each item says why it is where it is, what "done" means,
and whether it needs the maintainer: an account, a machine, or a decision
that is not the implementer's to make.

The rule that governs every measurement item still applies: a number goes in
only from a run that was actually made, and says how it was made.

Last revised 2026-11-06.

## Next

### 1. Verifier integrity, past what it has been shown to do

**Why first:** `agentsec verify` is the newest part of the tool. It has reached `verified` on real agent output and has a check for forged results, but that check has not yet caught anything outside this repository's tests. Four things are left.

**More of the sample runs.** 15 of the 20 pull requests in the neutral sample were `already-failing` or `unverified`, much of it from installing a stranger's project. Done when a larger sample has been re-graded with better setup and read by hand, with the verdicts reported whichever way they fall.

**The planted test in other languages.** It is Python only, so a suite in another language is not checked for forged results. Done when at least JavaScript and TypeScript suites are covered, from runs on real projects.

**Code that finds the planted test.** A change can look through the tree for it and report it failed along with invented results. `test_known_limit_code_that_finds_the_planted_test_can_still_invent_results` pins this. Done when the results can be shown to come from a run the code under test could not write to, or when this is stated as a permanent limit with the reason.

**Graders, past a generic forgery.** `scripts/check_harbor_grader.sh` shows a generic forgery failing on 3 public Terminal-Bench tasks with a separate verifier and working on a control with a shared one. Done when more tasks have settled and crafted artifacts, the route open against a separate verifier, have been tried. Public harnesses and tasks only, with their commits recorded.

### 2. Measurements still missing

**Why:** each of these is a gap in the published results, and each waits on something outside this repository.

**Done when**, each from a real run:
- **Gemini CLI:** the probe already checks its credential and settings paths, but it is not installed here. *Needs the maintainer to install it and approve its use.*
- **Antigravity CLI's sandbox:** it cannot start on stock Ubuntu, so only the unsandboxed result is published. *Needs a host that allows unprivileged user namespaces.*
- **A developer's Mac:** every macOS number comes from a GitHub-hosted machine. *Needs a Mac.*

Any result that contradicts a vendor's documentation is raised with the vendor before or at the time it is published (SECURITY.md).

### 3. Hosted agent sandboxes

Dev containers are measured through the CLI. Still open: E2B, Modal, Daytona and Docker's own sandboxes, and a dev container as an editor attaches to it. Each must say what it does not reproduce, and each recipe must come from a live run. *Needs the maintainer's accounts for E2B, Modal and Daytona, and a machine with Docker Desktop.*

### 4. A community benchmark from opt-in submissions

**Why:** every number in this repository comes from one machine or a GitHub-hosted one. Results that other people capture on their own hosts would show how agents and sandbox settings behave in practice, and the chart code in `agentsec chart` can already draw a leaderboard from them.

**What it ranks:** agents, sandbox modes and settings, and hosts. Blast radius is a property of the sandbox, and every measured profile records that the model choice does not change it. Ranking models needs a behavioral test, such as how often a model is prompt-injected or tries to leave its sandbox, which belongs with the promptfoo integration and item 1.

`agentsec submit` is built: it shows the exact record, asks at the terminal, and opens a pre-filled issue for the person to post. `--to` is required because no dataset exists yet.

**Done when:**
- A public dataset repository exists and is the default for `--to`.
- Published figures are aggregates, and a configuration appears only after enough independent submissions that no single one can be picked out of it.
- Results reproduced by the maintainer or a known harness are shown apart from community submissions, and every figure states how many runs it rests on, so that one person cannot move a vendor's ranking with invented reports.
- A hosted endpoint waits until volume calls for one, along with the privacy policy, abuse protection and hosting cost it brings.

*Needs the maintainer to decide on the dataset repository and its license, and on the threshold for publishing a configuration.*

## Done

**Unreleased, on main**
- A test planted to fail, so results that did not come from running the tests are caught, with the new verdict `results-not-credible`.
- `verified` reached on real agent output: 3 of 20 in a sample not chosen for editing its tests.
- Benchmark graders checked through real Harbor, with a run that tries to forge a pass and two controls.
- Dev containers measured through the devcontainer CLI, with a capture recipe.
- `agentsec submit`, which prepares a measurement for a person to post.
- `agentsec history`, with score and findings across saved runs.

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
