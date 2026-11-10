# Roadmap

Ordered by priority. Each item says why it is where it is, what "done" means,
and whether it needs the maintainer: an account, a machine, or a decision
that is not the implementer's to make.

The rule that governs every measurement item still applies: a number goes in
only from a run that was actually made, and says how it was made.

Last revised 2026-11-10.

## Next

### 1. Verifier integrity, past what it has been shown to do

**Why first:** `agentsec verify` is the newest part of the tool. It has reached `verified` on real agent output and has a check for forged results, but that check has not yet caught anything outside this repository's tests. Four things are left.

**A larger sample.** 15 of the 20 pull requests in the neutral sample were `already-failing` or `unverified`, much of it from installing a stranger's project. Done when a larger sample has been re-graded with better setup and read by hand, with the verdicts reported whichever way they fall.

**The planted test in other languages.** It is Python only, so a suite in another language is not checked for forged results. Done when at least JavaScript and TypeScript suites are covered, from runs on real projects.

**Code that finds the planted test.** A change can look through the tree for it and report it failed along with invented results. `test_known_limit_code_that_finds_the_planted_test_can_still_invent_results` pins this. Done when the results can be shown to come from a run the code under test could not write to, or when this is stated as a permanent limit with the reason.

**Graders, past a generic forgery.** `scripts/check_harbor_grader.sh` shows a generic forgery failing on 3 public Terminal-Bench tasks with a separate verifier and working on a control with a shared one. Done when more tasks have settled and crafted artifacts, the route open against a separate verifier, have been tried. Public harnesses and tasks only, with their commits recorded.

### 2. Measurements still missing

**A developer's Mac:** every macOS number comes from a GitHub-hosted machine, whose home holds no personal credentials. That is also why Gemini CLI's three Seatbelt profiles could not be told apart. *Needs a Mac.*

Any result that contradicts a vendor's documentation is raised with the vendor before or at the time it is published (SECURITY.md).

### 3. Hosted agent sandboxes

Still open: E2B, Daytona and Docker's own sandboxes. Each must say what it does not reproduce, and each recipe must come from a live run. *Needs the maintainer's accounts for E2B and Daytona, and a machine with Docker Desktop.*

**What an editor forwards.** A dev container with VS Code attached adds git credential and IPC sockets that the probe does not test. Done when the probe says whether a command can get a credential through them, from a run with a throwaway credential.

### 4. A community benchmark from opt-in submissions

**Why:** every number in this repository comes from one machine or a GitHub-hosted one. Results that other people capture on their own hosts would show how agents and sandbox settings behave in practice, and the chart code in `agentsec chart` can already draw a leaderboard from them.

**What it ranks:** agents, sandbox modes and settings, and hosts. Blast radius is a property of the sandbox, and every measured profile records that the model choice does not change it. Ranking models needs a behavioral test, such as how often a model is prompt-injected or tries to leave its sandbox, which belongs with the promptfoo integration and item 1.

`agentsec submit` opens a pre-filled issue in `binary-knight/agentsec-benchmark` by default, and `agentsec benchmark` turns those issues into figures. Records are released under CC0 1.0, so anyone can reuse them.

The rules `agentsec benchmark` enforces:
- A configuration appears once 5 different GitHub accounts have submitted it. The threshold cannot be set below 3.
- Each account counts once per configuration, using its newest record, so posting repeatedly does not move a figure.
- A figure is a median, the most common state of each axis, and how many accounts it rests on. Reproduced results are shown apart and say where they came from.

**Done when:**
- A public figures page is built from the issues on a schedule.
- Enough people have submitted that a configuration crosses the threshold.
- A hosted endpoint waits until volume calls for one, along with the privacy policy, abuse protection and hosting cost it brings.

**Known limit.** Submissions are not checked against a re-run, and one person with five accounts can still cross the threshold. A community figure reports what accounts posted, which is why reproduced results are shown apart.

## Done

**Unreleased, on main**
- Scoring under a user-space kernel: findings that describe what gVisor's kernel grants are reported at info, so Modal's scores count what the sandbox exposes beyond gVisor.
- A written compatibility policy, with a test for each promise, and JSON Schemas for reports.

**0.4.0, 2026-11-07**
- Probe 0.7.0, which no longer reports an allowlist that filters at TLS as open internet, and flags gVisor.
- Antigravity CLI's sandbox and Gemini CLI measured, with a local stand-in for the model.
- A dev container measured with VS Code attached, and Modal Sandboxes measured.
- A test planted to fail, so results that did not come from running the tests are caught, with the new verdict `results-not-credible`.
- `verified` reached on real agent output: 3 of 20 in a sample not chosen for editing its tests.
- Benchmark graders checked through real Harbor, with a run that tries to forge a pass and two controls.
- Dev containers measured through the devcontainer CLI, with a capture recipe.
- `agentsec submit`, which prepares a measurement for a person to post.
- `agentsec history`, with score and findings across saved runs.
- `agentsec benchmark`, which publishes a median past a threshold of different accounts.

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
