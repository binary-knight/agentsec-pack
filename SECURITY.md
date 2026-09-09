# Security policy

## Reporting a vulnerability in agentsec itself

Open a [private security advisory](../../security/advisories/new) on this
repository. Please do not open a public issue for a vulnerability.

Expect an acknowledgement within 3 working days and an assessment within 10.
This is a small project maintained in evenings; if a fix will take longer than
that, you will be told so rather than left waiting. Anyone who reports a valid
issue is credited in the release notes unless they ask not to be.

There is no bug bounty.

## What is in scope

The parts of this project that touch a trust boundary:

* **`agentsec/probe/blast_probe.py`** — runs *inside* the sandbox under test. It
  is stdlib-only and non-exfiltrating by construction: it reports the **names**
  of secret-looking environment variables and the **paths** of credential files,
  never their contents. Its network checks resolve and connect to a fixed list
  of hosts, send nothing, and close. Anything that makes it read, transmit or
  persist a secret value is in scope.
* **`agentsec/ui/server.py`** — the local console. Its threat model is written at
  the top of the module. Anything that lets a web page reach the API without the
  token, defeat the `Host` check, or cause a command outside the shipped presets
  to run is in scope.
* **`agentsec/redact.py`** — anything `--redact` fails to remove that identifies
  an operator or a machine.
* **`agentsec/runner.py`** — argument handling that lets a crafted image name,
  preset or flag reach a shell.

## What is not in scope

* **A high score is not a vulnerability in this tool.** It is a measurement of
  the sandbox you pointed it at.
* **The probe writes marker files.** One zero-byte marker per probed directory,
  created and removed immediately. That is how writability is measured, and it
  can trip file-integrity monitoring. It is documented, not a defect.
* Running the tool against infrastructure you do not have permission to test.
  That is on you.

## How this project reports issues in other people's software

`agentsec` measures sandboxes shipped by named vendors and publishes the
numbers. The rule this project holds itself to:

1. **Nothing that contradicts a vendor's own documentation is published before
   that vendor has been told and given time to respond.** A measurement that
   merely confirms documented behaviour may be published, and is labelled as
   documented behaviour rather than as a finding.
2. **A documented design boundary is recorded as such, never dressed up as a
   vulnerability.** Several profiles shipped here say exactly that.
3. **Every profile states how it was measured, in what environment, and by
   whom** — including where the measurer and the measured are the same product.
   A score with no record of its environment is not comparable to anything.

If you maintain a tool measured here and think a profile is wrong, open an
advisory or an issue. A correction ships faster than an argument.

## Running the probe safely

Read `agentsec/probe/blast_probe.py` before running it somewhere you care about.
It is one file and it is meant to be read. `docs/CAPTURING.md` explains how to
run it inside an agent you do not control, and `--redact` scrubs a report before
you share it.


## What is switched on

Enabled now:

* **Dependabot alerts** and **Dependabot security updates**, so a vulnerable
  dependency raises a pull request.
* **Dependabot version updates** for pip and for the GitHub Actions these
  workflows pin.
* **Secret scanning, dependency audit and a security lint in CI.** GitHub's own
  secret scanning and code scanning require a public repository or a purchased
  Advanced Security licence, and neither applies here yet, so the `security` job
  runs the free equivalents on every push: `detect-secrets` against an audited
  baseline, `pip-audit`, and `bandit` at high severity. The baseline holds three
  audited false positives and is quoted in the file; anything new fails the
  build.
* **A leak check as its own job**, which walks every tracked file and fails on an
  operator's home path. That has been needed twice.

To switch on at the moment this repository becomes public, none of which can be
enabled while it is private:

1. **Secret scanning and push protection** (Settings, Code security).
2. **Private vulnerability reporting**, which is what the advisory link at the
   top of this file depends on.
3. **CodeQL code scanning.** The workflow is already written and gated on
   visibility, so it starts by itself; confirm the first run succeeded.
