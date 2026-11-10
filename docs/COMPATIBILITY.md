# Compatibility

A build that gates on `agentsec` should not start failing because `agentsec` was upgraded, unless the upgrade says so. This page states what stays the same from one version to the next and how the rest can change. Each promise here has a test in `tests/test_compatibility.py` that fails if the promise breaks.

From 1.0 on, the promises below hold for every 1.x release, and anything that breaks one waits for 2.0. Releases before 1.0 follow them as far as they can, and the changelog names any exception.

## What is covered

**Commands and flags.** `presets`, `probe`, `blast-radius`, `matrix`, `score`, `assert`, `diff`, `history`, `report`, `chart`, `ui`, `combine` and `compare` keep their names and flags. A new flag is optional, and leaving it out keeps the earlier behavior.

**Exit codes.**

| Code | Meaning |
|---:|---|
| 0 | The command ran, and any gate it was given passed. |
| 2 | A gate failed: `--max-score`, `--baseline`, `agentsec diff`, or an `agentsec assert` expectation. |
| 1 | The command could not run, for example because the sandbox did not start or an input was missing. |

**Report files.** Two JSON formats are fixed by schemas that ship with the package:

- `agentsec/data/blast-radius-report.schema.json`, for what `probe`, `blast-radius`, `score` and `ui` write
- `agentsec/data/path-assertions.schema.json`, for what `assert --out` writes

Both carry `schema_version` 1. A field can be added without changing it, so a reader should ignore fields it does not know. Removing, renaming or changing the type of a field raises `schema_version`, and only in a new major version. The `probe` block inside a report belongs to the probe. Its contents are versioned by `probe_version`, and only `probe_version` itself is covered here.

**Scoring.** Each finding has a severity with a fixed weight: critical 25, high 15, medium 8, low 3, info 0. The score is the sum of the weights, capped at 100, and `raw_score` is the uncapped sum. A finding ID is never reused or given a different meaning. Most findings have one severity. Two take theirs from the evidence by a fixed rule:

- FS-001 is high when `/`, `/etc`, `/usr/bin` or `/usr/local/bin` is writable, and medium for other system paths.
- PRIV-003 takes the severity of the most dangerous Linux capability in the effective set.

Changing a weight, the severity of an existing finding, or either of those rules needs a new major version.

**The GitHub Action.** The inputs and outputs in `action.yml` keep their names and meaning. A new input is optional, and its default keeps the earlier behavior.

## How a score can still change

A score on an unchanged sandbox can change between minor versions in two ways, and each report records which versions produced it.

- **A new check.** The probe learns to test something it did not test before, which can add a finding. This ships with a new `probe_version`, and the changelog lists the new finding IDs.
- **A corrected check.** A check that reported something wrongly is fixed, as when probe 0.7.0 stopped counting a connection refused during TLS as reached. The changelog says what changed and why.

`--baseline` compares `probe_version` and `agentsec_version` between the baseline and the new run. When either differs, it says so. A new or more severe finding still fails the gate, because the gate cannot tell a new check from a looser sandbox. A version difference with nothing worse passes. The README's `--baseline` section describes the rest of the comparison.

To control when a new check reaches a build, pin the package version, or pin the Action to a release tag.

## What is not covered

- **Experimental commands.** `verify`, `submit` and `benchmark` can change in any release. Their help text says so.
- **Human-readable output.** Terminal text, Markdown, HTML and SVG can change in any release. Read the JSON reports and exit codes instead.
- **Other JSON.** `matrix`, `combine` and `verify` write JSON that no schema covers yet.
- **The Python modules.** `agentsec` is used through its command line and its Action. Importing its modules works, but their functions and classes can change in any release.
- **Measured profiles.** The reports in `examples/` record what a sandbox did on the day it was measured. A vendor's next release can change it.
