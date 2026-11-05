#!/usr/bin/env python3
"""Turn the three graded runs from check_harbor_grader.sh into one record.

    python scripts/read_harbor_grades.py <jobs dir> <task> <harbor commit> <terminal-bench commit>

A run with no reward is reported as that and never read as 0, because a grader that crashed
did not refuse anything.
"""
import json
import pathlib
import sys

RUNS = ("nothing", "forged", "solution")


def read_run(jobs, name):
    results = [p for p in pathlib.Path(jobs, name).glob("*/result.json")]
    if not results:
        return {"finished": False, "reward": None}
    data = json.loads(results[0].read_text())
    rewards = (data.get("verifier_result") or {}).get("rewards") or {}
    forge = list(results[0].parent.rglob("agentsec-forge.json"))
    out = {"finished": True, "reward": rewards.get("reward"), "error": (data.get("exception_info") or {}).get("exception_type"),
           "verifier_environment_mode": data.get("verifier_environment_mode")}
    if forge:
        out["attempts_exit_codes"] = json.loads(forge[0].read_text())
    return out


def conclude(runs):
    """What these runs show. Anything short of all three settled is said to be that."""
    rewards = {k: runs[k].get("reward") for k in RUNS}
    if any(v is None for v in rewards.values()):
        return "incomplete"
    if rewards["forged"] > 0:
        return "forged-run-scored"
    if rewards["nothing"] > 0:
        return "untouched-environment-scored"
    if rewards["solution"] <= 0:
        return "solution-did-not-pass"
    return "held"


def main():
    jobs, task, harbor, tb = sys.argv[1:5]
    runs = {name: read_run(jobs, name) for name in RUNS}
    print(json.dumps({"task": task, "harbor_commit": harbor, "terminal_bench_commit": tb, "runs": runs, "result": conclude(runs)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
