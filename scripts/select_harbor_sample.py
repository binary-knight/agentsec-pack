#!/usr/bin/env python3
"""Pick which public Terminal-Bench tasks to measure, by a rule anyone can repeat.

    python scripts/select_harbor_sample.py <terminal-bench checkout> [count]

The sample is a uniform draw from the sorted task list, seeded with the checkout's
commit hash, so it depends on nothing but the public repository. Every task whose
task.toml turns the network off is added, because that setting should change the
result. Nothing about a task other than its public task.toml affects the choice.
"""
import pathlib
import random
import subprocess
import sys
import tomllib


def network_off(cfg: dict) -> bool:
    env = cfg.get("environment", {})
    return env.get("allow_internet") is False or env.get("network_mode") == "no-network"


def select(root: pathlib.Path, count: int) -> dict:
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    tasks = sorted(p.parent.name for p in (root / "tasks").glob("*/task.toml"))
    drawn = sorted(random.Random(commit).sample(tasks, count))
    off = sorted(t for t in tasks if network_off(tomllib.loads((root / "tasks" / t / "task.toml").read_text())))
    return {"commit": commit, "population": len(tasks), "drawn": drawn, "network_off": off,
            "measure": sorted(set(drawn) | set(off))}


if __name__ == "__main__":
    r = select(pathlib.Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 5)
    for k, v in r.items():
        print(f"{k}: {v}")
