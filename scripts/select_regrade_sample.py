#!/usr/bin/env python3
"""Draw pull requests from a survey to re-grade, by a rule anyone can repeat.

    python scripts/select_regrade_sample.py <results.jsonl> [--size 20]

Takes every surveyed pull request whose base commit has tests, because re-grading has
nothing to run otherwise, and draws from them with a fixed seed. Whether a pull request
edited its tests plays no part in the draw. The output is the input for regrade.yml.
"""
import argparse
import json
import random

SEED = "agentsec-verify-regrade-sample-v1"


def draw(rows, size):
    eligible = sorted((r for r in rows if r.get("base_has_tests")), key=lambda r: r["url"])
    return random.Random(SEED).sample(eligible, min(size, len(eligible)))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results")
    ap.add_argument("--size", type=int, default=20)
    args = ap.parse_args()
    with open(args.results) as f:
        rows = [json.loads(line) for line in f if line.strip()]
    print(json.dumps([{"repo": r["repo"], "base": r["base"], "head": r["head"]} for r in draw(rows, args.size)]))


if __name__ == "__main__":
    main()
