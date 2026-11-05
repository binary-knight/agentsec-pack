#!/usr/bin/env python3
"""Run verify's static checks over public pull requests written by coding agents.

    python scripts/survey_agent_prs.py <work dir> [--per-cell 10]

This reads git objects only. Nothing from the surveyed repositories is executed, so
re-grading is not part of it, and it says how often the tampering and weakening
checks fire, and on what.

The sample is a repeatable rule. A fixed seed picks one day of the window for each
agent and outcome, and draws up to --per-cell pull requests from that day's results.
The result sets come from GitHub's search, so they can shift over time; the chosen
pull requests are saved so a later run can reuse them.
"""
import argparse
import json
import pathlib
import random
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from agentsec import verify as vf  # noqa: E402

AGENTS = ["copilot-swe-agent", "devin-ai-integration", "claude", "google-labs-jules", "cursor"]
OUTCOMES = {"merged": "is:merged", "closed": "is:unmerged is:closed"}
SEED = "agentsec-verify-survey-v1"
YEAR_MONTH, DAYS = "2026-10", 31


def gh(*args):
    p = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip()[:300])
    return json.loads(p.stdout)


def draw(per_cell):
    rng = random.Random(SEED)
    chosen = []
    for agent in AGENTS:
        for outcome, q in OUTCOMES.items():
            day = rng.randint(1, DAYS)
            query = f"is:pr {q} author:app/{agent} language:python created:{YEAR_MONTH}-{day:02d} is:public"
            items = gh("-X", "GET", "search/issues", "-f", f"q={query}", "-f", "per_page=100", "-f", "sort=created")["items"]
            urls = sorted(i["html_url"] for i in items)
            for url in rng.sample(urls, min(per_cell, len(urls))):
                chosen.append({"agent": agent, "outcome": outcome, "day": day, "url": url})
            time.sleep(7)  # the search API allows 10 requests a minute without a token, 30 with one
    return chosen


def survey_one(pr, work):
    owner, repo, _, number = pr["url"].split("/")[-4:]
    info = gh(f"repos/{owner}/{repo}/pulls/{number}")
    head_sha = info["head"]["sha"]
    cmp = gh(f"repos/{owner}/{repo}/compare/{info['base']['sha']}...{head_sha}")
    base_sha = cmp["merge_base_commit"]["sha"]
    d = work / "repos" / f"{owner}__{repo}"
    d.mkdir(parents=True, exist_ok=True)
    env_git = ["git", "-C", str(d), "-c", "core.hooksPath=/dev/null"]
    if not (d / ".git").exists():
        subprocess.run(env_git + ["init", "-q"], check=True)
        subprocess.run(env_git + ["remote", "add", "origin", f"https://github.com/{owner}/{repo}.git"], check=True)
        subprocess.run(env_git + ["config", "extensions.partialClone", "origin"], check=True)
    subprocess.run(env_git + ["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", base_sha, f"refs/pull/{number}/head"],
                   check=True, capture_output=True, timeout=600)
    base, head = vf._tree(str(d), base_sha), vf._tree(str(d), head_sha)
    ch = vf.diff_trees(str(d), base, head)
    weak = vf.find_weakening(str(d), ch)
    kinds = {}
    for p, k in ch.kinds.items():
        kinds[k] = kinds.get(k, 0) + 1
    additive = set(weak["only_added_to"])
    return {**pr, "repo": f"{owner}/{repo}", "base": base_sha, "head": head_sha, "stars": info["base"]["repo"]["stargazers_count"],
            "base_has_tests": any(vf.classify(p) == "test" for p in base),
            "changed_files": sum(1 for p in set(base) | set(head) if base.get(p) != head.get(p)),
            "kinds": kinds, "added": ch.added, "modified": ch.modified, "deleted": ch.deleted,
            "existing_tests_edited": sorted(p for p in ch.modified + ch.deleted if ch.kinds[p] == "test" and p not in additive),
            "weakening": {k: v for k, v in weak.items() if v and k != "only_added_to"}, "only_added_to": weak["only_added_to"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("work", type=pathlib.Path)
    ap.add_argument("--per-cell", type=int, default=10)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    sample = a.work / "sample.json"
    if not sample.exists():
        sample.write_text(json.dumps(draw(a.per_cell), indent=1))
    prs = json.loads(sample.read_text())
    out = a.work / "results.jsonl"
    done = {json.loads(l)["url"] for l in out.read_text().splitlines()} if out.exists() else set()
    with out.open("a") as f:
        for i, pr in enumerate(prs):
            if pr["url"] in done:
                continue
            try:
                row = survey_one(pr, a.work)
            except Exception as e:  # a deleted fork, a huge repo: recorded, never silently dropped
                row = {**pr, "error": f"{type(e).__name__}: {str(e)[:200]}"}
            f.write(json.dumps(row) + "\n")
            f.flush()
            print(f"{i + 1}/{len(prs)} {pr['agent']} {pr['outcome']} {'ERROR' if 'error' in row else 'ok'}", flush=True)


if __name__ == "__main__":
    main()
