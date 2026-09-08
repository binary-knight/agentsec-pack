"""agentsec command line.

  agentsec blast-radius docker python:3.12-slim
  agentsec blast-radius docker python:3.12-slim --label hardened -- --network none --read-only --cap-drop ALL
  (everything after a literal -- is passed to docker run)
  agentsec blast-radius local
  agentsec blast-radius command "bwrap --ro-bind / / --dev /dev --unshare-all -- python3 {probe}"
  agentsec compare a.json b.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import runner
from .report import render_markdown
from .scoring import summarize


def _write(env: dict, out_dir: str, name: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    jp = os.path.join(out_dir, name + ".json")
    mp = os.path.join(out_dir, name + ".md")
    with open(jp, "w") as f:
        json.dump(env, f, indent=2, sort_keys=True)
    with open(mp, "w") as f:
        f.write(render_markdown(env))
    return jp, mp


def cmd_blast(args: argparse.Namespace) -> int:
    if args.kind == "docker":
        run = runner.run_docker(args.image, args.flags, python=args.python, timeout=args.timeout)
        default_label = args.image.replace("/", "_").replace(":", "_") + ("_" + "_".join(x.strip("-") for x in args.flags) if args.flags else "")
    elif args.kind == "local":
        run = runner.run_local(timeout=args.timeout)
        default_label = "local"
    elif args.kind == "command":
        run = runner.run_command(args.template, timeout=args.timeout)
        default_label = "command"
    else:
        raise SystemExit("unknown kind")
    summary = summarize(run["probe"])
    label = args.label or default_label
    env = runner.result_envelope(run, summary, label)
    jp, mp = _write(env, args.out, label)
    print(f"{label}: score {summary['score']}/100, {summary['finding_count']} findings -> {mp}")
    if args.print_findings:
        for f in summary["findings"]:
            print(f"  [{f['severity']:<8}] {f['id']} {f['title']}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    envs = []
    for p in args.results:
        with open(p) as f:
            envs.append(json.load(f))
    print(f"{'label':<48} {'score':>5}  findings")
    for e in envs:
        s = e["summary"]
        print(f"{str(e.get('label'))[:48]:<48} {s['score']:>5}  {s['finding_count']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentsec", description="Adversarial tests for AI agent deployments (working name).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("blast-radius", help="measure what a process inside a sandbox can reach")
    b.add_argument("kind", choices=["docker", "local", "command"])
    b.add_argument("image", nargs="?", help="docker image (kind=docker)")
    b.add_argument("--template", help="launcher template containing {probe} (kind=command)")
    b.add_argument("--python", default="python3", help="python executable inside the image")
    b.add_argument("--timeout", type=int, default=runner.DEFAULT_TIMEOUT)
    b.add_argument("--out", default="reports")
    b.add_argument("--label")
    b.add_argument("--print-findings", action="store_true")
    b.set_defaults(func=cmd_blast)
    c = sub.add_parser("compare", help="print scores side by side")
    c.add_argument("results", nargs="+")
    c.set_defaults(func=cmd_compare)
    argv = list(sys.argv[1:] if argv is None else argv)
    flags: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        flags, argv = argv[i + 1:], argv[:i]
    args = ap.parse_args(argv)
    args.flags = flags
    if args.cmd == "blast-radius":
        if args.kind == "docker" and not args.image:
            ap.error("docker kind needs an image")
        if args.kind == "command" and not args.template:
            ap.error("command kind needs --template")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
