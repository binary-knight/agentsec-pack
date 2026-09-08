"""agentsec command line.

  agentsec presets
  agentsec blast-radius local
  agentsec blast-radius docker python:3.12-slim --print-findings
  agentsec blast-radius docker python:3.12-slim --label hardened -- --network none --read-only
    (everything after a literal -- is passed to the container engine)
  agentsec blast-radius preset docker-hardened --image python:3.12-slim
  agentsec blast-radius command --template "bwrap --ro-bind / / ... python3 {probe}"
  agentsec matrix python:3.12-slim
  agentsec compare reports/*.json

Exit codes: 0 ok, 1 error, 2 --max-score exceeded.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import presets as presets_mod
from . import runner
from .report import render_markdown, render_matrix_markdown
from .redact import redact
from .scoring import summarize

EXIT_OVER_BUDGET = 2


def _write(env: dict, out_dir: str, name: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    jp, mp = os.path.join(out_dir, name + ".json"), os.path.join(out_dir, name + ".md")
    with open(jp, "w") as f:
        json.dump(env, f, indent=2, sort_keys=True)
    with open(mp, "w") as f:
        f.write(env.pop("_markdown", None) or render_markdown(env))
    return jp, mp


def _budget(score: int, max_score: int | None) -> int:
    if max_score is None:
        return 0
    if score > max_score:
        print(f"FAIL: score {score} exceeds --max-score {max_score}", file=sys.stderr)
        return EXIT_OVER_BUDGET
    print(f"OK: score {score} within --max-score {max_score}")
    return 0


def cmd_presets(args: argparse.Namespace) -> int:
    all_p = presets_mod.load_all()
    print(f"{'preset':<28} {'kind':<10} {'needs':<8} available")
    for name in sorted(all_p):
        p = all_p[name]
        req = presets_mod.requirement(p)
        print(f"{name:<28} {p['kind']:<10} {req:<8} {'yes' if presets_mod.available(p) else 'no'}")
    if args.verbose:
        print()
        for name in sorted(all_p):
            print(f"{name}: {all_p[name].get('rationale','')}")
    return 0


def cmd_blast(args: argparse.Namespace) -> int:
    if args.kind == "preset":
        run = runner.run_preset(args.name, image=args.image, timeout=args.timeout)
        default_label = args.name + (("_" + args.image.replace("/", "_").replace(":", "_")) if args.image else "")
    elif args.kind in ("docker", "podman"):
        run = runner.run_container(args.name, args.flags, engine=args.kind, python=args.python, timeout=args.timeout)
        default_label = args.name.replace("/", "_").replace(":", "_")
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
    if args.redact:
        env = redact(env)
    jp, mp = _write(env, args.out, label)
    print(f"{label}: score {summary['score']}/100, {summary['finding_count']} findings -> {mp}")
    if args.print_findings:
        for f in summary["findings"]:
            print(f"  [{f['severity']:<8}] {f['id']} {f['title']}")
        if summary.get("recommended_flags"):
            print("  suggested: " + " ".join(summary["recommended_flags"]))
    return _budget(summary["score"], args.max_score)


def cmd_matrix(args: argparse.Namespace) -> int:
    wanted = args.presets.split(",") if args.presets else sorted(presets_mod.load_all())
    runs, skipped = [], {}
    for name in wanted:
        p = presets_mod.get(name)
        if not presets_mod.available(p):
            skipped[name] = f"{presets_mod.requirement(p)} not on PATH"
            continue
        if p["kind"] == "container" and not args.image:
            skipped[name] = "needs an image"
            continue
        try:
            run = runner.run_preset(name, image=args.image, timeout=args.timeout)
        except Exception as e:
            skipped[name] = f"{type(e).__name__}: {e}"
            continue
        s = summarize(run["probe"])
        worst = max(s["findings"], key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f["severity"]], default=None)
        runs.append({"preset": name, "score": s["score"], "raw_score": s["raw_score"], "findings": s["finding_count"],
                     "worst": f"{worst['id']} {worst['title']}" if worst else None,
                     "rationale": p.get("rationale", ""), "recommended_flags": s.get("recommended_flags", []),
                     "target": run["target"], "summary": s})
        print(f"  {name:<28} score {s['score']:>3}  findings {s['finding_count']}")
    if not runs:
        print("no presets could run here", file=sys.stderr)
        return 1
    digest = next((r["target"].get("digest") for r in runs if r["target"].get("digest")), None)
    env = {"tool": "agentsec-pack", "test": "sandbox-blast-radius-matrix", "schema_version": 1,
           "image": args.image, "digest": digest, "probe_version": runs[0]["summary"] and runner._probe_version(),
           "generated_at": int(time.time()), "generated_at_iso": time.strftime("%Y-%m-%d", time.gmtime()),
           "runs": runs, "skipped": skipped}
    if getattr(args, "redact", False):
        env = redact(env)
    env["_markdown"] = render_matrix_markdown(env)
    label = args.label or ("matrix_" + (args.image or "local").replace("/", "_").replace(":", "_"))
    jp, mp = _write(env, args.out, label)
    print(f"matrix: {len(runs)} configurations, {len(skipped)} skipped -> {mp}")
    return _budget(min(r["score"] for r in runs), args.max_score)


def cmd_score(args: argparse.Namespace) -> int:
    """Score a probe result the tool did not launch itself.

    Some sandboxes cannot be driven from outside: an agent's own sandbox mode is
    entered by the agent, not by us. Capture the probe's JSON however you can and
    score it here; `--how` is recorded verbatim so the measurement stays checkable.
    """
    with open(args.probe_json) as f:
        raw = f.read().strip()
    try:
        probe = json.loads(raw)
    except json.JSONDecodeError:
        # Agent transcripts sometimes clip the trailing brace off a pasted blob.
        repaired, added = raw, 0
        while repaired.count("{") > repaired.count("}") and added < 8:
            repaired += "}"
            added += 1
        probe = json.loads(repaired)
        print(f"note: input was missing {added} closing brace(s); repaired before scoring", file=sys.stderr)
    summary = summarize(probe)
    env = {"tool": "agentsec-pack", "test": "sandbox-blast-radius", "schema_version": 1, "label": args.label,
           "generated_at": int(time.time()),
           "target": {"kind": "captured", "label": args.label, "how": args.how,
                      "note": "Captured externally: the probe was run inside the target by the means described in `how`, not launched by agentsec."},
           "rc": 0, "summary": summary, "probe": probe, "probe_stderr": ""}
    if args.redact:
        env = redact(env)
    jp, mp = _write(env, args.out, args.label.replace(" ", "_").replace("/", "_"))
    print(f"{args.label}: score {summary['score']}/100, {summary['finding_count']} findings -> {mp}")
    for f in summary["findings"]:
        print(f"  [{f['severity']:<8}] {f['id']} {f['title']}")
    return _budget(summary["score"], args.max_score)


def cmd_combine(args: argparse.Namespace) -> int:
    from .integrations import promptfoo_combine as pc
    with open(args.sandbox) as f:
        sandbox = json.load(f)
    env = pc.combine(pc.load_promptfoo(args.promptfoo), sandbox, args.deployed_in)
    env["_markdown"] = pc.render_markdown(env)
    jp, mp = _write(env, args.out, args.label)
    pf, sb = env["promptfoo"], env["sandbox"]
    print(f"combined: {pf['failed']}/{pf['total']} promptfoo tests failed; sandbox scores {sb['score']}/100 -> {mp}")
    if env.get("overlap"):
        print(f"  overlap on {len(env['overlap'])} OWASP categor{'y' if len(env['overlap']) == 1 else 'ies'}: "
              + ", ".join(o["asi"] for o in env["overlap"]))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    print(f"{'label':<48} {'score':>5}  findings")
    for p in args.results:
        with open(p) as f:
            e = json.load(f)
        if e.get("test") == "sandbox-blast-radius-matrix":
            for r in e["runs"]:
                print(f"{r['preset'][:48]:<48} {r['score']:>5}  {r['findings']}")
        else:
            s = e["summary"]
            print(f"{str(e.get('label'))[:48]:<48} {s['score']:>5}  {s['finding_count']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentsec", description="Adversarial tests for AI agent deployments (working name).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("presets", help="list named sandbox configurations")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_presets)

    b = sub.add_parser("blast-radius", help="measure what a process inside a sandbox can reach")
    b.add_argument("kind", choices=["docker", "podman", "local", "command", "preset"])
    b.add_argument("name", nargs="?", help="image (docker/podman) or preset name")
    b.add_argument("--image", help="image to use with a container preset")
    b.add_argument("--template", help="launcher template containing {probe} (kind=command)")
    b.add_argument("--python", default="python3", help="python executable inside the image")
    b.add_argument("--timeout", type=int, default=runner.DEFAULT_TIMEOUT)
    b.add_argument("--out", default="reports")
    b.add_argument("--label")
    b.add_argument("--print-findings", action="store_true")
    b.add_argument("--max-score", type=int, help="exit 2 if the score exceeds this (CI gate)")
    b.add_argument("--redact", action="store_true", help="scrub hostname, working directory and secret-variable names before writing (for reports you intend to publish)")
    b.set_defaults(func=cmd_blast)

    m = sub.add_parser("matrix", help="run several presets and write one comparison table")
    m.add_argument("image", nargs="?", help="image for container presets")
    m.add_argument("--presets", help="comma-separated subset; default is all")
    m.add_argument("--timeout", type=int, default=runner.DEFAULT_TIMEOUT)
    m.add_argument("--out", default="reports")
    m.add_argument("--label")
    m.add_argument("--max-score", type=int, help="exit 2 if the BEST configuration still exceeds this")
    m.add_argument("--redact", action="store_true", help="scrub operator-identifying detail before writing")
    m.set_defaults(func=cmd_matrix)

    sc = sub.add_parser("score", help="score a probe result captured by any means (see docs/CAPTURING.md)")
    sc.add_argument("probe_json", help="JSON written by blast_probe.py, however you ran it")
    sc.add_argument("--label", required=True, help="what was measured, e.g. 'vendor-agent 1.2.3 read-only mode'")
    sc.add_argument("--how", required=True, help="exactly how the probe was run, recorded in the report so a reader can repeat it")
    sc.add_argument("--out", default="reports")
    sc.add_argument("--max-score", type=int)
    sc.add_argument("--redact", action="store_true")
    sc.set_defaults(func=cmd_score)

    cb = sub.add_parser("combine", help="join a promptfoo run with a sandbox measurement")
    cb.add_argument("--promptfoo", required=True, help="promptfoo output JSON (from `promptfoo eval -o out.json`)")
    cb.add_argument("--sandbox", required=True, help="report JSON from `agentsec blast-radius`")
    cb.add_argument("--deployed-in", required=True,
                    help="YOUR assertion that the tested agent runs in the measured sandbox; printed in the report as an operator assumption")
    cb.add_argument("--out", default="reports")
    cb.add_argument("--label", default="combined")
    cb.set_defaults(func=cmd_combine)

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
        if args.kind in ("docker", "podman") and not args.name:
            ap.error(f"{args.kind} needs an image")
        if args.kind == "preset" and not args.name:
            ap.error("preset needs a preset name")
        if args.kind == "command" and not args.template:
            ap.error("command kind needs --template")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
