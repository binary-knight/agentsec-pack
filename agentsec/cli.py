"""agentsec command line.

  agentsec presets
  agentsec probe --label "my-agent 1.2 workspace-write" --how "..."
    (measure the sandbox this command is running in)
  agentsec blast-radius local
  agentsec blast-radius docker python:3.12-slim --print-findings
  agentsec blast-radius docker python:3.12-slim --label hardened -- --network none --read-only
    (everything after a literal -- is passed to the container engine)
  agentsec blast-radius preset docker-hardened --image python:3.12-slim
  agentsec blast-radius command --template "bwrap --ro-bind / / ... python3 {probe}"
  agentsec matrix python:3.12-slim
  agentsec compare reports/*.json

  agentsec blast-radius docker myagent:tag --baseline reports/accepted.json
  agentsec diff reports/accepted.json reports/latest.json
  agentsec verify --base main --head agent-branch --test-cmd "pytest -q"
    (did the change pass its tests, or did it change the tests?)

Exit codes: 0 ok, 1 error, 2 --max-score exceeded or a regression against --baseline.
"""
from __future__ import annotations

import argparse
import json
import os
import re
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


def _against_baseline(env: dict, baseline_path: str | None) -> int:
    """Exit 2 if this run is worse than the saved baseline in any way, whatever the score."""
    if not baseline_path:
        return 0
    from . import baseline as bl
    with open(baseline_path) as f:
        base = json.load(f)
    result = bl.compare(base, env)
    out = sys.stderr if result["regressions"] else sys.stdout
    print(bl.render(result, baseline_path), file=out)
    return EXIT_OVER_BUDGET if result["regressions"] else 0


def _gate(score: int, args: argparse.Namespace, env: dict) -> int:
    """Both gates run, so one failing does not hide what the other would say."""
    a = _budget(score, args.max_score)
    b = _against_baseline(env, getattr(args, "baseline", None))
    return a or b


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
    return _gate(summary["score"], args, env)


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


def _probe_from_text(raw: str) -> tuple[dict, str]:
    """Get the probe object out of whatever the agent handed back.

    A read-only sandbox cannot write a file, so the JSON arrives inside a reply:
    surrounded by prose, wrapped in a code fence, and often clipped at the end,
    sometimes all three at once. Every one of those was hand-repaired by someone
    before this existed.
    """
    text = raw.strip()

    def attempts(candidate):
        """Direct parse, then drop trailing junk, then close unbalanced braces."""
        body = candidate.strip()
        if not body:
            return
        yield body, ""
        cut = body.rfind("}")
        if cut != -1 and cut < len(body) - 1:
            yield body[: cut + 1], "ignored trailing text after the object"
        for extra in range(1, 9):
            yield body + "}" * extra, f"input was missing {extra} closing brace(s); repaired before scoring"

    candidates = [(text, "")]
    for block in re.findall(r"```(?:json)?\s*(.*?)(?:```|\Z)", text, re.S):
        candidates.append((block, "extracted the object from a fenced code block"))
    brace = text.find('{"')
    if brace < 0:
        brace = text.find("{")
    if brace > 0:
        candidates.append((text[brace:], f"skipped {brace} characters of surrounding text"))

    for candidate, how in candidates:
        for body, repair in attempts(candidate):
            try:
                obj = json.loads(body)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            return obj, "; ".join(n for n in (how, repair) if n)

    if "{" not in text:
        raise ValueError("no JSON object found in that text")
    raise ValueError("that is not parseable probe JSON, even allowing for a fenced block, "
                     "surrounding prose and a truncated tail")


def cmd_probe(args: argparse.Namespace) -> int:
    """Measure the sandbox this command is running in, and score it, in one step."""
    run = runner.run_self(timeout=args.timeout, proxy_auth=args.proxy_auth)
    summary = summarize(run["probe"])
    run["target"].update(label=args.label, how=args.how)
    env = runner.result_envelope(run, summary, args.label)
    if args.redact:
        env = redact(env)
    name = args.label.replace(" ", "_").replace("/", "_")
    try:
        jp, mp = _write(env, args.out, name)
        print(f"{args.label}: score {summary['score']}/100, {summary['finding_count']} findings -> {mp}")
    except OSError as e:
        # A read-only sandbox cannot keep the report. Hand it back on stdout so
        # it can be saved from the transcript and gated or rendered elsewhere.
        print(f"could not write to {args.out} ({type(e).__name__}); the report follows on stdout. "
              "Save it to a file; `agentsec diff` and `agentsec report` accept it.", file=sys.stderr)
        print(json.dumps(env, sort_keys=True))
    for f in summary["findings"]:
        print(f"  [{f['severity']:<8}] {f['id']} {f['title']}", file=sys.stderr)
    if not run["target"]["proxy_auth"] and any(f["id"] == "NET-004" for f in summary["findings"]):
        print("  note: the network axis was not measured; --proxy-auth sends the proxy its own password "
              "(to that proxy only) so it can be. That is your decision, not an agent's.", file=sys.stderr)
    return _gate(summary["score"], args, env)


def cmd_score(args: argparse.Namespace) -> int:
    """Score a probe result the tool did not launch itself.

    Some sandboxes cannot be driven from outside: an agent's own sandbox mode is
    entered by the agent, not by us. Capture the probe's JSON however you can and
    score it here; `--how` is recorded verbatim so the measurement stays checkable.
    """
    with open(args.probe_json) as f:
        raw = f.read().strip()
    probe, note = _probe_from_text(raw)
    if note:
        print(f"note: {note}", file=sys.stderr)
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
    return _gate(summary["score"], args, env)


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two saved reports. For CI that measures in one step and gates in another."""
    with open(args.current) as f:
        current = json.load(f)
    return _against_baseline(current, args.baseline)


def cmd_submit(args: argparse.Namespace) -> int:
    """Prepare a measurement for a public dataset, for a person to send. See agentsec/submit.py."""
    import webbrowser
    from . import submit as sb
    try:
        with open(args.report) as f:
            env = json.load(f)
        record = sb.build_record(env, args.agent, args.agent_version, args.sandbox, args.setting)
        text = json.dumps(record, indent=2, sort_keys=True)
        url = sb.issue_url(args.to, text, record)
    except (OSError, ValueError, sb.SubmitError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"This is everything that would be posted, publicly, as an issue in {args.to}:\n\n{text}\n")
    if not sys.stdin.isatty():
        print("Nothing was opened. This needs a person at a terminal to confirm it.", file=sys.stderr)
        return 1
    if input("Open a pre-filled issue with exactly this? Type yes to continue: ").strip() != "yes":
        print("Nothing was opened or sent.")
        return 0
    if args.no_browser or not webbrowser.open(url):
        print(f"Open this address to review and post the issue:\n{url}")
    else:
        print("Opened in your browser. Nothing is posted until you submit the issue there.")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """How a sandbox's score and findings moved across saved runs. See agentsec/history.py."""
    from . import history as hs
    try:
        entries, skipped = hs.load(args.paths)
        for note in skipped:
            print(f"skipped {note}", file=sys.stderr)
        if args.label:
            entries = [e for e in entries if e.get("label") == args.label]
        if not entries:
            print("error: no blast-radius reports to read", file=sys.stderr)
            return 1
        if args.save:
            added = hs.save(args.save, entries)
            print(f"saved {added} new run{'' if added == 1 else 's'} to {args.save}", file=sys.stderr)
            entries, _skipped = hs.load([args.save])
            if args.label:
                entries = [e for e in entries if e.get("label") == args.label]
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    history = hs.build(entries, args.max_score)
    print(json.dumps(history, indent=2, sort_keys=True) if args.json else hs.render(history, args.max_score))
    return 0


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


def _load_results(paths: list[str]) -> list[dict]:
    """Accept files or directories, newest first, skipping anything unscored."""
    files: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            files += [os.path.join(p, n) for n in sorted(os.listdir(p)) if n.endswith(".json")]
        else:
            files.append(p)
    out = []
    for f in files:
        try:
            with open(f) as fh:
                env = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(env, dict) and "summary" in env and "probe" in env:
            out.append(env)
    out.sort(key=lambda e: e.get("generated_at", 0), reverse=True)
    return out


def cmd_verify(args: argparse.Namespace) -> int:
    """Did the change pass its tests, or did it change the tests? See agentsec/verify.py."""
    from . import verify as vf
    if not args.junit:
        print("note: without --junit the runs are compared by exit code alone, which cannot separate a suite that "
              "never started from one that failed.", file=sys.stderr)
    if not args.image:
        print("note: the tests run on this machine with your user's access, and they run the code under "
              "test. Pass --image to run them in a container with no network.", file=sys.stderr)
    try:
        env = vf.verify(args.repo, args.base, args.head, args.test_cmd, timeout=args.timeout, image=args.image,
                        engine=args.engine, flags=args.flags, extra_globs=args.tests, not_tests=args.not_tests,
                        env_names=args.env, run_base=not args.no_base_run, junit=args.junit)
    except vf.VerifyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    env["label"] = args.label or f"verify-{env['target']['head'][:12]}"
    if args.redact:
        env = redact(env)
    name = env["label"].replace(" ", "_").replace("/", "_")
    os.makedirs(args.out, exist_ok=True)
    jp, mp = os.path.join(args.out, name + ".json"), os.path.join(args.out, name + ".md")
    with open(jp, "w") as f:
        json.dump(env, f, indent=2, sort_keys=True)
    with open(mp, "w") as f:
        f.write(vf.render_markdown(env))
    s = env["summary"]
    print(f"{env['label']}: {s['verdict']}: {vf.VERDICT_TEXT[s['verdict']]} -> {mp}")
    for f_ in s["findings"]:
        print(f"  [{f_['severity']:<8}] {f_['id']} {f_['title']}")
    if s["verdict"] != "verified":
        return EXIT_OVER_BUDGET
    if args.strict and any(f_["severity"] not in ("info", "low") for f_ in s["findings"]):
        print("FAIL: --strict and the change touched its tests", file=sys.stderr)
        return EXIT_OVER_BUDGET
    return 0


def cmd_chart(args: argparse.Namespace) -> int:
    """One quick-look chart of many runs: a row per run, a colored cell per axis."""
    from . import chart
    rows = []
    for p in args.results:
        paths = [os.path.join(p, n) for n in sorted(os.listdir(p)) if n.endswith(".json")] if os.path.isdir(p) else [p]
        for path in paths:
            try:
                with open(path) as f:
                    env = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(env, dict) and env.get("test") == "sandbox-blast-radius-matrix":
                rows += chart.rows_from_matrix(env)
            elif isinstance(env, dict) and "summary" in env:
                rows.append(chart.row_from_envelope(env))
    if not rows:
        print("no scored results found in those paths", file=sys.stderr)
        return 1
    if args.sort:
        rows.sort(key=lambda r: -r["score"])
    body = (chart.render_markdown([("", rows)]) if args.out.endswith(".md")
            else chart.render_svg([("", rows)], args.title, args.subtitle, args.theme))
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(body)
    print(f"{len(rows)} row(s) -> {args.out}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .ui import render_html
    results = _load_results(args.results)
    if not results:
        print("no scored results found in those paths", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render_html(results))
    print(f"{len(results)} result(s) -> {args.out}")
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    from .ui.server import serve
    serve(port=args.port, results=_load_results(args.results), open_browser=args.open,
          bind=args.bind, allow_remote_runs=args.allow_remote_runs)
    return 0


def cmd_assert(args: argparse.Namespace) -> int:
    """Answer a narrow question: can this sandbox reach these specific paths?

    Exits 2 when any expectation is violated, so it drops into a grading harness
    or a build the same way `--max-score` does.
    """
    from . import assertions

    expectations: list[tuple[str, str]] = []
    for kind in assertions.KINDS:
        for path in getattr(args, kind.replace("-", "_")):
            expectations.append((kind, path))
    if not expectations:
        print("nothing to check: pass at least one of "
              + ", ".join("--" + k for k in assertions.KINDS), file=sys.stderr)
        return 1

    target, parsed = runner.run_script(
        assertions.build_script(expectations), kind=args.kind, image=args.image,
        flags=args.flags, template=args.template, python=args.python, timeout=args.timeout)
    outcome = assertions.check(parsed.get("assertions", []), expectations)
    print(assertions.render(outcome))
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            json.dump({"tool": "agentsec-pack", "test": "path-assertions", "schema_version": 1,
                       "generated_at": int(time.time()), "target": target, **outcome}, f, indent=2, sort_keys=True)
    return 2 if outcome["failed"] else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentsec", description="Adversarial tests for AI agent deployments.")
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
    b.add_argument("--baseline", metavar="REPORT_JSON",
                   help="exit 2 if anything is worse than this saved report: a new finding, a higher severity, wider evidence")
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

    pr = sub.add_parser("probe", help="measure the sandbox this command runs in, and score it, in one step")
    pr.add_argument("--label", required=True, help="what is being measured, e.g. 'vendor-agent 1.2.3 workspace-write'")
    pr.add_argument("--how", required=True, help="exactly how this was run: agent, mode, settings, launching environment")
    pr.add_argument("--out", default="reports")
    pr.add_argument("--timeout", type=int, default=runner.DEFAULT_TIMEOUT)
    pr.add_argument("--max-score", type=int, help="exit 2 if the score exceeds this")
    pr.add_argument("--baseline", metavar="REPORT_JSON", help="exit 2 if anything is worse than this saved report")
    pr.add_argument("--redact", action="store_true", help="scrub hostname, working directory and secret-variable names")
    pr.add_argument("--proxy-auth", action="store_true",
                    help="send a configured egress proxy its own password from the environment, to that proxy only, "
                         "so the network axis can be measured; never recorded")
    pr.set_defaults(func=cmd_probe)

    sc = sub.add_parser("score", help="score a probe result captured by any means (see docs/CAPTURING.md)")
    sc.add_argument("probe_json", help="JSON written by blast_probe.py, however you ran it")
    sc.add_argument("--label", required=True, help="what was measured, e.g. 'vendor-agent 1.2.3 read-only mode'")
    sc.add_argument("--how", required=True, help="exactly how the probe was run, recorded in the report so a reader can repeat it")
    sc.add_argument("--out", default="reports")
    sc.add_argument("--max-score", type=int)
    sc.add_argument("--baseline", metavar="REPORT_JSON",
                    help="exit 2 if anything is worse than this saved report")
    sc.add_argument("--redact", action="store_true")
    sc.add_argument("--print-findings", action="store_true",
                    help="accepted for symmetry with blast-radius; score always prints its findings")
    sc.set_defaults(func=cmd_score)

    cb = sub.add_parser("combine", help="join a promptfoo run with a sandbox measurement")
    cb.add_argument("--promptfoo", required=True, help="promptfoo output JSON (from `promptfoo eval -o out.json`)")
    cb.add_argument("--sandbox", required=True, help="report JSON from `agentsec blast-radius`")
    cb.add_argument("--deployed-in", required=True,
                    help="YOUR assertion that the tested agent runs in the measured sandbox; printed in the report as an operator assumption")
    cb.add_argument("--out", default="reports")
    cb.add_argument("--label", default="combined")
    cb.set_defaults(func=cmd_combine)

    rp = sub.add_parser("report", help="render saved results as one self-contained HTML page")
    rp.add_argument("results", nargs="+", help="report JSON files, or directories of them")
    rp.add_argument("--out", default="agentsec-report.html")
    rp.set_defaults(func=cmd_report)

    ch = sub.add_parser("chart", help="draw many saved runs as one color-coded chart (SVG) or table (.md)")
    ch.add_argument("results", nargs="+", help="report JSON files, matrix JSON files, or directories of them")
    ch.add_argument("--out", default="agentsec-chart.svg", help="write an SVG, or a Markdown table if the name ends in .md")
    ch.add_argument("--theme", choices=("light", "dark"), default="light")
    ch.add_argument("--title", default="Blast radius by configuration")
    ch.add_argument("--subtitle", default="One row per run. Score 0 means the probe reached nothing.")
    ch.add_argument("--sort", action="store_true", help="highest score first")
    ch.set_defaults(func=cmd_chart)

    u = sub.add_parser("ui", help="open a local console in the browser (127.0.0.1 only)")
    u.add_argument("--port", type=int, default=8787)
    u.add_argument("--results", nargs="*", default=[], help="report JSON files or directories to load at startup")
    u.add_argument("--open", action="store_true", help="open the console in your browser")
    u.add_argument("--bind", default="127.0.0.1",
                   help="address to bind; anything other than loopback makes the console read-only "
                        "unless --allow-remote-runs is also given")
    u.add_argument("--allow-remote-runs", action="store_true",
                   help="permit launching configurations from a console that is reachable off this machine")
    u.set_defaults(func=cmd_ui)

    a = sub.add_parser("assert", help="check specific paths from inside a sandbox (pass/fail, no score)")
    a.add_argument("--readable", action="append", default=[], metavar="PATH")
    a.add_argument("--not-readable", action="append", default=[], metavar="PATH")
    a.add_argument("--writable", action="append", default=[], metavar="PATH")
    a.add_argument("--not-writable", action="append", default=[], metavar="PATH")
    a.add_argument("--exists", action="append", default=[], metavar="PATH")
    a.add_argument("--not-exists", action="append", default=[], metavar="PATH")
    a.add_argument("--kind", choices=["local", "docker", "podman", "command"], default="local")
    a.add_argument("--image")
    a.add_argument("--template", help="launcher template containing {probe} (kind=command)")
    a.add_argument("--python", default="python3")
    a.add_argument("--timeout", type=int, default=runner.DEFAULT_TIMEOUT)
    a.add_argument("--out", help="write the result as JSON to this file")
    a.set_defaults(func=cmd_assert)

    d = sub.add_parser("diff", help="exit 2 if a report is worse than a baseline report in any way")
    d.add_argument("baseline", help="the accepted report JSON")
    d.add_argument("current", help="the report JSON to check")
    d.set_defaults(func=cmd_diff)

    sb = sub.add_parser("submit", help="prepare one measurement for a public dataset, shown to you first, for you to post")
    sb.add_argument("report", help="the report JSON")
    sb.add_argument("--to", required=True, metavar="OWNER/REPO", help="the public dataset repository to open the issue in")
    sb.add_argument("--agent", required=True, help="the agent's name")
    sb.add_argument("--agent-version", required=True, help="the agent's version")
    sb.add_argument("--sandbox", required=True, help="the sandbox mode, in the agent's own words")
    sb.add_argument("--setting", action="append", default=[], help="a setting that changes the sandbox, repeatable; paths and variable names are refused")
    sb.add_argument("--no-browser", action="store_true", help="print the address instead of opening it")
    sb.set_defaults(func=cmd_submit)

    hi = sub.add_parser("history", help="how a sandbox's score and findings moved across saved runs")
    hi.add_argument("paths", nargs="+", metavar="PATH", help="report JSON files, directories of them, or a history file (.jsonl)")
    hi.add_argument("--save", metavar="FILE", help="add these runs to a history file, which keeps them after a report with the same label is replaced")
    hi.add_argument("--label", help="only this label")
    hi.add_argument("--max-score", type=int, help="also show how much of this budget is left")
    hi.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    hi.set_defaults(func=cmd_history)

    v = sub.add_parser("verify", help="did a change pass its tests, or did it change the tests? (exit 2 if not shown to pass)")
    v.add_argument("--base", required=True, help="the commit before the change")
    v.add_argument("--head", required=True, help="the commit to check")
    v.add_argument("--test-cmd", required=True, help="the test command, run with sh -c from the root of each tree")
    v.add_argument("--junit", metavar="PATH", help="the JUnit XML file the test command writes, relative to the tree, to compare the runs test by test")
    v.add_argument("--repo", default=".")
    v.add_argument("--image", help="run the tests in this container image with no network; everything after -- goes to the engine")
    v.add_argument("--engine", choices=["docker", "podman"], default="docker")
    v.add_argument("--tests", action="append", default=[], metavar="GLOB", help="also treat these paths as tests")
    v.add_argument("--not-tests", action="append", default=[], metavar="GLOB", help="these paths are code, whatever their names suggest")
    v.add_argument("--env", action="append", default=[], metavar="NAME", help="pass this variable to the tests; none are passed otherwise")
    v.add_argument("--timeout", type=int, default=600, help="seconds for each test run")
    v.add_argument("--no-base-run", action="store_true", help="skip running the base commit, which only reports whether the tests already passed")
    v.add_argument("--strict", action="store_true", help="also exit 2 when the change passes but touched its tests")
    v.add_argument("--label")
    v.add_argument("--out", default="reports")
    v.add_argument("--redact", action="store_true", help="scrub test output and home paths before writing")
    v.set_defaults(func=cmd_verify)

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
