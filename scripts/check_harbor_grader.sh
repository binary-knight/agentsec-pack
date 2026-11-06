#!/usr/bin/env bash
# Check one public Terminal-Bench task's grader through real Harbor. Three runs, each graded:
#
#   nothing    Harbor's nop agent. The grader must not pass an untouched environment.
#   solution   Harbor's oracle agent, the task's own solution. A grader that can never pass
#              would resist any forgery, so this has to pass for the rest to mean anything.
#   forged     agentsec's ForgeAgent, which only tries to fake a pass. It must not pass.
#
#   bash scripts/check_harbor_grader.sh <scratch dir> <task> [seconds allowed for the solution]
#
# This builds the task's public Dockerfile and runs it, and runs the task's solution, so use a
# machine you can throw away. No API key is used. Writes examples/harbor-grader/<task>.json.
# TASK_DIR runs a task from somewhere else, such as the controls in examples/harbor-control/.
set -uo pipefail

HARBOR_COMMIT=b7cc86b617eb5a220c3d6041dbcca4fda8a6f5a8
TB_COMMIT=73d6279f91eb773bd51af2e2572a6fa044342e7a
REPO="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mkdir -p "$1" && cd "$1" && pwd)"
TASK="$2"
SOLUTION_SECONDS="${3:-3000}"
OUT="$REPO/examples/harbor-grader"
mkdir -p "$OUT"

fetch() {  # url dir commit
  [ -d "$2/.git" ] || { git init -q "$2"; git -C "$2" remote add origin "$1"; }
  git -C "$2" fetch -q --depth 1 origin "$3" && git -C "$2" checkout -q FETCH_HEAD
}
fetch https://github.com/harbor-framework/harbor.git "$W/harbor" "$HARBOR_COMMIT" || exit 1
fetch https://github.com/harbor-framework/terminal-bench.git "$W/terminal-bench" "$TB_COMMIT" || exit 1
uv venv -q --allow-existing --python 3.13 "$W/hv" || exit 1
uv pip install -q --python "$W/hv/bin/python" "$W/harbor" "$REPO" || exit 1

run() {  # name, seconds, agent arguments...
  local name="$1" seconds="$2"; shift 2
  echo "== $name"
  timeout "$seconds" env PATH="$W/hv/bin:$PATH" harbor run --path "${TASK_DIR:-$W/terminal-bench/tasks/$TASK}" "$@" \
    --jobs-dir "$W/jobs" --job-name "$name" -n 1 > "$W/$name.out" 2> "$W/$name.err"
  echo "   harbor exit $?"
}
run nothing 2400 --agent nop
run forged 2400 --agent-import-path agentsec.integrations.harbor_agent:ForgeAgent
run solution "$SOLUTION_SECONDS" --agent oracle

"$W/hv/bin/python" "$REPO/scripts/read_harbor_grades.py" "$W/jobs" "$TASK" "$HARBOR_COMMIT" "$TB_COMMIT" > "$OUT/$TASK.json"
cat "$OUT/$TASK.json"
