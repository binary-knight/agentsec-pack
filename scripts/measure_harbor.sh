#!/usr/bin/env bash
# Measure what an agent can reach inside public Terminal-Bench tasks, through real Harbor.
#
#   bash scripts/measure_harbor.sh <scratch dir>
#
# Clones Harbor and Terminal-Bench at the commits below, installs Harbor into a new
# virtualenv under the scratch dir, and runs the no-model ProbeAgent on the tasks
# chosen by scripts/select_harbor_sample.py. This builds each task's public
# Dockerfile and runs its container on this machine's Docker daemon, which can take
# a long time and several GB per task. No API key is used and no task is attempted.
set -euo pipefail

HARBOR_COMMIT=b7cc86b617eb5a220c3d6041dbcca4fda8a6f5a8
TB_COMMIT=73d6279f91eb773bd51af2e2572a6fa044342e7a
REPO="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mkdir -p "$1" && cd "$1" && pwd)"
OUT="$REPO/examples/harbor"

fetch() {  # url dir commit
  [ -d "$2/.git" ] || { git init -q "$2"; git -C "$2" remote add origin "$1"; }
  git -C "$2" fetch -q --depth 1 origin "$3"
  git -C "$2" checkout -q FETCH_HEAD
}
fetch https://github.com/harbor-framework/harbor.git "$W/harbor" "$HARBOR_COMMIT"
fetch https://github.com/harbor-framework/terminal-bench.git "$W/terminal-bench" "$TB_COMMIT"

uv venv -q --allow-existing --python 3.13 "$W/hv"
uv pip install -q --python "$W/hv/bin/python" "$W/harbor" "$REPO"

ENVV=(env -i "HOME=$HOME" "PATH=$W/hv/bin:/usr/local/bin:/usr/bin:/bin" TERM=xterm "USER=$USER" LANG=C.UTF-8)
TASKS="$(python3 "$REPO/scripts/select_harbor_sample.py" "$W/terminal-bench" 5 | sed -n "s/^measure: //p" | tr -d "[]',")"
echo "tasks: $TASKS"

mkdir -p "$OUT"
for t in $TASKS; do
  echo "== $t"
  rc=0
  "${ENVV[@]}" harbor run --path "$W/terminal-bench/tasks/$t" \
    --agent-import-path agentsec.integrations.harbor_agent:ProbeAgent --disable-verification \
    --jobs-dir "$W/jobs" --job-name "$t" -n 1 > "$W/$t.out" 2> "$W/$t.err" || rc=$?
  json="$(find "$W/jobs/$t" -name agentsec-probe.json | head -1)"
  if [ -z "$json" ] || [ ! -s "$json" ]; then
    echo "   no probe result (harbor exit $rc), see $W/$t.err"
    continue
  fi
  cat "$(dirname "$json")/agentsec-verifier-paths.json"; echo
  "$W/hv/bin/agentsec" score "$json" --label "harbor-$t" --redact --out "$OUT" \
    --how "Harbor ${HARBOR_COMMIT:0:12}, terminal-bench ${TB_COMMIT:0:12}, task $t: harbor run with the no-model agentsec ProbeAgent, Docker environment, verifier disabled, launched with env -i. Task chosen by scripts/select_harbor_sample.py." || true
done
echo "reports: $OUT"
