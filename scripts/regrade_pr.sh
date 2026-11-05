#!/usr/bin/env bash
# One pull request on a disposable machine: fetch it, install its dependencies, re-grade it.
# Run by .github/workflows/regrade.yml with REPO, BASE, HEAD_SHA and LABEL set. Everything
# after the checkout below may be running the project's code, so a result from this script
# is only as trustworthy as the machine. Do not run it on a machine you care about.
set -uo pipefail
: "${REPO:?}" "${BASE:?}" "${HEAD_SHA:?}" "${LABEL:?}" "${RUNNER_TEMP:?}"
TOOL="$RUNNER_TEMP/tool/bin/agentsec"
OUT="$RUNNER_TEMP/out"
SRC="$RUNNER_TEMP/repo"
DEPS="$RUNNER_TEMP/deps"
mkdir -p "$OUT" "$SRC"

note() { printf '%s\n' "$1" | tee -a "$OUT/$LABEL.setup.txt"; }

git -C "$SRC" -c core.hooksPath=/dev/null init -q
git -C "$SRC" remote add origin "https://github.com/$REPO.git"
if ! git -C "$SRC" -c core.hooksPath=/dev/null fetch -q --depth 1 origin "$BASE" "$HEAD_SHA"; then
  note "setup: could not fetch the two commits"
  exit 0
fi
git -C "$SRC" -c core.hooksPath=/dev/null checkout -q "$HEAD_SHA"

# Dependencies come from the new commit. Each attempt may fail, and a suite that cannot
# then import what it needs comes back unverified, which is the honest result.
python -m venv "$DEPS"
PIP="$DEPS/bin/pip"
PY="$DEPS/bin/python"
timeout 300 "$PIP" install -q --upgrade pip uv || note "setup: pip did not upgrade"
timeout 600 "$PIP" install -q pytest pytest-asyncio pytest-mock pytest-timeout || note "setup: pytest did not install"
cd "$SRC" || exit 0
while IFS= read -r req; do
  timeout 600 "$PIP" install -q -r "$req" || note "setup: $req did not install"
done < <(find . -maxdepth 3 -type f \( -name 'requirements*.txt' -o -name '*-requirements.txt' \) -not -path './.git/*' | sort)
while IFS= read -r proj; do
  dir="$(dirname "$proj")"
  installed=no
  if timeout 600 "$PIP" install -q "$dir" 2>/dev/null; then installed=yes; fi
  # Every optional and development group the project declares. Tests usually need one of them.
  while IFS= read -r spec; do
    [ -n "$spec" ] || continue
    timeout 300 "$PIP" install -q "$spec" 2>/dev/null || note "setup: $dir: $spec did not install"
  done < <("$PY" - "$proj" <<'DECLARED' 2>/dev/null
import sys, tomllib
data = tomllib.load(open(sys.argv[1], "rb"))
groups = list(data.get("project", {}).get("optional-dependencies", {}).values()) + list(data.get("dependency-groups", {}).values())
for group in groups:
    for spec in group:
        if isinstance(spec, str):
            print(spec)
DECLARED
)
  note "setup: $dir: project install: $installed"
done < <(find . -maxdepth 3 -type f -name pyproject.toml -not -path './.git/*' | sort)
[ -f setup.py ] && { timeout 600 "$PIP" install -q . 2>/dev/null || note "setup: setup.py did not install"; }
cd - >/dev/null || exit 0

# Each tree is a plain copy of the files, so its own code has to come first on the path.
CMD='PYTHONPATH=.:src python -B -m pytest -q -p no:cacheprovider --timeout=60 --continue-on-collection-errors --junit-xml=agentsec-results.xml'

# An empty network namespace with only loopback, so the tests cannot reach anything.
sudo unshare --net -- sh -c '
  ip link set lo up
  if "$2/python" -c "import socket; socket.create_connection((\"1.1.1.1\", 443), 5)" 2>/dev/null; then
    echo "setup: network check: REACHED 1.1.1.1 from the test namespace" >> "$9/$8.setup.txt"
    exit 1
  fi
  echo "setup: network check: no route out of the test namespace" >> "$9/$8.setup.txt"
  exec sudo --preserve-env=PATH -u "$1" env PATH="$2:$PATH" "$3" verify --repo "$4" --base "$5" --head "$6" \
    --test-cmd "$7" --junit agentsec-results.xml --timeout 480 --label "$8" --out "$9"
' sh "$(id -un)" "$DEPS/bin" "$TOOL" "$SRC" "$BASE" "$HEAD_SHA" "$CMD" "$LABEL" "$OUT"
echo "verify exit: $?"
exit 0
