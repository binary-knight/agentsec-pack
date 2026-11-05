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
# then import what it needs comes back failing or unverified, which is the honest result.
python -m venv "$DEPS"
PIP="$DEPS/bin/pip"
timeout 600 "$PIP" install -q pytest pytest-asyncio pytest-mock pytest-timeout || note "setup: pytest did not install"
for req in requirements.txt requirements-dev.txt requirements-test.txt dev-requirements.txt test-requirements.txt; do
  [ -f "$SRC/$req" ] && { timeout 600 "$PIP" install -q -r "$SRC/$req" || note "setup: $req did not install"; }
done
if [ -f "$SRC/pyproject.toml" ] || [ -f "$SRC/setup.py" ]; then
  installed=no
  for extra in "[dev,test]" "[dev]" "[test]" "[tests]" ""; do
    if timeout 600 "$PIP" install -q "$SRC$extra" 2>/dev/null; then installed="yes$extra"; break; fi
  done
  note "setup: project install: $installed"
fi

# Each tree is a plain copy of the files, so its own code has to come first on the path.
CMD='PYTHONPATH=.:src python -B -m pytest -q -p no:cacheprovider --timeout=120'

# An empty network namespace with only loopback, so the tests cannot reach anything.
sudo unshare --net -- sh -c '
  ip link set lo up
  exec sudo --preserve-env=PATH -u "$1" env PATH="$2:$PATH" "$3" verify --repo "$4" --base "$5" --head "$6" \
    --test-cmd "$7" --timeout 480 --label "$8" --out "$9"
' sh "$(id -un)" "$DEPS/bin" "$TOOL" "$SRC" "$BASE" "$HEAD_SHA" "$CMD" "$LABEL" "$OUT"
echo "verify exit: $?"
exit 0
