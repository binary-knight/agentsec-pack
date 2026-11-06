#!/usr/bin/env bash
# Measure what a process gets inside a dev container, through the real devcontainer CLI.
#
#   bash scripts/measure_devcontainer.sh <scratch dir>
#
# Each configuration below goes through `devcontainer up`, and the probe runs through
# `devcontainer exec`, which is how a command reaches the container. This pulls images and
# starts containers on this machine's Docker daemon. Needs Node, Docker, and agentsec on PATH.
set -uo pipefail

CLI_VERSION=0.90.0
IMAGE=mcr.microsoft.com/devcontainers/python:3.12
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mkdir -p "$1" && cd "$1" && pwd)"
OUT="$REPO/examples/devcontainer"
CLI=(npx --yes "@devcontainers/cli@$CLI_VERSION")
mkdir -p "$OUT"
# Pulled up front, because an image the CLI pulls through BuildKit may not record a digest.
docker pull -q "$IMAGE" > /dev/null || exit 1
DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE")"
[ -n "$DIGEST" ] || { echo "no digest for $IMAGE"; exit 1; }

measure() {  # name, the rest of devcontainer.json, how it differs
  local name="$1" config="$2" differs="$3" dir="$WORK/$1"
  mkdir -p "$dir/.devcontainer"
  printf '{"image": "%s"%s}\n' "$IMAGE" "$config" > "$dir/.devcontainer/devcontainer.json"
  cp "$REPO/agentsec/probe/blast_probe.py" "$dir/agentsec_probe.py"
  echo "== $name"
  if ! "${CLI[@]}" up --workspace-folder "$dir" > "$WORK/$name.up.log" 2>&1; then
    echo "   devcontainer up failed:"; grep -iE "error|denied|failed" "$WORK/$name.up.log" | tail -25 | cut -c1-400
    return
  fi
  "${CLI[@]}" exec --workspace-folder "$dir" python3 agentsec_probe.py > "$WORK/$name.json" 2> "$WORK/$name.err" \
    || { echo "   the probe did not finish:"; tail -5 "$WORK/$name.err"; }
  agentsec score "$WORK/$name.json" --label "devcontainer-$name" --redact --out "$OUT" \
    --how "devcontainer CLI $CLI_VERSION, $DIGEST, $differs. devcontainer up, then the probe through devcontainer exec, on a GitHub-hosted ubuntu-latest machine. Run by scripts/measure_devcontainer.sh. The CLI was used, not an editor, so nothing an editor forwards into the container is included." || true
}

measure default '' "no other settings"
measure hardened ', "runArgs": ["--cap-drop=ALL", "--security-opt=no-new-privileges"]' "runArgs --cap-drop=ALL --security-opt=no-new-privileges"
measure docker-socket ', "mounts": ["source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"]' "the host's Docker socket mounted into the container"
echo "reports: $OUT"
