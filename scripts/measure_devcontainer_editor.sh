#!/usr/bin/env bash
# Measure a dev container as VS Code attaches to it, on a disposable machine.
#
#   bash scripts/measure_devcontainer_editor.sh <scratch dir>
#
# Installs VS Code and the Dev Containers extension, opens a folder in a container under a
# virtual display, and lets a task that runs on opening the folder run the probe, in the
# environment an editor terminal gets. A throwaway SSH agent and git identity exist so there
# is something to forward. Needs sudo, Docker, and agentsec on PATH. Do not run it on your
# own machine: it installs packages and starts an agent with a throwaway key.
set -uo pipefail

IMAGE=mcr.microsoft.com/devcontainers/python:3.12
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mkdir -p "$1" && cd "$1" && pwd)"
OUT="$REPO/examples/devcontainer"
LOGS="$REPO/editor-logs"
DIR="$WORK/project"
mkdir -p "$OUT" "$LOGS" "$DIR/.devcontainer" "$DIR/.vscode" "$WORK/user/User"

curl -fsSL -o "$WORK/code.deb" https://update.code.visualstudio.com/latest/linux-deb-x64/stable || exit 1
sudo apt-get update -qq && sudo apt-get install -y -qq xvfb "$WORK/code.deb" > /dev/null || exit 1
CODE=(code --user-data-dir "$WORK/user" --extensions-dir "$WORK/ext" --no-sandbox --disable-gpu)
"${CODE[@]}" --install-extension ms-vscode-remote.remote-containers --force || exit 1
VSCODE_VERSION="$("${CODE[@]}" --version | head -1)"
EXTENSION="$("${CODE[@]}" --list-extensions --show-versions | grep remote-containers)"
echo "VS Code $VSCODE_VERSION, $EXTENSION"

docker pull -q "$IMAGE" > /dev/null || exit 1
DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE")"
[ -n "$DIGEST" ] || { echo "no digest for $IMAGE"; exit 1; }

cp "$REPO/agentsec/probe/blast_probe.py" "$DIR/agentsec_probe.py"
printf '{"image": "%s"}\n' "$IMAGE" > "$DIR/.devcontainer/devcontainer.json"
cat > "$DIR/.vscode/tasks.json" <<'JSON'
{"version": "2.0.0", "tasks": [{"label": "probe", "type": "shell",
  "command": "python3 agentsec_probe.py > probe.tmp 2> probe.err; env | cut -d= -f1 | sort > env-names.txt; ls -a /tmp > tmp-names.txt; mv probe.tmp probe.json",
  "runOptions": {"runOn": "folderOpen"}}]}
JSON
cat > "$WORK/user/User/settings.json" <<'JSON'
{"security.workspace.trust.enabled": false, "task.allowAutomaticTasks": "on", "telemetry.telemetryLevel": "off", "update.mode": "none"}
JSON

# Something for the editor to forward. Throwaway, and gone with this machine.
eval "$(ssh-agent -s)" > /dev/null
ssh-keygen -q -t ed25519 -N '' -f "$WORK/throwaway"
ssh-add -q "$WORK/throwaway"
git config --global user.name "throwaway"
git config --global user.email "throwaway@example.invalid"

HEX="$(printf '%s' "$DIR" | xxd -p -c 2000)"
xvfb-run -a "${CODE[@]}" --wait --verbose --folder-uri "vscode-remote://dev-container+$HEX/workspaces/project" > "$LOGS/code.log" 2>&1 &
EDITOR_PID=$!
for _ in $(seq 1 90); do
  [ -s "$DIR/probe.json" ] && break
  kill -0 "$EDITOR_PID" 2> /dev/null || { echo "the editor exited early"; break; }
  sleep 10
done
cp "$DIR/env-names.txt" "$DIR/tmp-names.txt" "$DIR/probe.err" "$LOGS/" 2> /dev/null
find "$WORK/user/logs" -name '*.log' -print0 2> /dev/null | tar -czf "$LOGS/vscode-logs.tgz" --null -T - 2> /dev/null
kill "$EDITOR_PID" 2> /dev/null
[ -s "$DIR/probe.json" ] || { echo "no probe report, so nothing was measured"; tail -20 "$LOGS/code.log" | cut -c1-300; exit 1; }
echo "== variable names in the editor's environment that a CLI run would not have"; grep -E 'VSCODE|REMOTE_CONTAINERS|SSH_AUTH|GIT_' "$LOGS/env-names.txt"
echo "== names in /tmp"; cat "$LOGS/tmp-names.txt"

agentsec score "$DIR/probe.json" --label devcontainer-editor-default --redact --out "$OUT" \
  --how "VS Code $VSCODE_VERSION with $EXTENSION, $DIGEST, no other settings. The folder was opened in the container under a virtual display, and a task that runs on opening the folder ran the probe, on a GitHub-hosted ubuntu-latest machine with a throwaway SSH agent and git identity. Run by scripts/measure_devcontainer_editor.sh. The machine holds no personal credentials, so this shows what is forwarded, not what a person's forwarded credentials could do."
