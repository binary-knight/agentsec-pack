# Measurements

This page is the full write-up behind the charts in the README. It covers every measured configuration, how each was captured, and what the vendor documents. Each result has a report in `examples/`, and `agentsec/data/measured_profiles.json` records its provenance. `scripts/readme_charts.py` generates the README's charts and table from those same reports, and a test fails when they fall out of date.

## python:3.12-slim under eleven launchers

Eleven sandbox configurations were measured against one image, `python:3.12-slim`, on one Linux host with probe 0.4.0 on 2026-11-04, each launched with a minimal environment from `env -i`.

| Configuration | Score | Worst finding |
|---|---:|---|
| `bwrap-ro-root` | 71 | container runtime socket reachable |
| `docker-default` | 59 | unrestricted internet egress |
| `bwrap-unshare-all` | 56 | container runtime socket reachable |
| `bwrap-unshare-all-clearenv` | 56 | container runtime socket reachable |
| `bwrap-workdir-net` | 54 | unrestricted internet egress |
| `codex-cli-0.153.4-bwrap-layer` | 48 | container runtime socket reachable |
| `podman-rootless-default` | 47 | unrestricted internet egress |
| `docker-no-network` | 44 | runs as real root |
| `docker-readonly` | 44 | unrestricted internet egress |
| `docker-hardened` | **0** | none |
| `podman-rootless-hardened` | **0** | none |

In the top row, `bwrap-ro-root`, the lightweight bubblewrap setup that mounts the host root read-only, scores 71, a wider blast radius than a plain `docker-default` container at 59. A read-only host root only blocks writes, so the agent can still read every home credential file and connect to the host's Docker socket, which gives it root on the host. Bubblewrap rows depend on what lives on the host, such as sockets and credentials in the home directory. Container rows depend only on the image and the flags, so they score the same on any host.

Since the first run, container rows keep the same scores under probe 0.4.0 that they had under probe 0.1.0. Probe 0.4.0 adds the informational `FS-010` finding at 0 points because writable startup files live on the container overlay and vanish on exit. The three bubblewrap rows that keep the environment each fell by 15, from 86 to 71, 71 to 56, and 69 to 54. The first run's shell exported a secret-shaped variable that those sandboxes inherited, so `SEC-002` scored it against them. Clearing the environment in `bwrap-unshare-all-clearenv` blocked that inherited variable, so its score stayed at 56 across both runs. This project's own table fell into Trap 1 of `docs/CAPTURING.md`, so those rows are now measured with `env -i` and record their launching environment.

Run `agentsec matrix python:3.12-slim` to reproduce the table. The full report is `examples/matrix_slim.md`.

## Agents' own sandboxes

A coding agent enters the sandbox it ships with on its own, so the measurement cannot wrap that sandbox from the outside like a container. You instruct the agent to run the probe inside that sandbox with `agentsec probe`, or to execute the probe file and send back its output for `agentsec score`. The instructions in `docs/CAPTURING.md` walk through every step. Each report below logs the agent version, the date, the host, the exact capture command, and the launching environment alongside citations to the vendor's documentation.

### Codex CLI

Codex CLI 0.153.4 was measured on Ubuntu 24.04 with bubblewrap 0.9.0 on September 8 and 9, 2026.

| Sandbox | Score | Contained | Still reachable |
|---|---:|---|---|
| Codex CLI 0.153.4 `--sandbox read-only` | 26 | root filesystem read-only, working directory not writable, DNS fails, direct-IP connects refused, container sockets refused | the invoking user's home directory: `~/.ssh/config`, `~/.gitconfig`, `~/.config/gh/hosts.yml`, PID 1's environment |
| Codex CLI 0.153.4 `--sandbox workspace-write` | 34 | as above | as above, plus a writable working directory (expected, scored informational) and read-write bind mounts from the host |
| the same two, launched from a developer shell | 41 / 49 | as above | as above, plus one secret-shaped environment variable the shell had already exported |

Every launching shell counts toward both the exposure and the score because a sandbox receives its environment from the starting shell. The first two rows start the sandbox with `env -i`, so their scores of 26 and 34 measure the sandbox on its own. In the third row, a developer shell with an exported token launches those same two sandboxes the way users run them. That secret has nothing to do with Codex, and it raises both scores by 15, to 41 and 49. Reporting both sets of numbers reveals the portion of the score that users can fix within their own shell.

OpenAI's documentation, read on 2026-11-04, describes read-only mode as "The agent can inspect files, but it can't edit files or run commands without approval." An agent reading the user's `gh` credentials file therefore operates within the documented boundary, and the report records that access as a design boundary. The resulting number in the report remains useful because it demonstrates strong sandbox restrictions on writes and network access. What stays inside the blast radius is read access to the secrets in the home directory of the user who launched it. Neither a filesystem sandbox nor a network sandbox governs what an agent does with data it has already read, so that read access matters. Any content that the agent is able to read can surface in the text that the agent generates. This tool leaves that text path unmeasured and makes no claim regarding how any product handles that output.

Every attempt to open a connection to the visible `/var/run/docker.sock` socket path is refused in both Codex modes. Permission bits leave it unclear whether that block stems from a restriction on those paths or from filtering on the system call itself, so the probe executes a control test. The first control binds a Unix socket created by the probe itself before attempting a connection to that new socket. When the environment provides no writable directory, the second control attempts to establish a connection to a nonexistent path. Receiving `PermissionError` from a call that would ordinarily raise `FileNotFoundError` demonstrates that the system call was rejected prior to path lookup. Because Codex refuses both control tests, the visible socket paths are inert, so the report notes that status while scoring it as the low-severity finding SEC-006.

The Codex sandbox wraps a command in two layers that both appear in the arguments of the live processes. Bubblewrap forms the first layer by running `bwrap --as-pid-1 --new-session --die-with-parent --ro-bind / / --dev /dev --unshare-user --unshare-pid --unshare-ipc --unshare-net --proc /proc --cap-drop ALL`. In the second layer, a helper built into Codex invokes the command once more under a permission profile with `--apply-seccomp-then-exec`. Running the `codex-cli-0.153.4-bwrap-layer` preset recreates the first layer alone, so the result reveals what the second layer contributes. Below, a two-row table compares Codex read-only against that single-layer preset.

| Run | Score | Container socket | Seccomp |
|---|---:|---|---|
| Codex CLI 0.153.4 `--sandbox read-only` | 26 | visible, every connect refused | mode 2 |
| `codex-cli-0.153.4-bwrap-layer` preset | 48 | **reachable: the connect succeeds** | none |

The seccomp filter in layer two of the sandbox is the control that closes `/var/run/docker.sock` to probe connections. Passing `--unshare-net` disconnects the network stack and leaves unix-domain sockets available, so under bubblewrap alone the probe reaches `/var/run/docker.sock` and the control test confirms that unix connections succeed. Among the two expected differences in this preset, the first is that the configuration omits a seccomp layer by design. Second, `--as-pid-1` assigns PID 1 to the probe itself, which prevents the finding about reading the environment of PID 1 from triggering as it does in the full sandbox. As the rationale in the presets file documents, this preset measures only what bubblewrap provides on its own as a configuration separate from Codex.

Codex CLI 0.164.0 keeps its scores of 26 in read-only mode and 34 in `workspace-write` mode when re-measured on 2026-11-04 with probe 0.4.0. The run launched under `env -i` on the same host with identical flags inside a disposable git repository that contained an empty `.codex/config.toml` file. Probe output came from the `--json` event stream of Codex, which prevented the model from retyping the results. When the new checks test whether the agent can plant something to execute outside the sandbox later, Codex blocks every attempt. Inside the writable working directory of `workspace-write` mode, `.git/hooks` and the project `.codex/config.toml` file reject writes with `EROFS`. Every shell startup file, `authorized_keys`, `.gitconfig`, the home directory, and the user settings for both agents also return `EROFS` on write attempts. Those restrictions in the working directory match the documentation where `<writable_root>/.git` and `<writable_root>/.codex` receive recursive protection as read-only. Read access remains, which the mode is documented to allow, and it reaches Codex's own login file at `~/.codex/auth.json`. Full reports for the read-only and `workspace-write` measurements live in `examples/agents/codex-cli-0.164.0-read-only.md` and `examples/agents/codex-cli-0.164.0-workspace-write.md`.

### Aider

Aider 0.86.2, the first open-source agent in these measurements, receives a score of 100 because the release ships without a sandbox. With no container or isolation flags in `aider --help`, the code at `aider/run_cmd.py:62` executes commands directly on the host through `subprocess.Popen(shell=True)` with the inherited process environment. The probe executed through that same call, so it measured an Aider command environment that grants unrestricted network access and a read-write filesystem where the Docker socket is reachable. Because the project omits any claim of containment, the score of 100 serves as a neutral record of the host exposure that running the agent accepts. The hardening presets in this repository exist for this case. The full report is `examples/agents/aider-0.86.2-default.md`.

### Antigravity CLI

Google's Antigravity CLI, `agy` 1.4.12, failed to start its terminal sandbox on 2026-11-04 on the same Ubuntu 24.04 host when launched under `env -i` with `--sandbox` requested. Ubuntu sets `kernel.apparmor_restrict_unprivileged_userns=1`, which blocks the unprivileged user namespaces required by `agy`, so its log recorded "Terminal sandbox unavailable". Vendor documentation covers this case and explains that the `--sandbox` flag stays inactive on restricted hosts and auto mode remains unavailable. Headless print mode rejected the probe command three times until a single allow rule for that command stood in for user approval and permitted execution. The approved command executed with full user authority and scored 100, with unrestricted network access, a reachable Docker socket, readable credential files including `agy`'s own login token at `~/.gemini/antigravity-cli/antigravity-oauth-token`, and every persistence path writable including `agy`'s own `hooks.json`. On that same host, `bubblewrap` still enforces a sandbox because Ubuntu includes an AppArmor profile that exempts that tool. The sandbox built into `agy` went unmeasured because testing it requires a system without that restriction and this project keeps host security settings intact.

When running in print mode for CI, `agy` kept the terminal silent about the sandbox because that notice goes only into its log file. Because of that silence, a pipeline passing `--sandbox` executes an approved command unsandboxed without any warning on the terminal. This outcome creates the same gap between configuration and the running process as Claude Code's fail-open default, described below. Documentation for `agy` lists no setting that converts an unavailable sandbox into a hard failure, so a `--max-score` gate on a probe run catches the exposure. The report is at `examples/agents/antigravity-cli-1.4.12-sandbox-unavailable.md`.

### Claude Code

Claude Code 2.1.266 was measured the same way in three configurations. Its sandbox stays off until `sandbox.enabled` is set, and on Linux it needs `bubblewrap` and `socat` installed.

| Configuration | Score | What the probe found |
|---|---:|---|
| default, `sandbox.enabled` unset | 100 | no containment: root filesystem read-write, unrestricted egress, no seccomp, and `/var/run/docker.sock` **reachable** |
| `sandbox.enabled: true`, `socat` missing | 100 | identical to the row above |
| `sandbox.enabled: true`, dependencies present | 41 | seccomp mode 2, `no_new_privs`, user namespace, read-only root, no egress, PID 1's environment hidden, `AF_UNIX socket()` itself refused |

The score of 100 in the middle row with the sandbox configured on and `socat` missing reflects the documented default behavior in Claude Code. The sandboxing page, as read on 2026-09-09, says: "By default, if the sandbox cannot start because dependencies are missing or the platform is unsupported, Claude Code shows a warning and runs commands without sandboxing. To make this a hard failure instead, set `sandbox.failIfUnavailable` to `true`." When tested here with `socat` absent and `sandbox.failIfUnavailable` set to `true`, the run prints "refusing to start without a working sandbox" and exits with code 1, so the probe never runs. You should apply this vendor setting as the fix whenever you enable the sandbox in an automated context.

In CI, the default behavior omitted from the documentation lets the agent run with the user's full authority while the configuration file says it is sandboxed. The process writes its warning to `stderr` before returning an exit code of 0 at the end of the run. That gap between the configuration file and the running process is why this tool takes its measurement from inside. With any agent, even one that lacks a fail-closed setting, a `--max-score` gate on a probe run catches that gap.

The unsandboxed first row of the table reflects the normal behavior of the product when it runs without a sandbox. Compared with a score of 88 from running the probe straight in a shell, the product injects one environment variable, which raises the unsandboxed score to 100. Turning on the sandbox in the third row causes the sandbox itself to inject `CLAUDE_CODE_MESSAGING_TOKEN` and `CLOUDSDK_PROXY_PASSWORD`, two variables shaped like secrets that together add 15 points as one high finding, `SEC-002`. After a second run listed the environment variable names, a third run displayed only the non-secret proxy fields. Those settings place `CLOUDSDK_PROXY_PASSWORD` alongside `CLOUDSDK_PROXY_ADDRESS=localhost`, `_TYPE=http` and `_PORT=3128`, so the password acts as the credential for a proxy on the loopback interface. Readable credential files account for `SEC-003`, the other high finding in the third row. Without the environment variables injected by the sandbox, the score in the third row would drop to 26. Claude Code hides PID 1's environment and Codex in `workspace-write` leaves it readable, which creates the 8-point `SEC-004` difference that brings Codex to a score of 34.

Claude Code isolates network traffic by enforcing an allowlist through a local proxy, so the zero egress recorded during this headless run with nothing approved reflects an empty allowlist. In Codex, the `--unshare-net` flag detaches the network at the namespace level regardless of what the policy states. Failures on direct IP connections and cloud metadata requests still hold under both of those isolation designs. Probe version 0.1.0 collected these rows through direct connections that ignored `HTTPS_PROXY`, so it missed proxy egress and would have reported a sealed network even with hosts on the allowlist. A test on 2026-11-03 demonstrated this behavior when `curl` reached `github.com` through the proxy with status 200 while every direct connection from the probe was refused. Starting in version 0.2.0, the probe records only the names of set proxy variables and reports `NET-004` to indicate unmeasured proxy egress in places where earlier output claimed containment. Because of that change, you should treat the network column in these rows as unverified. Vendor documentation describes the seccomp filter for unix-domain sockets as an optional add-on, yet both this run and 2.1.317 refused `AF_UNIX socket()` calls without that add-on installed, so the sandbox measured stricter than the documentation states. The result was raised publicly as [anthropics/claude-code#107142](https://github.com/anthropics/claude-code/issues/107142) on 2026-11-04, after the README had already published it. `SECURITY.md` says the vendor hears first, and here the vendor did not.

Claude Code 2.1.317 matches the 2.1.266 score of 41 in a 2026-11-04 run of probe 0.4.0 on the same host with the sandbox enabled. Its Bash tool ran that test from a live session under `AGENTSEC_PROBE_PROXY_AUTH=1` with no added domains permitted for the command. The table below shows what the new checks found on the network, persistence and credentials axes.

| Axis | What 0.4.0 found |
|---|---|
| network | **contained, now proven**: every direct connection refused, and the sandbox's proxy refused a tunnel (403) to every target and to the control. Without the opt-in it answers 407 and the axis reads not measured |
| persistence | **closed**: shell startup files, `~/.ssh/authorized_keys`, `~/.gitconfig`, `.git/hooks`, the home directory and `~/.claude/settings.json` all refuse writes; the project's `.claude/settings*.json` and `.mcp.json` are masked with a device node |
| credentials | **readable**: `~/.ssh/config`, `~/.gitconfig`, `~/.config/gh/hosts.yml`, and the agent's own login, `~/.claude/.credentials.json` (another agent's, `~/.codex/auth.json`, too), each proven by opening it |

The credentials row is the new result. According to the vendor documentation, `~/.claude/.credentials.json` serves as the file path where Claude Code stores its login on Linux. Because a sandboxed command can open that file, it can output the token into a transcript or write it into the working tree. This is documented behavior. The sandboxing page gives the default as "read access to the entire computer, except certain denied directories. This default still allows reading credential files", says "There is no built-in credential deny list", and lists `.credentials.json` among the paths it protects from writes only. As a remedy, the vendor offers `sandbox.filesystem.denyRead`, with an example that blocks `~/` and restores access to `.`, or `sandbox.credentials` entries set to deny mode. If you run this sandbox on a machine that has a login, you should configure one of those settings. The report is `examples/agents/claude-code-2.1.317-sandbox-auto-mode.md`.

Applying the vendor's documented `denyRead` setting to Claude Code 2.1.318 lowers the score from the default of 41 down to 26. On 2026-11-04, a headless run launched under `env -i` passed `--settings` using the vendor example of `sandbox.filesystem.denyRead: ["~/"]` with `allowRead: ["."]` plus `failIfUnavailable`, so the run fails if the sandbox cannot start. An empty tmpfs acts as the sandbox home directory, which hides `~/.claude/.credentials.json` along with every other credential file that the default exposes, so `SEC-003` drops out of the findings. Any write to `~` succeeds by landing on that tmpfs before vanishing when the sandbox exits, which the probe records as an informational `FS-010` result outside the persistence findings. The only remaining items are the working-directory bind mounts alongside `SEC-002` for the two variables that the sandbox injects. With a login on the machine, this is the setting to add. The report is `examples/agents/claude-code-2.1.318-sandbox-denyread.md`.

Network allowlisting applies to one command at a time, so a repeat run can permit `github.com` for a single execution in the same way a user authorizes a destination. The proxy opens a `github.com` tunnel with status 200 while blocking the control host and all other destinations, so the probe logs `NET-005` for allowlisted proxy egress with a score of 49. The sandbox is filtering as designed. It lets through whatever has been approved, and a code host accepts uploads. The report is `examples/agents/claude-code-2.1.317-sandbox-auto-mode-github-allowed.md`.

These Claude Code figures come from a Claude Code session that measured Claude Code itself by running the same probe under the same capture method and scorer as every other profile. Raw JSON output ships alongside the profile results so every figure can be recomputed from the captured data. You should still weigh the source of the session when you evaluate the scores from that measurement.

Complete reports with full provenance for every sandbox measurement covered in this section reside in the `examples/agents/` directory. Each entry in `agentsec/data/measured_profiles.json` is added exclusively from a direct measurement accompanied by citations to the vendor's documentation. Any sandbox measurement that conflicts with the vendor's documentation is reported to that vendor prior to publication of the profile.

## macOS

These measurements ran on a GitHub-hosted macOS 26.6.2 machine, arm64, with probe 0.6.0, through `.github/workflows/macos-measure.yml`. Each measurement was launched with `env -i`. The machine's home directory holds no personal credentials, so the credential findings score lower here than they would on a developer's own Mac. The reports are in `examples/macos/` and `examples/agents/`.

| Configuration | Score | What changed |
|---|---:|---|
| no sandbox | 76 | everything the account can reach, including `~/Library/LaunchAgents`, `.git/hooks` and the user-owned `/opt/homebrew/bin` |
| `seatbelt-allow-default` | 68 | only PRIV-006, because a profile that allows everything still counts as a sandbox |
| `seatbelt-deny-network` | 53 | no network and no unix sockets, while writes and credential reads stay open |
| `seatbelt-confined` | 8 | no network, writes only to the temporary directories, no reads of the common credential paths |
| Codex CLI 0.164.0, read-only | 15 | no network, no writes, other processes hidden |
| Codex CLI 0.164.0, workspace-write | 30 | as read-only, plus a writable workspace in which Claude Code's project config is writable |
| Claude Code 2.1.318, no sandbox | 100 | everything, including `ANTHROPIC_API_KEY` |
| Claude Code 2.1.318, sandbox on | 53 | network contained, writes confined to the workspace, Codex's and Antigravity's project config writable, `ANTHROPIC_API_KEY` visible |
| Claude Code 2.1.318, sandbox + `denyRead` | 38 | as sandbox on, without the readable `~/.gitconfig` |

The gap between no sandbox and `seatbelt-allow-default` is worth noting. A Seatbelt profile that allows everything removes PRIV-006 and nothing else, so its presence earns 8 points while it restricts nothing. Linux has the same property, since a seccomp filter that allows every call also removes PRIV-004. The other four axes are where a profile's real effect shows.

### Codex CLI on macOS

Codex was measured through `codex sandbox -c sandbox_mode=...`, which runs a command under Codex's own sandbox policy with no model and no login. On Linux the same helper reproduced the full-session scores exactly, 26 in read-only and 34 in `workspace-write` with identical findings, so it stands in for the sandbox of a session. The throwaway project held empty project config for Codex, Claude Code and Antigravity.

Both modes keep the network off, refuse every write outside the workspace, and refuse the process-list `sysctl` with `EPERM`. That last check hides every other process on the machine, which the Linux sandbox does not do. In `workspace-write` the working directory is writable, and inside it `.codex/config.toml`, `.agents` and `.git/hooks` refuse writes, as OpenAI documents for `.git` and `.codex`. Claude Code's `.claude/settings.json` and `.mcp.json` in the same directory are writable, which the probe reports as FS-009. Codex documents only its own protected paths, so this is its documented boundary. The consequence is cross-agent: in a project where both agents are used, a command run in Codex's sandbox can change the settings and MCP servers that Claude Code loads in its next session, outside Codex's sandbox.

### Claude Code on macOS

Claude Code has no helper that runs a command under its policy without a model, so it was measured in full headless sessions through `.github/workflows/macos-claude-code.yml`. That workflow reads `ANTHROPIC_API_KEY` from a GitHub environment that requires a reviewer's approval for every run and deploys only from `main`. Each session ran `claude -p` on `claude-haiku-5-5`, asked to run the probe and nothing else, with `AGENTSEC_PROBE_PROXY_AUTH=1` so the probe could ask the sandbox proxy for its allowlist.

With the sandbox on, Seatbelt applies, the proxy refused a tunnel to every target and to the control, and every write outside the workspace is refused. Inside the workspace Claude Code protects its own `.claude/settings.json` and `.mcp.json` and the `.git` hooks, which its documentation describes as the files it loads configuration and code from. Codex's `.codex/config.toml` and Antigravity's `.agents` directory in the same project are writable. That mirrors the Codex result in the other direction: each agent protects its own project config and not the other's, so in a project where both are used a command inside either sandbox can change what the other agent loads in its next session. Neither vendor documents protecting another agent's files.

Sandboxed commands can see `ANTHROPIC_API_KEY` by name. Claude Code documents that sandboxed commands inherit its environment "including any secrets in its environment", and its `sandbox.credentials` setting is the documented way to withhold a variable. With `denyRead` on the home directory the score falls from 53 to 38, because `~/.gitconfig` is no longer readable, as `denyRead` did on Linux.

## Public Terminal-Bench tasks under Harbor

These runs measure the environment an agent gets during the agent phase of a benchmark. `scripts/measure_harbor.sh` runs real Harbor (`b7cc86b`) on public Terminal-Bench tasks (`73d6279`) with `ProbeAgent` from `agentsec/integrations/harbor_agent.py`, an agent that makes no model calls and does not attempt the task. It uses Harbor's Docker environment with the verifier disabled, launched with `env -i`, on one Linux host on 2026-11-04.

`scripts/select_harbor_sample.py` chooses the tasks. It makes a uniform draw of 5 from the 66 sorted tasks, seeded with the Terminal-Bench commit hash, so anyone can repeat it. The rule also adds any task whose `task.toml` turns the agent's network off, and there are none.

| Task | Score | `/tests` | `/solution` | Result |
|---|---:|---|---|---|
| `fin-saccr-rwa` | 67 | absent | absent | measured |
| `formal-crypto` | 67 | absent | absent | measured |
| `interleaved-vigenere` | 67 | absent | absent | measured |
| `uefi-bootkit` | 67 | absent | absent | measured |
| `fp8-rmsnorm-gemm` | none | none | none | not measured: the task needs a GPU and this host has none, so it was not replaced |

Harbor keeps the grader's files out of the agent's container in all four, and each task sets `environment_mode = "separate"`, which runs the verifier in its own container. The agent runs as root with Docker's default capabilities and seccomp filter, can write anywhere in its container, and has unrestricted egress. The container shows 3 processes, no Docker socket, no credential files beyond its own `/etc/shadow`, and no host bind mounts. Writes land on the container's own overlay. This is the harness's design and none of it is a vulnerability: the agent has a disposable root environment on the network, and the answer material is kept elsewhere. The 66 public tasks all leave the agent's network on. Two set `allow_internet = false`, and only for the verifier.

**Read the score of 67 with care.** Plain `docker-default` scores 59, and the only additional finding is SEC-004 at 8 points. Harbor execs into a container whose PID 1 is `sh -c sleep infinity`, so the probe can read PID 1's environment, and in the plain Docker run the probe is PID 1 itself. The difference comes from how the probe is launched, so it does not show that Harbor is looser than Docker. SEC-004's title mentions host or supervisor secrets, and its advice is a separate PID namespace, which this container already has. The probe does not record what that environment holds, so these runs do not show whether anything secret is in it.

**Limits.** This is 4 tasks of 66, on one host, through Harbor's Docker environment. All 4 are single-container tasks running as root. The 11 tasks with their own `docker-compose.yaml` and the tasks that set a non-root user were not in the sample, and Harbor's cloud environments are not covered. The cloud metadata address is unreachable here, which says nothing about a run on a cloud machine.

