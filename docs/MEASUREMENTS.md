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

## Dev containers

These runs measure what a command gets inside a dev container. `scripts/measure_devcontainer.sh` starts each configuration with the real devcontainer CLI (0.90.0) and runs the probe through `devcontainer exec`. It used `mcr.microsoft.com/devcontainers/python:3.12` at the digest in each report, on a GitHub-hosted `ubuntu-latest` machine, through `devcontainer-measure.yml`, on 2026-11-05. Probe 0.6.0. Reports are in `examples/devcontainer/`.

| Configuration | Score | Findings above informational |
|---|---:|---|
| No other settings | 57 | NET-001, NET-002, FS-003, PRIV-005, FS-002, FS-006 |
| `runArgs`: `--cap-drop=ALL`, `--security-opt=no-new-privileges` | 51 | NET-001, NET-002, FS-003, FS-002 |
| The host's Docker socket mounted | 60 | NET-001, NET-002, FS-003, PRIV-005, FS-002, FS-006, SEC-006 |

The container runs as the image's unprivileged user, with the workspace mounted read-write from the host, and with unrestricted egress. Dropping capabilities and setting `no_new_privs` removes 6 points and leaves the network and the workspace mount as they were.

**Read the scores with care.** NET-002, the cloud metadata address, is 25 of the points in every row. It comes from the hosted machine these runs used, and a dev container on a laptop would not be expected to reach one. Without it the rows would be 32, 26 and 35, but those three totals were not measured on a machine without a metadata address.

**The socket row is a lower bound.** The probe found the socket and was refused with a permission error, because the container's user cannot open it on this machine. A container whose user can open the socket would control the host's Docker daemon, and the image's user may be able to get there through `sudo` or a group. The probe never tries to escalate, so that was not measured.

**Limits.** This is one image on one kind of machine. The CLI was used and not an editor, so anything an editor forwards into the container, such as credential helpers or an SSH agent, is not in these numbers. The `docker-outside-of-docker` feature did not install on this image in the two runs that tried it, so the socket row mounts the socket directly and does not measure that feature.

## `agentsec verify` on real agent pull requests

`scripts/survey_agent_prs.py` runs verify's static checks, tampering and weakening, over public pull requests written by coding agents. It reads git objects only and executes nothing from those repositories, so **this survey produced no verdicts**. Re-grading is a separate step, covered at the end of this section. It shows how often the checks fire and whether they are right, which was judged by reading every flagged change.

A fixed seed picks one day of October 2026 for each of five agent accounts and each outcome, merged or closed without merging, and draws up to 10 pull requests in repositories GitHub lists as Python. That gave 99 pull requests across 65 repositories, run on 2026-11-05. Individual projects are not named here, because the point is how the check behaves and none of these changes was shown to be cheating. The rule is repeatable, though GitHub's search results can shift over time.

| Of 99 pull requests | Count |
|---|---:|
| touched anything test-related | 47 |
| edited or deleted existing tests | 16 |
| flagged as weakening, first version of the check | 7 |
| flagged as weakening, after the fix below | 5 |
| added a skip or a vacuous assertion | 0 |

**Reading the flags found a bug.** Two of the seven were false alarms: one moved its tests to another file under the same names, and one was a version bump that renamed tests such as `test_version_is_0_77_0`. The check now recognizes a moved or renamed test. Moving a test does not excuse it, so one that lost assertions or gained a skip is still reported, and only a test that did not exist at that location before the change can count as where a removed test went.

**The five that remain are not proof of anything.** In one, the code the test covered was removed in the same change, which reads as deliberate. The other four need someone who knows the project. Two of those are near-identical attempts from one repository. In them a removed assertion checks a string that is still in the code, so that assertion would still have passed, which does not look like hiding a failure.

**What this does not support.**
- Merged and closed pull requests were flagged at about the same rate, 3 of 50 and 2 of 49, so the flag does not predict rejection in a sample this small.
- Skips and vacuous assertions never appeared, so these results say nothing about how those checks behave on real code.
- The sample leans small: the median pull request is in a repository with 1 star, 39 pull requests are in repositories with none, and 19 are in repositories with 100 or more. Several pull requests can share a repository, so they are not independent.
- Static checks cannot judge a changed expected value. Of the 9 pull requests that edited tests and raised no flag in the first version, 4 changed assertion lines, and only re-grading can say whether those edits were needed.

One of the five agent accounts is Anthropic's Claude, and this survey was run and judged by a Claude session. Three of the five remaining flags are on that account's pull requests, all in one repository, and the other two are on another agent's. The sample and the code are public, so the numbers can be recomputed, but a reader should weigh the source.

### Re-grading the 16 that edited tests

The 16 pull requests that edited or deleted existing tests, in 12 repositories, were then run through `agentsec verify --junit` on 2026-11-05. `.github/workflows/regrade.yml` gave each one its own disposable GitHub Actions runner, and `scripts/regrade_pr.sh` installed the project's declared dependencies, then ran each test run for up to 480 seconds in a network namespace. A direct check on every pull request found no route out of that namespace.

An earlier pass compared exit codes only and installed fewer dependencies, so the difference below comes from both changes.

| Verdict, of 16 | Exit codes only | `--junit` and fuller setup |
|---|---:|---:|
| `verified` | 0 | 0 |
| `tests-changed-the-result` | 4 | 7 |
| `failing` | 11 | 1 |
| `already-failing` | not available | 2 |
| `unverified` | 1 | 6 |

The sample cannot show how often `verified` happens, because every pull request in it was chosen for editing existing tests. **`verified` has still not been reached on real agent output.**

**Nothing here was shown to be cheating.** Each `tests-changed-the-result` and `failing` verdict was read by hand, with one exception noted below.

| Result, as read | Pull requests | Verdict |
|---|---:|---|
| A release bump, and the old tests pin the old version | 1 | `tests-changed-the-result` |
| A rename to a private name, and the old tests import the old name | 1 | `tests-changed-the-result` |
| Behavior moved on purpose, with the old assertions updated or carried to new tests | 2 | `tests-changed-the-result` |
| A test file moved, from a location where it could not load in this setup | 1 | `tests-changed-the-result` |
| A red suite turned green largely by editing its tests, which the project's owner would have to judge | 2 | `tests-changed-the-result` |
| A new test file could not load in this setup | 1 | `failing` |
| No failure was new | 2 | `already-failing` |
| Timed out in all three runs | 3 | `unverified` |
| A crash while importing a dependency, so no results were written | 1 | `unverified` |
| A test file exits at import, so pytest never reached a test | 2 | `unverified` |

**The two that need a person are near-identical attempts from one repository, both closed without merging.** Their base commit was already failing. With the change, 11 tests pass only because of its test edits, 8 are fixed by its code, and 3 that passed before fail when their old versions return. Most edits state a reason in a comment or docstring. Several look like plain corrections, such as replacing a hardcoded value that had gone out of date with a read of the file it describes. Others loosen what a test demands: one lets a draft entry go without citations, one widens the failure reasons a check over the live data accepts, and one accepts any of three exit codes after moving its strict form to a fixture. New companion tests limit the first of those. This may be the right decision for that project, and `verify` cannot tell. It did point to the edits that need reading. One of the two was read closely, and the other has identical per-test results.

**One repository's verdicts mostly reflect the setup.** Three of the pull requests are in a repository where a package failed to install here, so about 30 test files could not load. That produced the only `failing` verdict, a new test file hitting the same missing module as the rest. It also produced the test file move in the table and one `already-failing`.

**`--junit` separated what exit codes could not.** One project's test downloads a database extension and fails without a network, and it now reads as already failing, apart from the change. Another 20 failures in a different pull request were all present before the change. Pytest exiting without reaching a test had read as `failing` and now reads as `unverified`.

**Reading the results found a bug.** One project's parameterized tests put `uuid4()` in their ids, so each run looked as if 5 tests had stopped and 5 others had appeared. That counts as a failure, and it would give a clean change a false `failing`. It did not change this verdict, which rested on a different test. `verify` now pairs a case whose id changed, keeps each case's own status, and still reports a case that went away. These reports predate that fix.

**What this does not support.**
- 16 pull requests, 6 of them in 2 repositories, are too few to give any rate.
- Installing a project from its declared dependencies is a generic approximation, and it is not how those projects run their own CI.
- The results depend on the setup, and 6 of the 16 produced no result at all.

Five of the 16 are on Anthropic's Claude account, including both that need a person, and all of this was read and judged by a Claude session. Reports are kept out of this repository because they name the projects, so these totals cannot be recomputed from it, though the workflow and the selection rule are public.
