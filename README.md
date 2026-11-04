# agentsec-pack

Installed with `pip install agentsec-pack`, the `agentsec` command measures what an AI agent could reach from inside its sandbox across the network, secrets, the host filesystem, privileges and the other processes on the machine. The sandbox sets the limit on damage because a prompt-injected or mistaken agent can do whatever its sandbox allows. A transcript shows what the agent did, and this tool measures what the sandbox would have let it do.

A small standard-library Python probe inside the sandbox opens credential files, connects to hosts and sockets, writes zero-byte marker files, and reports secret names and paths without values. Refused connections count as contained, and a control test checks whether refusals apply to the entire system call or one path. A scorer turns results into findings with fixed weights and a score from 0 to 100, where 0 means the probe reached nothing. The `--max-score` flag fails a CI build above a budget, `--baseline` fails when anything got worse than an accepted report, and both exit with code 2.

A second test class, verifier integrity, will check whether an agent passed CI by editing the tests. It is listed in [`docs/ROADMAP.md`](docs/ROADMAP.md) and is not built yet.

## How to use this tool

### By hand

```bash
pip install agentsec-pack   # or, from a checkout: uv venv .venv && uv pip install -e '.[dev]'
agentsec presets            # which configurations this host can run right now
```

Hardening an image takes at least two measurements, one of the image as it runs today and one after applying the flags the report recommends.

```bash
# 1. what you run today
agentsec blast-radius docker myagent:latest --label as-i-run-it --print-findings

# 2. apply the flags the report recommends, keeping what your workload needs
agentsec blast-radius docker myagent:latest --label hardened --print-findings -- \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 65534:65534 --tmpfs /tmp --pids-limit 256 --memory 512m

# 3. see what moved
agentsec compare reports/*.json
```

The hardening flags drop a stock `python:3.12-slim` image from 59 on the initial measurement to 15 on the second run. Passing the `--network none` flag with those hardening options in the command reduces the measurement to a score of 0. An agent must connect to its model provider to function, so a working agent usually stays above a score of 0. You should work toward the lowest score that still lets the workload run and record why each remaining finding stays open.

Three more commands cover a full comparison, a browser view and the CI gate.

```bash
agentsec matrix python:3.12-slim              # all eleven configurations, one table
agentsec ui --results reports/ --open         # the same results in a browser
agentsec blast-radius preset docker-hardened --image myagent:latest --max-score 15
```

Passing `--max-score 15` in that command establishes a CI gate by setting a budget on the measured sandbox score. Any scan whose total finishes above that budget causes `--max-score` to return exit code 2 to the build. Match that budget to the score you record after hardening the sandbox, so any later drift breaks the build.

A round number chosen in advance gives a hardened sandbox room to drift before the score gate trips. Budget checks fail a run only once the total crosses that ceiling, so drift beneath the limit passes. For example, a sandbox scoring 26 against a budget of 45 might add a writable host mount under `FS-003` worth 8 points and drop `no_new_privs` under `PRIV-005` worth 3 points. Those two changes bring the measured total score to 37, so the run still passes the budget check. The `--baseline` commands below fail when a run gets worse at any score by comparing it against an earlier accepted report.

```bash
agentsec blast-radius preset docker-hardened --image myagent:tag --label accepted   # once, then commit it
agentsec blast-radius preset docker-hardened --image myagent:tag --baseline reports/accepted.json
agentsec diff reports/accepted.json reports/latest.json    # when measuring and gating are separate steps
```

Both `--baseline` and `agentsec diff` exit with code 2 and list each finding that is new or rises in severity. The check also lists and fails on any existing finding whose evidence widens by one additional writable path, reachable host, or readable credential. Disappearing findings are marked as fixed alongside a prompt to record a fresh baseline, so the gate retains the improvement. New informational findings scored at 0 points appear as noted and let the check pass, unless the finding reports an unmeasured axis. Mismatched probe versions across the two runs make the tool report the difference and fail, because an added check can produce a new finding in an unchanged sandbox. Record the baseline with the same `--redact` setting that you use on the runs you compare against it.

GitHub Actions runs the same gate checks in one workflow step by installing `agentsec` from the action's own checkout, so the version pinned in the workflow is the version that measures.

```yaml
- uses: binary-knight/agentsec-pack@v0.2.0     # the first release that ships the action
  with:
    image: myagent:${{ github.sha }}
    preset: docker-hardened                    # or leave out and pass `flags:` instead
    max-score: 15                              # what you measured after hardening
    baseline: security/agentsec-accepted.json  # optional: fail on anything worse
```

The action fails the workflow job by returning the same exit code that `agentsec` produces on the command line. Every execution of the step records the measured score in the workflow job summary as well as in `steps.<id>.outputs.score`. Workflow runs upload the JSON, Markdown, and HTML report files as a workflow artifact including when a gate check fails. The inputs are listed in `action.yml`.

The `assert` command narrows the focus from a finding list to test whether a sandbox can reach specific paths. Each target path tested against the sandbox receives a pass or fail result from the command without a score.

```bash
# can the graded child read the answer key it is being marked against?
agentsec assert --kind docker --image grader:latest \
  --not-readable /answers/key.json --not-writable /results --readable /workspace/input \
  -- -v ./answers:/answers:ro
```

Any violated expectation causes the command to exit with code 2, so it works in builds or grading harnesses just like `--max-score`. Results from the command separate `absent` from `present, denied` into two distinct answers for every path it checks. An `absent` status means the sandbox lacks the target path, so that result continues to hold when someone adds a mount later. With `present, denied`, the path exists inside the sandbox under a rule that refuses it, so the result depends on that rule remaining in place.

An agent's own sandbox cannot be measured from the outside by wrapping it the way a container can, because the agent is already running inside that sandbox when it executes commands. Ask the agent to run `agentsec probe --label ... --how ...`, which in one step measures and scores the sandbox where that command executes. The guide in `docs/CAPTURING.md` explains the details, such as what to do when the package cannot be installed inside the sandbox and the result has to come back through the agent's reply.

### By pointing an agent at this repository

To hand this repository to an agent, clone it, point the agent at `AGENTS.md`, a brief written for an agent, and give it a prompt like this one:

> Read AGENTS.md in this repository and carry out Task A, then report what you
> found. Do not change any host settings.

Task A directs the agent to evaluate its own running sandbox, because a user cannot easily measure that environment on their own. When you name a target image, Task B instructs the agent to measure that image and harden it. In Task C, the agent adds the CI gate.

You should review `AGENTS.md` before passing it over. The brief stays under 100 lines and runs without `sudo`. Network traffic in the brief stops at installing this package, while writes stay inside the working directory and a temp path. Having an agent execute instructions from a file is the pattern this tool addresses, so that brief instructs the agent to treat any repository as data with no authority. The agent returns a score and the sealing status across the five axes along with whether findings were proven reachable or only seen. Both `--label` and `--how` are mandatory flags, so any number reported without an account of its capture came from outside the tool.

Every measurement run writes a machine-readable file to `reports/<label>.json` under `schema_version` 1 alongside a companion report at `reports/<label>.md`. That JSON output captures the specific image and flags from the run, so anyone can reproduce the resulting number. A generated report includes the sandbox hostname and working directory along with secret-looking environment variable names, so you should review it before publishing. Passing `--redact` strips those host and environment details while preserving every score and finding alongside the recorded flags. The reports in `examples/`, which this README cites, were made that way, and git ignores `reports/`.

## What it found

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

## Measuring an agent's own sandbox

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

Claude Code isolates network traffic by enforcing an allowlist through a local proxy, so the zero egress recorded during this headless run with nothing approved reflects an empty allowlist. In Codex, the `--unshare-net` flag detaches the network at the namespace level regardless of what the policy states. Failures on direct IP connections and cloud metadata requests still hold under both of those isolation designs. Probe version 0.1.0 collected these rows through direct connections that ignored `HTTPS_PROXY`, so it missed proxy egress and would have reported a sealed network even with hosts on the allowlist. A test on 2026-11-03 demonstrated this behavior when `curl` reached `github.com` through the proxy with status 200 while every direct connection from the probe was refused. Starting in version 0.2.0, the probe records only the names of set proxy variables and reports `NET-004` to indicate unmeasured proxy egress in places where earlier output claimed containment. Because of that change, you should treat the network column in these rows as unverified. Vendor documentation describes the seccomp filter for unix-domain sockets as an optional add-on, yet both this run and 2.1.317 refused `AF_UNIX socket()` calls without that add-on installed, so the sandbox measured stricter than the documentation states. The result was raised publicly as [anthropics/claude-code#107142](https://github.com/anthropics/claude-code/issues/107142) on 2026-11-04, after this README had already published it. `SECURITY.md` says the vendor hears first, and here the vendor did not.

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

## Seeing it

Two commands render the same page.

```bash
# a self-contained HTML file: keep it as a CI artifact, mail it, open it offline
agentsec report reports/ --out blast-radius.html

# a console on localhost, with the runs you have already saved loaded in
agentsec ui --results reports/ --open
```

Both `agentsec report` and `agentsec ui` display an identical page where a top band spans the five axes that the probe evaluates. That band comes first because separating what is reachable from what is only visible is the purpose of the tool. Each axis reports Sealed if nothing appears, Visible but refused if the probe detects something inaccessible, Reachable if the probe makes contact, and Not measured if the probe fails to resolve it. An axis reports Not measured because an egress proxy demands a password that only `AGENTSEC_PROBE_PROXY_AUTH=1` lets the probe send, or because the probe cannot speak to the proxy, as with a SOCKS proxy. The score appears second on the page, because a number by itself leaves out the state of each axis. Provenance, the record of where and how the run was collected, occupies a dedicated panel on the page.

The console and the exported file always stay in sync because both commands build their output from a shared template. Local system fonts and inline CSS handle all styling directly, so the generated page avoids any CDN or network request. When any `src` or `href` attribute on the exported page references a location outside the local machine, a test fails.

The local console accepts requests only from this machine and runs only configurations shipped with the tool. Listening exclusively on `127.0.0.1`, the server generates a random token during initialization that every incoming API request must present. Request handling validates the `Host` header first, which prevents a malicious website from contacting the service through a domain pointed at the loopback address. HTTP responses from the console include a strict Content-Security-Policy header while omitting any CORS header from the reply. Execution is limited to configurations bundled in `presets.json` or to an engine and an image paired with flags recognized by the remediation map. Command templates are rejected by the console, a restriction that `tests/test_ui.py` checks to confirm that a browser cannot request one.

Passing `--bind` directs the console to listen on a different network address, which lets a browser on a separate machine open the interface. Any console bound to an address outside loopback operates in read-only mode unless you also pass `--allow-remote-runs` at launch. Reports are safe to expose on a network for remote browsers to read. Permitting a network to launch containers requires a separate, deliberate choice that you make when starting the server.

## Alongside a red-team run

Promptfoo evaluates how the agent behaves during an attack, and `agentsec` determines what the agent's sandbox allows a successful attack to access. The three commands below run both and join their output.

```bash
# 1. measure the sandbox
agentsec blast-radius preset docker-default --image youragent:tag --out reports
# 2. run your promptfoo suite with the containment row (examples/promptfoo/promptfooconfig.yaml)
AGENTSEC_REPORT=reports/docker-default_youragent_tag.json   npx promptfoo@0.122.2 eval -c promptfooconfig.yaml -o out.json
# 3. join them
agentsec combine --promptfoo out.json --sandbox reports/docker-default_youragent_tag.json   --deployed-in docker-default
```

The assertion records a `blast_radius` score inside promptfoo's `namedScores`. Because promptfoo invokes assertions once for every test row, this assertion loads a report that the probe generated earlier. Attach this assertion to one dedicated test row. Putting the assertion on `defaultTest` executes it across every row, which causes one permissive sandbox to fail the entire test suite over a single issue in the environment.

The `combine` command identifies the overlap by listing every OWASP agentic category where a failed test pairs with a corresponding finding from the sandbox. A local cache at `agentsec/data/promptfoo_plugin_asi.json` stores the category mapping published by promptfoo alongside the origin URL and the date of retrieval. When an entry uses a plugin identifier formatted like `owasp:agentic:asi05`, the command reads the category directly from that identifier.

Every run requires the `--deployed-in` flag as an assertion from the user that connects the two input files. The input files cannot verify whether the agent tested by promptfoo runs inside the measured sandbox, so the report places that assumption at the top as a condition for every conclusion. An example of the output is in `examples/promptfoo/combined_example.md`.

Automated tests verify this integration against a `promptfoo eval` run captured as a fixture on 2026-09-08 alongside an end-to-end check that invokes `npx promptfoo@0.122.2`. Because a live red-team run requires a target and credentials absent from this repository, the test for joining plugin identifiers uses only a manually authored fixture matching the promptfoo schema. In the output produced by a red-team evaluation, an entry with `success: false` signifies that the attack succeeded against the target.

## How it works

The probe script at `agentsec/probe/blast_probe.py` lives inside a single file with its dependencies limited to the Python standard library. Its runner either mounts that file read-only inside a container or invokes it via any command template capable of running `python3`, then collects a single line of JSON in return. Running the `agentsec probe` command spawns the script as a child of the active process inside that process's own environment. `agentsec/scoring.py` converts that JSON payload into findings at fixed severity levels that assign 25 points to critical, 15 to high, 8 to medium, 3 to low, and 0 to informational. Point totals add up to a maximum score of 100, where a result of 0 indicates that nothing was reached by the probe. Those severity weights remain constant, so anyone can recalculate the final score manually from the reported list of findings. Every finding corresponds to the OWASP Top 10 for Agentic Applications (2026) through the category mappings and source records stored in `agentsec/data/owasp_asi_2026.json`.

## What the probe will not do

You should read through the probe before you execute it on any system that matters. The secret scan records only the names of environment variables that resemble secrets and the filesystem paths of credential files without ever reading their contents. Network checks resolve each address in a fixed list of hosts and open a connection that sends nothing before closing. The tool also asks any configured egress proxy for a tunnel to those same hosts and to `example.com`, a control host that no allowlist would have reason to include. Each proxy check logs only the returned status code and never starts TLS, so nothing ever reaches a target host. A proxy that requests a password receives it only when `AGENTSEC_PROBE_PROXY_AUTH=1` is set, with the password sent solely to that proxy. The probe never writes the password supplied for proxy authentication or the address of the proxy to its output.

Filesystem checks confirm that a file is readable by opening it and reading zero bytes, so no credential contents ever pass through the tool. The probe measures directory writability through its only disk writes by creating and immediately deleting one zero-byte marker file per probed directory, so those brief file operations can trigger file-integrity monitoring. Persistence checks test whether the agent could place anything persistent to run outside the sandbox by opening existing shell startup files, `~/.ssh/authorized_keys`, `~/.gitconfig`, and the agent's own settings files for appending. Each opened file is closed right away without writing a byte, so its content and modification time remain unchanged. The check opens only target files that already exist on disk, so a missing file is never created. A file watcher monitoring those paths will still observe each existing file being closed when the append test finishes. The test suite in `tests/test_probe.py` verifies the secret redaction and the fixed target list in addition to confirming that those files remain byte-for-byte unchanged.

## Status

The list below shows what is built and what is still open. [`docs/ROADMAP.md`](docs/ROADMAP.md) gives the prioritized plan and what each open item needs.

- [x] blast-radius probe, runner (docker / podman / local / command template), scorer, JSON + Markdown reports
- [x] ten launcher presets, `matrix` comparison table, `--max-score` CI gate, recommended-flag output, image digests
- [x] promptfoo integration: containment assertion, `combine` report, OWASP category overlap
- [x] measured profiles of named agents' sandboxes, captured by running the probe inside them
- [x] three agents (Claude Code, Codex CLI, Aider) measured across twelve configurations, and a preset that reproduces Codex's bubblewrap layer to measure what its seccomp layer adds
- [x] egress measured through a configured proxy, with an allowlist control host and opt-in proxy credentials (probe 0.4.0)
- [x] agents' own login credentials, a forwarded SSH agent, rootless container sockets, and writes that persist outside the sandbox (probe 0.3.0)
- [x] PyPI release workflow for `agentsec-pack` (trusted publishing, on a version tag)
- [ ] macOS: the probe reads `/proc` and assumes Linux
- [ ] more agents as they become installable here, with a preset only where the argv can be captured live
- [ ] verifier-integrity test class
- [x] browser front end: static HTML report and a localhost console, sharing one template
- [x] a CI gate that fails on any regression against an accepted baseline (`--baseline`, `agentsec diff`)
- [ ] history across runs

## Reporting a problem

Report a security issue in this tool through `SECURITY.md`, which also states the rule this project follows when it measures someone else's software. Open an issue for anything else, and read `CONTRIBUTING.md` before working on the code.

## License

MIT, in `LICENSE`.
