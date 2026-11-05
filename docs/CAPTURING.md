# Measuring a sandbox you cannot launch from outside

`agentsec blast-radius` launches the probe itself for containers and for any
launcher you can spell as a command. An agent's own sandbox is different: it is
entered by the agent, on the agent's terms. You cannot wrap it from outside, so
you ask the agent to run the probe and you score what comes back.

If `agentsec` is installed where the agent's commands can run it (`pip install
agentsec-pack`, or a checkout's `.venv`), one command does all of it:

```bash
<agent> "run: agentsec probe --label 'vendor-agent 1.2.3 workspace-write' --how '<the exact command, date, host>'"
```

It runs the probe in the environment the agent's command actually gets, scores
it, and writes the report; in a read-only sandbox it prints the report on stdout
instead. When the package cannot be installed inside the sandbox, use the
three steps below, which need only `python3`.

```bash
# 1. put the probe somewhere the agent can reach
cp agentsec/probe/blast_probe.py /tmp/probe.py

# 2. ask the agent to run it, inside whatever sandbox mode you are measuring.
#    If the mode can write files, redirect to one; that is the reliable path:
<agent> --sandbox workspace-write "run: python3 /tmp/probe.py > /tmp/out.json"

#    If the mode is read-only, it cannot write, so take the JSON from the
#    transcript. Agents sometimes clip the final brace; `score` repairs that
#    and says so.
<agent> --sandbox read-only "run python3 /tmp/probe.py and paste its raw stdout"

# 3. score it, recording exactly how you got it
agentsec score /tmp/out.json \
  --label "vendor-agent 1.2.3 read-only" \
  --how "…the exact command, date, host…" \
  --redact
```

`--how` is not decoration. A measurement nobody can repeat is not evidence, and
the capture method is the part a reader cannot infer from the JSON.

## Reading the result fairly

A sandbox mode is a documented boundary, not a promise of total isolation.
Before calling anything a finding, read what the vendor says the mode does. If
the documentation says the agent "can inspect files", then the agent reading
`~/.ssh/config` is the design working as written, and the honest report is
"this is what the documented boundary includes in the blast radius", not "we
found a vulnerability".

Report anything that genuinely contradicts the documentation to the vendor
before publishing it.

## Two gotchas when capturing from an agent's transcript

**Ask for the whole object, not a tail.** A read-only sandbox cannot write a file, so the probe's JSON has to come back through the agent's reply. If you cap the output (`tail -c N`) you lose the *leading* keys and the result will not parse. Ask for the complete output from the first `{` to the last `}`. `agentsec score` repairs a missing closing brace and tells you it did, but it cannot invent a missing opening one.

**The control tests behave differently by mode.** `unix_control` needs a writable directory, so in a read-only sandbox it fails at `mkdtemp` and proves nothing on its own. `unix_control_nopath` needs no writable directory: it connects to a path that does not exist, where `FileNotFoundError` means unix-domain connect is permitted and `PermissionError` means the call was refused before the path was consulted. Scoring prefers the first control and falls back to the second, and says plainly when neither settled the question.

## Trap 1: the captured sandbox inherits the shell you launched it from

This one has now caught two people independently, both of whom had read this
document. It is the default outcome, not an unlucky one.

An agent's sandbox inherits the environment of whatever started it. Launch the
agent from inside another agent's shell, or from a terminal where you have
exported a token, and those variables are visible inside the sandbox and are
scored against the product you think you are measuring. The tell is a
secret-shaped variable in the report that has nothing to do with the vendor:
`CLAUDE_CODE_MESSAGING_TOKEN` and `CLOUDSDK_PROXY_PASSWORD`, which Claude Code
puts in its own sandbox, both turned up in a Codex measurement that had been
launched from inside a Claude Code session.

Prefer a plain terminal. Where you cannot, strip the environment and say that
you did:

```bash
env -i HOME="$HOME" PATH="$PATH" TERM=xterm USER="$USER" SHELL=/bin/bash LANG=C.UTF-8 \
  <agent command>
```

Measuring both ways is better than choosing one: the minimal environment gives
the intrinsic figure, and the difference is the part of the blast radius you
close by fixing your own shell rather than the agent. Record which you did in
`--how`; a score without its environment is not comparable to another score.

## When the sandbox sends traffic through a proxy

Some sandboxes cut the direct route out and send traffic through a proxy that
checks an allowlist. Claude Code's does this, through `HTTPS_PROXY` on loopback.
The probe sees the proxy variables and asks the proxy for a tunnel to each fixed
target and to `example.com`, a control no allowlist has a reason to contain, and
records only the status codes.

The axis reads **contained** only when the proxy clearly refuses every destination it was
asked about. A timeout, a failed connection or a gateway error reads **not measured**
(NET-004), and the evidence lists which destinations got no clear answer.

If the proxy wants a password, it answers 407 and the network axis also reads **not
measured** (NET-004). The password is usually already in the proxy variable, and
the probe will send it to that proxy, and nowhere else, only if you say so:

```bash
agentsec probe --proxy-auth --label ... --how ...         # one step
AGENTSEC_PROBE_PROXY_AUTH=1 python3 /tmp/probe.py > /tmp/out.json   # three-step form
```

That is your decision to make, not the agent's: an agent following `AGENTS.md`
should report NET-004 rather than set this on its own. Two further things belong
in `--how`. Whether you set it, and which domains were allowed when the probe
ran: in Claude Code the allowlist can change per command, and the same sandbox
scored 41 with nothing allowed and 49 with `github.com` allowed.

## When a launcher is installed and still cannot build a sandbox

`bwrap` on PATH does not mean bubblewrap can sandbox anything. Ubuntu 24.04 ships
with unprivileged user namespaces restricted, so bubblewrap gets `Permission
denied` setting up its uid map and the probe never runs. Check the capability
rather than the binary:

```bash
bwrap --ro-bind / / --unshare-user --unshare-pid --dev /dev --proc /proc true \
  && echo "can sandbox" || echo "cannot"

cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns   # 1 means restricted
```

Two ways out. Where you control the host, allow it for this binary with an
AppArmor profile at `/etc/apparmor.d/bwrap` granting `userns,`, then
`sudo apparmor_parser -r /etc/apparmor.d/bwrap`. On a throwaway machine or a CI
runner, `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` lifts it
globally, which is fine there and not fine on a workstation.

`agentsec` tests the capability rather than the path: `runner.sandbox_available()`
runs a trivial sandbox and reports whether it worked, and the test suite skips on
that rather than on `which`. Presence is not capability, which is the same point
the tool makes about everything else it measures.


## Trap 2: do not "improve" a score by moving what it looks at

`$HOME` is an environment variable, so anything inside a sandbox can set it.
Pointing it at an empty directory once cleared the credential finding and dropped
the score by fifteen points while every one of those files stayed readable at its
real path. That was a defect in this tool and it is fixed: credential paths are
now resolved under the passwd entry as well as `$HOME`, and each result records
which home found it in a `via` field.

The general rule survives the fix. **A number that falls because you moved the
instrument is not an improvement.** If a change lowers a score, be able to say
what it stopped the agent from reaching. If you cannot, you have concealed
something rather than contained it. Redirecting `$HOME` is a legitimate hardening
step and this tool does not score it against you; it simply will not let it hide
a file that is still reachable.

The same test applies to anything else you might be tempted to adjust: an
allowlist that removes a probe target, a label that reframes a finding, a budget
raised to meet a score. Contain the reach, or record the finding as accepted and
say why.

## Dev containers

`devcontainer exec` is how a command reaches a dev container, so the probe can go in the
same way. `scripts/measure_devcontainer.sh` does this for three configurations. For your
own, from the folder that holds `.devcontainer/`:

```bash
cp agentsec/probe/blast_probe.py ./agentsec_probe.py
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . python3 agentsec_probe.py > out.json
agentsec score out.json --label my-devcontainer --how "<the CLI version, image digest and settings>" --redact
```

This goes through the CLI. It does not reproduce what an editor adds when it attaches, such
as forwarded credential helpers or an SSH agent. To measure that, run the probe from a
terminal inside the editor. Remove `agentsec_probe.py` afterward, since it sits in your
workspace.
