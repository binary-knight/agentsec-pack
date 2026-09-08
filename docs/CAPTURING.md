# Measuring a sandbox you cannot launch from outside

`agentsec blast-radius` launches the probe itself for containers and for any
launcher you can spell as a command. An agent's own sandbox is different: it is
entered by the agent, on the agent's terms. You cannot wrap it from outside, so
you ask the agent to run the probe and you score what comes back.

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
