# Design notes

## Why these two test classes

Agent observability tools record what an agent did. This pack tries to catch the agent doing what it should not be able to do, or claiming to have done what it did not:

- **Blast radius** is a property of the deployment, not the model. A coding agent that is prompt-injected into `curl`-ing a credential to the internet only succeeds if the sandbox lets it. Measuring the sandbox once, per image and flag set, tells a team what an injection can cost them before any prompt is involved.
- **Verifier integrity** (next) is the reward-hacking failure: an agent that passes CI by editing the tests. The test is to run a verifier the agent never saw, on the agent's diff, and to diff the tests themselves.

Both are adversarial to the agent and independent of any particular model or framework.

## Reproducibility rule

A finding nobody can reproduce is not a finding. Every result envelope records the exact target (image, flags, launcher command, probe version). Reports are meant to be published alongside the command that produced them.

## Non-exfiltration rule

The probe reports presence and names, never values; connects only to a fixed host list; writes only a temp marker. Any change to the probe that touches these rules needs a test that asserts the rule still holds.

## Scoring

Fixed weights per severity (critical 25, high 15, medium 8, low 3), summed and capped at 100. Deliberately not a model: a reader can recompute it by hand from the findings list.

## Roadmap

1. Launcher presets: bwrap, gVisor/runsc, Firecracker-based sandboxes, the sandboxes shipped by popular coding agents.
2. Promptfoo integration so the score appears next to an agent's red-team results.
3. Verifier-integrity class.
4. Hosted history: score per image over time, a CI gate on regression.
