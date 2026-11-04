# Design notes

## Why these two test classes

Agent observability tools record what an agent did. This pack tries to catch the agent doing what it should not be able to do, or claiming to have done what it did not:

- **Blast radius** is a property of the deployment, not the model. A coding agent that is prompt-injected into `curl`-ing a credential to the internet only succeeds if the sandbox lets it. Measuring the sandbox once, per image and flag set, tells a team what an injection can cost them before any prompt is involved.
- **Verifier integrity** (next) is the reward-hacking failure: an agent that passes CI by editing the tests. The test is to run a verifier the agent never saw, on the agent's diff, and to diff the tests themselves.

Both are adversarial to the agent and independent of any particular model or framework.

## Reproducibility rule

A finding nobody can reproduce is not a finding. Every result envelope records the exact target (image, flags, launcher command, probe version). Reports are meant to be published alongside the command that produced them.

## Non-exfiltration rule

The probe reports presence and names, never values, and proves readability by opening and reading zero bytes; connects only to a fixed host list, and when an egress proxy is configured asks that proxy for a tunnel to each of the same hosts plus one control host (`example.com`), reading the status line and closing without TLS, so nothing reaches a target; writes only zero-byte marker files, one per probed directory, removed at once. Existing persistence files (shell startup files, `authorized_keys`, `.gitconfig`, the agent's own settings) are opened for append without `O_CREAT` and closed without writing, so nothing is created and nothing changes. One exception, opt-in: with `AGENTSEC_PROBE_PROXY_AUTH=1` the proxy's password from the environment is sent to that proxy, and only that proxy, in a `Proxy-Authorization` header, because an authenticating proxy (Claude Code's is one) otherwise answers 407 and the network axis cannot be measured. It is never recorded, and neither is the proxy's address. Any change to the probe that touches these rules needs a test that asserts the rule still holds.

## Scoring

Fixed weights per severity (critical 25, high 15, medium 8, low 3), summed and capped at 100. Deliberately not a model: a reader can recompute it by hand from the findings list.

## Roadmap

The prioritized plan lives in [`ROADMAP.md`](ROADMAP.md).
