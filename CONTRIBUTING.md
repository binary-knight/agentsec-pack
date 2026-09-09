# Contributing

The one rule that matters: **never assert a read you did not make.**

Every number in this repository comes from a measurement that was actually
taken, and says how it was taken. That discipline is the product. It has already
caught a scoring defect in this tool, a mis-transcribed company name, and three
claims that turned out to rest on a variable name rather than a value.

In practice:

* A finding's severity must follow from what the probe **proved**, not from what
  the permission bits suggested. `SEC-001` is critical only when a connection
  actually succeeded; when it was refused, a control test decides whether the
  refusal was path-scoped or applied to the call itself.
* A profile of a named product needs `how`, `environment` and `vendor_docs`, and
  tests fail without them.
* A preset named after a product must say what it does **not** reproduce.
* If you find that this tool measured something stricter or looser than a vendor
  documents, record the discrepancy rather than smoothing it away.

## Working on it

```bash
uv venv .venv && uv pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

Tests that need `docker`, `podman` or `bwrap` skip when the binary is absent, so
the suite runs anywhere. If you change scoring, add the fixture that would have
caught the old behaviour.

Front-end changes: the page loads nothing from the network, and a test enforces
it. Keep it that way.
