"""Scrub operator-identifying detail from a result before it is published.

A blast-radius report is meant to be pasted into an issue or a blog post. What
it legitimately contains -- the sandbox's hostname, its working directory, the
NAMES of secret-looking environment variables -- can still identify a machine
or a vendor. `--redact` removes that while leaving every score, finding and
target flag intact, so the result stays reproducible and checkable.
"""
from __future__ import annotations

import os
import re
from typing import Any

PLACEHOLDER = "<redacted>"


def _scrub_str(v: str, home: str, user: str) -> str:
    if home and home != "/" and home in v:
        v = v.replace(home, "~")
    if user:
        v = re.sub(r"\b%s\b" % re.escape(user), PLACEHOLDER, v)
    return v


def redact(obj: Any, home: str | None = None, user: str | None = None) -> Any:
    """Return a copy with home paths collapsed, usernames and env var names removed."""
    home = os.path.expanduser("~") if home is None else home
    user = (os.environ.get("USER") or os.path.basename(home)) if user is None else user

    def walk(o: Any, key: str | None = None) -> Any:
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if k in ("env_secret_names", "names"):
                    items = v if isinstance(v, list) else []
                    out[k] = [{"name": PLACEHOLDER, "length": i.get("length")} if isinstance(i, dict) else PLACEHOLDER for i in items]
                elif k in ("hostname", "cwd", "pid1_cmdline", "cgroup"):
                    out[k] = PLACEHOLDER
                else:
                    out[k] = walk(v, k)
            return out
        if isinstance(o, list):
            return [walk(i, key) for i in o]
        if isinstance(o, str):
            return _scrub_str(o, home, user)
        return o

    return walk(obj)
