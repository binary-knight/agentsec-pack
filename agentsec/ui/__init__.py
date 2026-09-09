"""Browser front end: one template, two modes.

`render_html` produces a self-contained page with the data inlined, which is
what `agentsec report --html` writes and what CI can keep as an artifact.
`serve` runs the same template against a local API. Sharing the template is
deliberate: two renderers would drift, and the static one is the one people
send to each other.

No external resources. A tool that argues about supply chains has no business
pulling a script from a CDN, so the page uses system fonts and inline CSS only.
"""
from __future__ import annotations

import json
import os
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "template.html")
PLACEHOLDER = "__AGENTSEC_PAYLOAD__"


def _safe_json(payload: dict[str, Any]) -> str:
    """Inline JSON that cannot break out of the script element."""
    return (json.dumps(payload, sort_keys=True)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def _profiles(resources) -> dict[str, Any]:
    with resources.files("agentsec.data").joinpath("measured_profiles.json").open("r") as f:
        return json.load(f)["profiles"]


def render_html(results: list[dict[str, Any]], mode: str = "static", token: str = "",
                presets: dict[str, Any] | None = None) -> str:
    from importlib import resources

    from ..scoring import FINDING_FLAGS, load_owasp

    payload = {
        "mode": mode,
        "token": token,
        "results": results,
        "presets": presets or {},
        "owasp": load_owasp(),
        "flags": FINDING_FLAGS,
        "profiles": _profiles(resources),
    }
    with open(TEMPLATE, encoding="utf-8") as f:
        html = f.read()
    return html.replace(PLACEHOLDER, _safe_json(payload))
