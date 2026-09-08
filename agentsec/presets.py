"""Named sandbox configurations, loaded from data/presets.json."""
from __future__ import annotations

import json
import shutil
from importlib import resources
from typing import Any


def load_all() -> dict[str, dict[str, Any]]:
    with resources.files("agentsec.data").joinpath("presets.json").open("r") as f:
        return json.load(f)["presets"]


def meta() -> dict[str, Any]:
    with resources.files("agentsec.data").joinpath("presets.json").open("r") as f:
        return json.load(f)["_meta"]


def get(name: str) -> dict[str, Any]:
    presets = load_all()
    if name not in presets:
        raise KeyError(f"unknown preset {name!r}; known: {', '.join(sorted(presets))}")
    return presets[name]


def requirement(preset: dict[str, Any]) -> str:
    """The executable a preset needs on PATH."""
    if preset["kind"] == "container":
        return preset["engine"]
    return preset["template"].split()[0]


def available(preset: dict[str, Any]) -> bool:
    return shutil.which(requirement(preset)) is not None


def names_for(kind: str | None = None, only_available: bool = False) -> list[str]:
    out = []
    for name, p in sorted(load_all().items()):
        if kind and p["kind"] != kind:
            continue
        if only_available and not available(p):
            continue
        out.append(name)
    return out
