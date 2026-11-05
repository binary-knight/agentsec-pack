"""What ships in the wheel. The source tree working is not the installed package working."""
import fnmatch
import os
import re

import agentsec

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def _package_data_patterns():
    with open(os.path.join(REPO, "pyproject.toml"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^\[tool\.setuptools\.package-data\]\s*\nagentsec\s*=\s*\[(.*?)\]", text, re.M | re.S)
    assert m, "pyproject.toml must declare package-data for agentsec"
    return re.findall(r'"([^"]+)"', m.group(1))


def test_every_non_python_file_in_the_package_is_shipped():
    """agentsec/ui/template.html was missing from the wheel, so `agentsec report`
    and `agentsec ui` crashed with FileNotFoundError on any install from PyPI,
    while every test passed from the source tree."""
    patterns = _package_data_patterns()
    root = os.path.join(REPO, "agentsec")
    missing = []
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in files:
            if name.endswith((".py", ".pyc")):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
            if not any(fnmatch.fnmatch(rel, p) for p in patterns):
                missing.append(rel)
    assert not missing, f"not in [tool.setuptools.package-data]: {missing}"


def test_the_package_reports_the_version_it_is_published_under():
    with open(os.path.join(REPO, "pyproject.toml"), encoding="utf-8") as f:
        assert f'version = "{agentsec.__version__}"' in f.read()
