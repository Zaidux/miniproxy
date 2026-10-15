"""Release hygiene: version strings must agree everywhere.

0.5.0 shipped with ``pyproject.toml``/``package.json`` at 0.5.0 while
``__init__.py`` still said 0.4.0, so ``/api/meta`` reported a version that
did not match what was actually installed. These tests pin all three
together, plus the changelog.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert m, "no version in pyproject.toml"
    return m.group(1)


def test_package_json_version_matches_pyproject() -> None:
    pkg = json.loads((ROOT / "package.json").read_text())
    assert pkg["version"] == _pyproject_version()


def test_runtime_version_matches_pyproject() -> None:
    """What the dashboard reports via /api/meta must match the release."""
    from miniproxy import __version__

    assert __version__ == _pyproject_version()


def test_version_is_not_a_placeholder() -> None:
    v = _pyproject_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+", v), f"not a release version: {v!r}"


def test_changelog_documents_current_version() -> None:
    """The version being published must have a changelog section."""
    changelog = (ROOT / "CHANGELOG.md").read_text()
    v = _pyproject_version()
    assert f"## [{v}]" in changelog, f"CHANGELOG.md has no section for {v}"