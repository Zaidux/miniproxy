"""Shared fixtures for the MiniProxy test suite.

Every test gets an isolated SQLite capture DB (tmp_path) so tests can run in
parallel and never touch the developer's real ``~/.miniproxy`` state.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make `import miniproxy` work from a source checkout without installing.
SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture()
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "proxy.db")


@pytest.fixture()
def db(db_path: str):
    from miniproxy.addon.db import Database

    return Database(db_path)


@pytest.fixture()
def app_client(db_path: str, monkeypatch):
    """Flask test client wired to an isolated capture DB."""
    import miniproxy.app as appmod
    from miniproxy.addon.db import Database

    monkeypatch.delenv("MINIPROXY_DASHBOARD_TOKEN", raising=False)
    appmod.DASHBOARD_TOKEN = ""
    test_db = Database(db_path)
    original_db = appmod.db
    appmod.db = test_db
    try:
        yield appmod.app.test_client(), test_db, appmod
    finally:
        appmod.db = original_db


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path: Path, monkeypatch):
    """Keep tests away from real ~/.miniproxy state (pid files etc.)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # server.py computes STATE_DIR at import time; point it at the sandbox too.
    from miniproxy import server as servermod

    monkeypatch.setattr(servermod, "STATE_DIR", tmp_path / ".miniproxy")
    yield
