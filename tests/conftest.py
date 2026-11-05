"""Shared fixtures for the MiniProxy test suite.

Every test gets an isolated SQLite capture DB (tmp_path) so tests can run in
parallel and never touch the developer's real ``~/.miniproxy`` state.
"""
from __future__ import annotations

import os
import sys
import time
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
    # The intruder job is a module-level global so the API can report on a
    # background thread. Without this reset, a job left running by one test
    # makes the next test's start() return 409 and fail for the wrong reason.
    original_job = appmod._intruder_job
    appmod._intruder_job = None
    # Workers dereference module-global db on every flush. Join every worker
    # before restoring/replacing that database, including threads that haven't
    # yet registered their job ID. Otherwise a three-item job can write into the
    # next test's 25-item job (the observed count of 28).
    workers = []
    thread_type = appmod.threading.Thread
    def tracked_thread(*args, **kwargs):
        thread = thread_type(*args, **kwargs)
        if kwargs.get("target") is appmod._run_intruder_job:
            workers.append(thread)
        return thread
    monkeypatch.setattr(appmod.threading, "Thread", tracked_thread)
    try:
        yield appmod.app.test_client(), test_db, appmod
    finally:
        with appmod._intruder_lock:
            appmod._intruder_cancelled.update(job["id"] for job in test_db.running_intruder_jobs())
        deadline = time.monotonic() + 15
        for worker in workers:
            worker.join(timeout=max(0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            pytest.fail("Intruder worker outlived its isolated database fixture")
        with appmod._intruder_lock:
            appmod._intruder_cancelled.clear()
        appmod.db = original_db
        appmod._intruder_job = original_job


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path: Path, monkeypatch):
    """Keep tests away from real ~/.miniproxy state (pid files etc.)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Browser defaults are computed during collection, before HOME is patched.
    # Never use an operator's persistent cookie/profile directory in tests.
    from miniproxy import browser_client
    monkeypatch.setattr(browser_client, "DEFAULT_PROFILE", tmp_path / "browser-profile")
    # server.py computes STATE_DIR *and* the pid/port file constants at
    # import time; patch all of them so a developer's leftover mitmdump
    # state can never make tests think a proxy is (or isn't) running.
    from miniproxy import server as servermod
    state = tmp_path / ".miniproxy"
    monkeypatch.setattr(servermod, "STATE_DIR", state)
    monkeypatch.setattr(servermod, "PID_FILE", state / "mitmdump.pid")
    # HOST_FILE was missed, so a start() wrote it to whatever STATE_DIR the
    # module computed at import time — a previous test's tmp dir — and a
    # FileNotFoundError there failed an unrelated test later in the run.
    monkeypatch.setattr(servermod, "HOST_FILE", state / "mitmdump.host")
    monkeypatch.setattr(servermod, "PORT_FILE", state / "mitmdump.port")
    monkeypatch.setattr(servermod, "DASH_PID_FILE", state / "dashboard.pid")
    monkeypatch.setattr(servermod, "DASH_PORT_FILE", state / "dashboard.port")
    monkeypatch.setattr(servermod, "DASH_HOST_FILE", state / "dashboard.host")
    yield
    with browser_client._BRIDGE_LOCK:
        bridge = browser_client._BRIDGE
        browser_client._BRIDGE = None
    if bridge is not None:
        bridge.close()
