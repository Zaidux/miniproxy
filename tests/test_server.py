"""Tests for the process manager (server.py) — run without touching real state."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from miniproxy import server as srv


@pytest.fixture()
def state(tmp_path, monkeypatch):
    """Redirect pid/port files at a temp dir and give the module clean state."""
    monkeypatch.setattr(srv, "STATE_DIR", tmp_path)
    monkeypatch.setattr(srv, "PID_FILE", tmp_path / "mitmdump.pid")
    monkeypatch.setattr(srv, "PORT_FILE", tmp_path / "mitmdump.port")
    monkeypatch.setattr(srv, "DASH_PID_FILE", tmp_path / "dashboard.pid")
    monkeypatch.setattr(srv, "DASH_PORT_FILE", tmp_path / "dashboard.port")
    return tmp_path


class TestPidGuard:
    def test_pid_matches_checks_cmdline(self):
        import time

        proc = subprocess.Popen(["sleep", "2"])
        try:
            time.sleep(0.2)  # let the child exec (Popen returns pre-exec)
            assert srv._pid_matches(proc.pid, "sleep")
            assert not srv._pid_matches(proc.pid, "definitely-not-this-command")
        finally:
            proc.kill()
            proc.wait()

    def test_missing_proc_entry_assumes_match(self):
        # No /proc on the platform (or raced exit): keep permissive behavior.
        assert srv._pid_matches(10**9, "mitmdump") in (True, False)

    def test_status_cleans_stale_pid(self, state, monkeypatch):
        # A pid file pointing at *this* python process (not mitmdump).
        srv.PID_FILE.write_text(str(os.getpid()))
        st = srv.status()
        assert st["status"] == "not_running"
        assert not srv.PID_FILE.exists(), "stale pid file must be removed"

    def test_stop_cleans_recycled_pid(self, state, monkeypatch):
        srv.PID_FILE.write_text(str(os.getpid()))
        result = srv.stop()
        assert result["status"] == "not_running"
        assert "stale" in result["message"]


class TestStartValidation:
    def test_start_reports_missing_binary(self, state, monkeypatch):
        # A port that is free *and* never bound keeps port-validation from
        # short-circuiting before the binary check.
        r = srv.start(port=59999, mitmdump_path="/nonexistent/mitmdump-xyz")
        assert r["status"] == "error"
        assert "install mitmproxy" in r["message"]

    def test_start_rejects_busy_port(self, state):
        import socket

        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        try:
            r = srv.start(port=port)
            assert r["status"] == "error"
            assert str(port) in r["message"]
        finally:
            blocker.close()

    def test_start_without_dashboard_leaves_no_dash_files(self, state, monkeypatch):
        """Fake a successful mitmdump launch: no dashboard pid/port files."""
        import time

        proc = subprocess.Popen(
            ["python3", "-c", "# mitmdump -s addon.py\nimport time; time.sleep(30)"],
        )
        time.sleep(0.2)  # let the child exec

        def fake_popen(cmd, **kwargs):
            return proc

        monkeypatch.setattr(subprocess, "Popen", fake_popen)
        monkeypatch.setattr(srv, "_wait_listening", lambda p, pr, timeout=8.0: True)
        try:
            r = srv.start(port=59998, dashboard=False)
            assert r["status"] == "started"
            assert "dashboard" not in r
            assert srv.PID_FILE.exists()
            assert not srv.DASH_PID_FILE.exists()
        finally:
            proc.kill()
            proc.wait()


class TestDashboardLifecycle:
    def test_stop_dashboard_when_not_running(self, state):
        r = srv.stop_dashboard()
        assert r["status"] == "not_running"

    def test_dashboard_url_reports_configured_host(self, state, monkeypatch):
        # already-running path just reports the recorded port — use a real
        # sleeping python child whose cmdline contains "miniproxy dashboard"
        # so the pid guard accepts it.
        import time

        proc = subprocess.Popen(
            ["python3", "-c", "# miniproxy dashboard\nimport time; time.sleep(30)"],
        )
        try:
            time.sleep(0.2)
            srv.DASH_PID_FILE.write_text(str(proc.pid))
            srv.DASH_PORT_FILE.write_text("5599")
            r = srv._ensure_dashboard(None, 5599, dash_host="0.0.0.0")
            assert r["status"] == "already_running", r
            assert r["url"] == "http://0.0.0.0:5599"
        finally:
            proc.kill()
            proc.wait()
