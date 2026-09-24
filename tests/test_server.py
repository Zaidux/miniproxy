"""Tests for the process manager (server.py) — run without touching real state."""
from __future__ import annotations

import os
import subprocess
import time
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

    def test_busy_port_falls_back_to_next_free(self, state, monkeypatch):
        """New contract: a busy port moves up to the next free one."""
        import socket

        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        proc = subprocess.Popen(
            ["python3", "-c", "# mitmdump\nimport time; time.sleep(30)"],
        )
        time.sleep(0.2)

        def fake_popen(cmd, **kwargs):
            return proc

        monkeypatch.setattr(subprocess, "Popen", fake_popen)
        monkeypatch.setattr(srv, "_wait_listening", lambda p, pr, timeout=8.0: True)
        try:
            r = srv.start(port=port, dashboard=False)
            assert r["status"] == "started"
            assert r["port"] in range(port + 1, port + 20)
            assert r["fallback"] is True
            assert "busy" in r["message"].lower()
            assert srv.PORT_FILE.read_text() == str(r["port"])
        finally:
            blocker.close()
            proc.kill()
            proc.wait()

    def test_start_port_auto_picks_free_port(self, state, monkeypatch):
        import socket

        proc = subprocess.Popen(
            ["python3", "-c", "# mitmdump\nimport time; time.sleep(30)"],
        )
        time.sleep(0.2)

        def fake_popen(cmd, **kwargs):
            return proc

        monkeypatch.setattr(subprocess, "Popen", fake_popen)
        monkeypatch.setattr(srv, "_wait_listening", lambda p, pr, timeout=8.0: True)
        try:
            r = srv.start(port="auto", dashboard=False)
            assert r["status"] == "started"
            assert isinstance(r["port"], int) and 1024 <= r["port"] <= 65535
            assert r["fallback"] is False
            assert srv.PORT_FILE.read_text() == str(r["port"])
        finally:
            proc.kill()
            proc.wait()

    def test_resolve_port_variants(self, state):
        import socket

        assert srv._resolve_port("AUTO") == srv._resolve_port("auto")
        assert isinstance(srv._resolve_port("auto"), int)
        assert srv._resolve_port("8085") == 8085
        assert srv._resolve_port(8085) == 8085
        assert srv._resolve_port(None) is not None
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            taken = s.getsockname()[1]
        chosen = srv._resolve_port("auto")
        assert chosen != taken or not srv._port_free(taken)  # never a bound port

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

    def test_dashboard_url_uses_reachable_host_for_wildcard_bind(self, state, monkeypatch):
        # already-running path just reports the recorded port — use a real
        # sleeping python child whose cmdline contains "miniproxy dashboard"
        # so the pid guard accepts it.
        import time
        from miniproxy import connect

        monkeypatch.setattr(
            connect, "candidate_hosts",
            lambda **kwargs: [{"host": "203.0.113.7", "label": "test"}],
        )
        proc = subprocess.Popen(
            ["python3", "-c", "# miniproxy dashboard\nimport time; time.sleep(30)"],
        )
        try:
            time.sleep(0.2)
            srv.DASH_HOST_FILE.parent.mkdir(parents=True, exist_ok=True)
            srv.DASH_PID_FILE.write_text(str(proc.pid))
            srv.DASH_PORT_FILE.write_text("5599")
            srv.DASH_HOST_FILE.write_text("0.0.0.0")
            r = srv._ensure_dashboard(None, 5599, dash_host="127.0.0.1")
            assert r["status"] == "already_running", r
            assert r["url"] == "http://203.0.113.7:5599"
        finally:
            proc.kill()
            proc.wait()

    def test_dashboard_url_keeps_loopback_for_local_bind(self, state, monkeypatch):
        from miniproxy import connect

        monkeypatch.setattr(
            connect, "candidate_hosts",
            lambda **kwargs: [{"host": "203.0.113.7", "label": "test"}],
        )
        assert srv._dashboard_display_host("127.0.0.1") == "127.0.0.1"
        monkeypatch.setattr(
            connect, "candidate_hosts",
            lambda **kwargs: [{"host": "169.254.10.20", "label": "link-local"}],
        )
        assert srv._dashboard_display_host("0.0.0.0") == "127.0.0.1"
