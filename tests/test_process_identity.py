import os

import pytest

from miniproxy import runtime, server


@pytest.mark.parametrize("dashboard", [False, True])
def test_stop_refuses_missing_or_recycled_identity(monkeypatch, dashboard):
    path = server.DASH_PID_FILE if dashboard else server.PID_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()))
    monkeypatch.setattr(server.os, "killpg", lambda *a: pytest.fail("foreign process signalled"))
    stop = server.stop_dashboard if dashboard else server.stop
    assert stop()["status"] == "error"
    server._write_process_identity(path, os.getpid())
    monkeypatch.setattr(runtime, "process_identity", lambda _: "recycled")
    assert stop()["status"] == "error"
    assert path.exists()


@pytest.mark.skipif(not os.path.isdir("/proc"), reason="Linux process creation identity")
def test_process_identity_includes_boot_and_creation_time():
    value = runtime.process_identity(os.getpid())
    assert value and ":" in value
    assert runtime.process_identity(10**9) == ""
