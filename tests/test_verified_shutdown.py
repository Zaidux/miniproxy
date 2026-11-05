"""Real private process groups, never operator proxy processes."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from miniproxy import runtime, server

pytestmark = pytest.mark.skipif(not Path("/proc").is_dir(), reason="Linux process-group identity")


def group(tmp_path, *, leader_ignores=False):
    script = r'''
import os, signal, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('child-ready', flush=True); time.sleep(60)"], stdout=subprocess.PIPE)
child.stdout.readline()
open(sys.argv[1], "w").write(str(child.pid))
if sys.argv[2] == "ignore":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(60)
'''
    child_file = tmp_path / "child.pid"
    proc = subprocess.Popen([sys.executable, "-c", script, str(child_file), "ignore" if leader_ignores else "exit"], start_new_session=True)
    deadline = time.monotonic() + 5
    while not child_file.exists() or not child_file.read_text():
        assert time.monotonic() < deadline
        time.sleep(.01)
    return proc, int(child_file.read_text())


def cleanup(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=5)


@pytest.mark.parametrize("leader_ignores", [False, True])
def test_verified_termination_kills_descendants_even_after_leader_exit(tmp_path, leader_ignores):
    proc, child = group(tmp_path, leader_ignores=leader_ignores)
    try:
        assert runtime.terminate_process_group(proc.pid, runtime.process_identity(proc.pid), timeout=.2)
        proc.wait(timeout=5)
        assert runtime._group_members(proc.pid) == {}
    finally:
        cleanup(proc)


def test_group_termination_requires_leader_in_initial_group_snapshot(monkeypatch):
    monkeypatch.setattr(runtime, "process_identity", lambda pid: "leader")
    monkeypatch.setattr(runtime.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(runtime.os, "getsid", lambda pid: pid)
    monkeypatch.setattr(runtime, "_group_members", lambda pgid: {pgid + 1: ("child", pgid)})
    monkeypatch.setattr(runtime.os, "killpg", lambda *a: pytest.fail("ambiguous group signalled"))
    assert not runtime.terminate_process_group(1234, "leader")


@pytest.mark.parametrize("dashboard", [False, True])
def test_stop_retains_all_ownership_files_when_cleanup_unconfirmed(monkeypatch, tmp_path, dashboard):
    proc, _ = group(tmp_path)
    paths = [tmp_path / name for name in ("proxy.pid", "proxy.port", "proxy.host")]
    names = ("DASH_PID_FILE", "DASH_PORT_FILE", "DASH_HOST_FILE") if dashboard else ("PID_FILE", "PORT_FILE", "HOST_FILE")
    for name, path in zip(names, paths):
        monkeypatch.setattr(server, name, path)
        path.write_text(str(proc.pid) if name.endswith("PID_FILE") else "fixture")
    server._write_process_identity(paths[0], proc.pid)
    monkeypatch.setattr(runtime, "terminate_process_group", lambda *a, **k: False)
    try:
        result = (server.stop_dashboard if dashboard else server.stop)()
        assert result["status"] == "error"
        assert all(path.exists() for path in paths)
        assert paths[0].with_suffix(".identity").exists()
        assert proc.poll() is None
    finally:
        cleanup(proc)


def test_dashboard_timeout_has_provisional_ownership_and_verified_cleanup(monkeypatch, tmp_path):
    proc, _ = group(tmp_path, leader_ignores=True)
    monkeypatch.setattr(server, "STATE_DIR", tmp_path)
    for name in ("DASH_PID_FILE", "DASH_PORT_FILE", "DASH_HOST_FILE"):
        monkeypatch.setattr(server, name, tmp_path / name)
    monkeypatch.setattr(server.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(server, "_port_free", lambda _: True)
    monkeypatch.setattr(server.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError("never ready")))
    clock = iter([0, 100])
    monotonic = time.monotonic
    monkeypatch.setattr(server.time, "monotonic", lambda: next(clock))
    def stop(path, pid):
        assert path.exists() and path.with_suffix(".identity").exists()
        # Restore the clock for the real termination deadline.
        monkeypatch.setattr(server.time, "monotonic", monotonic)
        return runtime.terminate_process_group(pid, runtime.process_identity(pid), timeout=.2)
    monkeypatch.setattr(server, "_stop_owned_group", stop)
    try:
        result = server._ensure_dashboard(None, 5555)
        assert result["status"] == "error" and "stopped" in result["message"]
        assert runtime._group_members(proc.pid) == {}
    finally:
        cleanup(proc)


@pytest.mark.parametrize("dashboard", [False, True])
def test_vanished_leader_retains_descendant_ownership(monkeypatch, tmp_path, dashboard):
    proc, _ = group(tmp_path)
    names = ("DASH_PID_FILE", "DASH_PORT_FILE", "DASH_HOST_FILE") if dashboard else ("PID_FILE", "PORT_FILE", "HOST_FILE")
    paths = [tmp_path / name for name in names]
    for name, path in zip(names, paths):
        monkeypatch.setattr(server, name, path)
        path.write_text(str(proc.pid) if name.endswith("PID_FILE") else "fixture")
    identity = runtime.process_identity(proc.pid)
    server._write_process_identity(paths[0], proc.pid)
    try:
        proc.terminate()
        proc.wait(timeout=5)
        assert not runtime.process_group_exited(proc.pid)
        with monkeypatch.context() as guard:
            guard.setattr(runtime.os, "killpg", lambda *a: pytest.fail("unanchored group signalled"))
            assert not runtime.terminate_process_group(proc.pid, identity)
            assert (server.stop_dashboard if dashboard else server.stop)()["status"] == "error"
            if not dashboard:
                assert server.status()["status"] == "error"
            assert all(path.exists() for path in paths)
    finally:
        cleanup(proc)


@pytest.mark.parametrize("failed_suffix", ["pid", "identity", "port", "host"])
def test_publication_failure_retires_in_memory_owned_group(monkeypatch, tmp_path, failed_suffix):
    proc, _ = group(tmp_path, leader_ignores=True)
    paths = [tmp_path / ("proxy." + suffix) for suffix in ("pid", "port", "host")]
    write = server._write_state
    def fail(path, value):
        if path.suffix == "." + failed_suffix:
            raise OSError("fixture publication failure")
        write(path, value)
    monkeypatch.setattr(server, "_write_state", fail)
    terminate = runtime.terminate_process_group
    monkeypatch.setattr(runtime, "terminate_process_group", lambda pid, identity: terminate(pid, identity, timeout=.2))
    try:
        assert not server._publish_process_state(proc, *paths, 5555, "127.0.0.1")
        assert runtime.process_group_exited(proc.pid)
        assert not any(path.exists() for path in paths)
    finally:
        cleanup(proc)


def test_failed_publication_and_cleanup_retains_recovery_anchor(monkeypatch, tmp_path):
    proc, _ = group(tmp_path)
    paths = [tmp_path / ("proxy." + suffix) for suffix in ("pid", "port", "host")]
    monkeypatch.setattr(server, "PID_FILE", paths[0])
    monkeypatch.setattr(server, "_write_state", lambda *a: (_ for _ in ()).throw(OSError("disk failure")))
    monkeypatch.setattr(runtime, "terminate_process_group", lambda *a: False)
    try:
        assert not server._publish_process_state(proc, *paths, 5555, "127.0.0.1")
        assert server._read_pid() == proc.pid
        assert server._owned_process(paths[0], proc.pid)
        assert server.stop()["status"] == "error"
        assert proc.poll() is None
    finally:
        cleanup(proc)
        server._PENDING_PROCESSES.pop(paths[0], None)
