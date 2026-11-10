"""Real DB queries and inert lifecycle fixtures for CLI automation."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from miniproxy import automation, server
from miniproxy.__main__ import build_parser, main


@pytest.mark.parametrize("value", [-1, 65536, True, False, 1.5, "invalid"])
def test_invalid_programmatic_ports_do_not_spawn(monkeypatch, value):
    monkeypatch.setattr(server.subprocess, "Popen", lambda *a, **k: pytest.fail("spawned before validation"))
    assert server.start(port=value)["error_type"] == "invalid_port"
    assert server._ensure_dashboard(None, value)["error_type"] == "invalid_port"


def test_port_zero_consistent_and_upper_bound_scan(monkeypatch):
    monkeypatch.setattr(server, "_port_free", lambda p: p == 65535)
    assert server._next_free_port(65535) == 65535
    monkeypatch.setattr(server, "_next_free_port", lambda p: 8081)
    assert server._resolve_port(0) == server._resolve_port("0") == 8081
    for command in (["start", "--port", "65536"], ["connect", "--port", "-1"]):
        with pytest.raises(SystemExit):
            build_parser().parse_args(command)


def test_ipv6_busy_port_detected():
    import socket
    if not socket.has_ipv6:
        pytest.skip("IPv6 unavailable")
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as blocker:
        try:
            blocker.bind(("::1", 0))
        except OSError:
            pytest.skip("IPv6 loopback unavailable")
        blocker.listen(1)
        port = blocker.getsockname()[1]
        assert not server._port_free(port, "::1")


@pytest.mark.parametrize("scope", [[], ["bad host"], "fixture.test"])
def test_invalid_scope_rejected_before_runtime_or_spawn(monkeypatch, scope):
    monkeypatch.setattr("miniproxy.runtime.resolve_mitmdump", lambda *a: pytest.fail("invalid scope reached runtime startup"))
    assert server.start(scope_hosts=scope)["error_type"] == "invalid_scope"


@pytest.mark.parametrize("arguments", [["--listen-port", "9999"], ["--set", "listen_host=0.0.0.0"], ["-s", "/different/addon.py"], ["-p9999"], ["--listen-p", "9999"], ["--set=listen_port=9999"], ["--set=scripts=other.py"]])
def test_extra_args_cannot_override_owned_listener_or_addon(monkeypatch, arguments):
    monkeypatch.setattr("miniproxy.runtime.resolve_mitmdump", lambda *a: pytest.fail("conflicting option reached startup"))
    assert server.start(extra_args=arguments)["error_type"] == "conflicting_proxy_option"


def test_malformed_inherited_policy_fails_preflight(monkeypatch):
    monkeypatch.setenv("MINIPROXY_RULES_SCOPE", "malformed")
    monkeypatch.setattr("miniproxy.runtime.resolve_mitmdump", lambda *a: pytest.fail("invalid policy reached startup"))
    assert server.start()["error_type"] == "invalid_scope"
    monkeypatch.delenv("MINIPROXY_RULES_SCOPE")
    monkeypatch.setenv("MINIPROXY_SCOPE", "malformed")
    assert server.start()["error_type"] == "invalid_scope"


def test_omitted_scope_retains_inherited_scope(monkeypatch):
    monkeypatch.setenv("MINIPROXY_SCOPE", '["fixture.test"]')
    assert server._inherited_scope(None) == ["fixture.test"]
    assert server._inherited_scope(["other.test"]) == ["other.test"]
    assert server._effective_ca_path(["--set=confdir=/tmp/opencode/fixture-ca"]) == "/tmp/opencode/fixture-ca/mitmproxy-ca-cert.pem"


def test_verified_manifest_sidecar_disagreement_is_not_ready(monkeypatch, tmp_path):
    pid_path = tmp_path / "proxy.pid"
    monkeypatch.setattr(server, "PID_FILE", pid_path)
    pid_path.write_text("1234")
    pid_path.with_suffix(".identity").write_text("run")
    server._write_state(server._manifest_path(pid_path), json.dumps({"schema_version": 1, "pid": 1234, "process_identity": "run", "host": "127.0.0.1", "port": 8123}))
    monkeypatch.setattr(server, "_read_port", lambda: 9999)
    monkeypatch.setattr(server, "_read_proxy_host", lambda: "192.0.2.99")
    monkeypatch.setattr(server, "_owned_process", lambda *a: True)
    monkeypatch.setattr(server, "_process_exists", lambda _: True)
    status = server.status()
    assert status["host"] == "127.0.0.1" and status["port"] == 8123
    assert status["status"] == "error" and status["state_integrity_error"]


def test_inherited_scope_mode_canonicalized_before_start(monkeypatch):
    monkeypatch.setenv("MINIPROXY_SCOPE", '["fixture.test"]')
    monkeypatch.setenv("MINIPROXY_SCOPE_MODE", " BLOCK ")
    monkeypatch.setattr("miniproxy.runtime.resolve_mitmdump", lambda p: p)
    monkeypatch.setattr(server, "_read_pid", lambda: 1234)
    monkeypatch.setattr(server, "_process_exists", lambda _: True)
    monkeypatch.setattr(server, "_owned_process", lambda *a: True)
    observed = []
    original = server._preflight_policy
    monkeypatch.setattr(server, "_preflight_policy", lambda mode: observed.append(mode) or original(mode))
    assert server.start(dashboard=False)["status"] == "already_running"
    assert observed == ["block"]


def test_real_query_filters_before_cursor_page(db):
    target = db.store_request("GET", "https://fixture.test/api?debug=&flag", {}, "")
    for i in range(6):
        db.store_request("GET", f"https://noise.test/{i}", {}, "")
    result = automation.query(db, limit=1, host="fixture.test")
    assert result["count"] == 1 and result["items"][0]["id"] == target
    assert result["matched_count"] == 1 and result["total_captured"] == 7
    first = automation.query(db, limit=2)
    second = automation.query(db, limit=2, before_id=first["next_cursor"])
    assert first["has_more"] and not ({i["id"] for i in first["items"]} & {i["id"] for i in second["items"]})
    inventory = automation.endpoint_inventory(db, limit=1, host="fixture.test")
    assert inventory["complete"]
    assert inventory["endpoints"][0]["query_params"] == ["debug", "flag"]
    incomplete = automation.endpoint_inventory(db, limit=1)
    assert not incomplete["complete"] and incomplete["next_cursor"]


def test_cli_json_and_jsonl_are_typed(db, db_path, capsys):
    db.store_request("GET", "https://fixture.test/", {}, "")
    assert main(["log", "--db", db_path, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 1
    assert main(["export", "--db", db_path, "--format", "jsonl"]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["type"] for line in lines] == ["metadata", "flow"]
    assert main(["log", "--db", db_path, "--json", "--limit", "-1"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"
    assert main(["endpoints", "--db", db_path, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["complete"]


def test_cli_export_sqlite_error_is_json(monkeypatch, capsys):
    import sqlite3
    monkeypatch.setattr("miniproxy.__main__._open_db", lambda *args, **kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("fixture locked")))
    assert main(["export"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"


@pytest.mark.parametrize("command", ["log", "export", "endpoints"])
def test_missing_evidence_never_created(tmp_path, capsys, command):
    path = tmp_path / "missing.db"
    args = [command, "--db", str(path)] + (["--json"] if command == "log" else [])
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"
    assert not path.exists()


def test_jsonl_missing_evidence_typed_error(tmp_path, capsys):
    assert main(["export", "--format", "jsonl", "--db", str(tmp_path / "absent.db")]) == 2
    assert json.loads(capsys.readouterr().out)["type"] == "error"


def test_human_log_pending_and_filters(db, db_path, capsys):
    db.store_request("GET", "https://target.test/", {}, "")
    db.store_request("GET", "https://noise.test/", {}, "")
    assert main(["log", "--db", db_path, "--host", "target.test"]) == 0
    output = capsys.readouterr().out
    assert "pending" in output and "target.test" in output and "noise.test" not in output


def test_addon_manifest_matches_resources():
    manifest = automation.addon_manifest()
    assert set(manifest["resources"]) == {"proxy.py", "db.py", "intercept_addon.py"}
    assert all(len(digest) == 64 for digest in manifest["resources"].values())


def test_status_uses_launched_db_not_caller_environment(monkeypatch, tmp_path):
    pid_path = tmp_path / "proxy.pid"
    monkeypatch.setattr(server, "PID_FILE", pid_path)
    pid_path.write_text("1234")
    pid_path.with_suffix(".identity").write_text("fixture-identity")
    monkeypatch.setattr(server, "_process_exists", lambda pid: True)
    monkeypatch.setattr(server, "_owned_process", lambda *a: True)
    metadata = {"schema_version": 1, "pid": 1234, "process_identity": "fixture-identity",
                "db": str(tmp_path / "launched.db"), "session_id": "run-1"}
    server._write_state(server._manifest_path(pid_path), json.dumps(metadata))
    monkeypatch.setenv("MINIPROXY_DB_PATH", str(tmp_path / "different.db"))
    status = server.status()
    assert status["db"] == metadata["db"] and status["metadata_verified"]
    assert server._manifest_path(pid_path).stat().st_mode & 0o777 == 0o600


def test_status_does_not_reuse_manifest_for_wrong_identity(monkeypatch, tmp_path):
    pid_path = tmp_path / "proxy.pid"
    monkeypatch.setattr(server, "PID_FILE", pid_path)
    pid_path.write_text("1234")
    pid_path.with_suffix(".identity").write_text("new-run")
    server._write_state(server._manifest_path(pid_path), json.dumps({"schema_version": 1, "pid": 1234, "process_identity": "old-run", "db": "/old/capture.db"}))
    monkeypatch.setattr(server, "_process_exists", lambda _: True)
    monkeypatch.setattr(server, "_owned_process", lambda *a: True)
    monkeypatch.setenv("MINIPROXY_DB_PATH", "/different/capture.db")
    result = server.status()
    assert result["db"] is None and not result["metadata_verified"]


def test_dashboard_readiness_uses_concrete_interface(monkeypatch, tmp_path):
    for name in ("DASH_PID_FILE", "DASH_PORT_FILE", "DASH_HOST_FILE"):
        monkeypatch.setattr(server, name, tmp_path / name)
    monkeypatch.setattr(server, "_read_dash_pid", lambda: None)
    monkeypatch.setattr(server, "_port_free", lambda p: True)
    proc = SimpleNamespace(pid=1234)
    monkeypatch.setattr(server.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(server, "_publish_process_state", lambda *a: True)
    monkeypatch.setattr(server, "_publish_manifest", lambda *a: True)
    class Connection:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    probes = []
    monkeypatch.setattr(server.socket, "create_connection", lambda address, **k: probes.append(address) or Connection())
    result = server._ensure_dashboard(None, 5001, "192.0.2.10")
    assert result["status"] == "started"
    assert probes == [("192.0.2.10", 5001)]


def test_health_no_external_forwarding_claim(monkeypatch, db, db_path):
    monkeypatch.setattr(server, "status", lambda: {"status": "running", "pid": 1234, "port": 5001, "host": "127.0.0.1", "db": db_path})
    monkeypatch.setattr("miniproxy.runtime.environment_error", lambda: None)
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    def connect(address, **kwargs):
        assert address == ("127.0.0.1", 5001)
        return Connection()
    monkeypatch.setattr(server.socket, "create_connection", connect)
    result = server.health()
    assert result["ready"] and result["capture_ready"] and not result["forwarding_verified"]
