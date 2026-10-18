"""Regressions from the pre-release audits.

Each test here pins a defect that was found by reading the code rather than by
running the suite, and that had a real consequence: deleted captures, a lost
backup, a wrong diff verdict, or a destination filter that matched the wrong
host.
"""
from __future__ import annotations

import os
import sqlite3
import stat

import pytest

from miniproxy.addon.db import Database, NoiseBackupError, is_static_asset


# ── prune() must not empty the database chasing an unreachable size cap ──

def test_prune_stops_when_vacuum_cannot_reclaim(tmp_path):
    """The size loop deleted 100 rows per pass while `page_count` never moved.

    Deleting rows does not shrink `page_count` — only VACUUM does. So when
    VACUUM is blocked (a concurrent reader, a busy disk) the loop could never
    satisfy its own condition and deleted captures until the table was empty,
    silently. Measured before the fix: 249 of 249 rows removed in one call.
    """
    path = str(tmp_path / "proxy.db")
    db = Database(path)
    for i in range(300):
        db.store_request("GET", f"https://t/{i}", {}, "")
    db.max_db_bytes = 1  # unreachable, so the loop always wants to continue

    # Hold a read transaction on another connection: VACUUM raises
    # "database is locked", which prune() swallows.
    blocker = sqlite3.connect(path)
    blocker.execute("BEGIN")
    blocker.execute("SELECT count(*) FROM requests").fetchone()
    try:
        db.prune()
    finally:
        blocker.rollback()
        blocker.close()

    conn = sqlite3.connect(path)
    remaining = conn.execute("SELECT count(*) FROM requests").fetchone()[0]
    conn.close()
    assert remaining > 0, "prune() emptied the database trying to hit a size cap"


def test_prune_still_enforces_the_row_cap(tmp_path):
    """The guard must not disable the row cap, which is the other half."""
    db = Database(str(tmp_path / "proxy.db"))
    for i in range(50):
        db.store_request("GET", f"https://t/{i}", {}, "")
    db.max_rows = 10
    db.prune()
    conn = sqlite3.connect(str(tmp_path / "proxy.db"))
    assert conn.execute("SELECT count(*) FROM requests").fetchone()[0] == 10
    conn.close()


# ── noise cleanup must not delete without its backup ─────────────────

def test_clean_noise_aborts_when_the_backup_fails(tmp_path, monkeypatch):
    """The UI and CLI both promise a backup before deleting.

    `clean_noise` ignored `_backup_db()`'s empty-string failure return and
    deleted anyway, breaking exactly the promise that makes cleanup safe.
    """
    db = Database(str(tmp_path / "proxy.db"))
    db.add_noise_rule("noise.example", "host", True)
    db.store_request("GET", "https://noise.example/a", {}, "")
    assert db.scan_noise()["matched"] == 1

    monkeypatch.setattr(db, "_backup_db", lambda: "")
    with pytest.raises(NoiseBackupError):
        db.clean_noise()
    assert db.count_logs() == 1, "a capture was deleted despite the failed backup"


def test_clean_noise_still_deletes_when_the_backup_works(tmp_path):
    db = Database(str(tmp_path / "proxy.db"))
    db.add_noise_rule("noise.example", "host", True)
    db.store_request("GET", "https://noise.example/a", {}, "")
    result = db.clean_noise()
    assert result["removed"] == 1
    assert result["backup"] and os.path.isfile(result["backup"])
    assert db.count_logs() == 0


def test_noise_scan_honours_keep_hosts(tmp_path):
    """The preview ignored --keep-host, so it over-reported what Delete would
    remove (finding: dry-run count != delete count)."""
    db = Database(str(tmp_path / "proxy.db"))
    db.add_noise_rule("noise.example", "host", True)
    db.store_request("GET", "https://noise.example/a", {}, "")
    db.store_request("GET", "https://keep.example/b", {}, "")
    db.add_noise_rule("keep.example", "host", True)

    without = db.scan_noise()
    with_keep = db.scan_noise(keep_hosts=["keep.example"])
    assert without["matched"] == 2
    assert with_keep["matched"] == 1


# ── destination filters and static classification ────────────────────

def test_host_filter_is_exact_for_a_full_hostname(db):
    """Substring matching made host=example.com return notexample.com and
    example.com.evil — the wrong target's traffic."""
    for url in ("https://example.com/a", "https://notexample.com/b",
                "https://example.com.evil/c", "https://api.example.com/d"):
        db.store_request("GET", url, {}, "")
    hosts = sorted(r["url"].split("/")[2] for r in db.get_logs(host="example.com"))
    # The domain itself plus its subdomains, never a lookalike.
    assert hosts == ["api.example.com", "example.com"], hosts
    assert db.count_logs(host="example.com") == 2
    # A bare fragment keeps the convenience substring behaviour.
    assert db.count_logs(host="example") == 4


def test_hide_static_sql_matches_python_for_query_strings(db):
    """`app.js?v=1` is static to Python (it parses the path) but the SQL twin
    used `LIKE '%.js'`, which only matches the end of the URL."""
    db.store_request("GET", "https://t/app.js?v=1", {}, "")
    db.store_request("GET", "https://t/api/users", {}, "")

    rows = {r["url"]: r for r in db.get_logs(limit=10)}
    js = next(r for u, r in rows.items() if u.endswith("?v=1"))
    assert is_static_asset(js["url"], js["content_type"] or "") is True

    visible = {r["url"] for r in db.get_logs(limit=10, hide_static=True)}
    assert not any("app.js" in u for u in visible), visible
    assert any("api/users" in u for u in visible), visible


# ── the DB's own directory is the only one that gets tightened ───────

def test_hardening_does_not_chmod_a_shared_parent(tmp_path):
    """With `--db /tmp/lab.db` this used to chmod /tmp to 0700."""
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o755)
    Database(str(shared / "proxy.db"))
    assert stat.S_IMODE(os.stat(shared).st_mode) == 0o755


# ── the diff must not call a superset "identical" ────────────────────

def test_diff_superset_is_not_identical():
    """Token diff was one-directional, so a response that contained A plus
    extra content reported identical — the access-control question answered
    the wrong way."""
    from miniproxy.diff import diff_captures

    def row(body):
        return {"id": 1, "method": "GET", "url": "https://t/x",
                "response_code": 200, "response_body": body,
                "headers": {}, "body": ""}

    d = diff_captures(row("welcome user"), row("welcome user ADMIN SECRET"))
    assert d["identical"] is False
    assert d["body"]["only_b"] == ["ADMIN", "SECRET"]
    assert "only in B" in d["summary"], d["summary"]

    same = diff_captures(row("welcome user"), row("welcome user"))
    assert same["identical"] is True


# ── a foreign site must not be able to drive the dashboard ───────────

def test_cross_origin_post_is_refused(app_client):
    """An HTML form on any site could POST /api/clear with no preflight and
    wipe every capture."""
    client, db, _ = app_client
    db.store_request("GET", "https://t/a", {}, "")
    r = client.post("/api/clear", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403, r.status_code
    assert db.count_logs() == 1, "cross-origin POST cleared the captures"


def test_cross_site_fetch_metadata_is_refused(app_client):
    client, db, _ = app_client
    r = client.post("/api/clear", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_same_origin_post_is_allowed(app_client):
    client, db, _ = app_client
    db.store_request("GET", "https://t/a", {}, "")
    host = "localhost"
    r = client.post("/api/clear", headers={"Origin": f"http://{host}",
                                          "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200, r.get_json()


def test_cors_does_not_echo_a_lookalike_origin(app_client):
    """`startswith("http://127.0.0.1")` also matched 127.0.0.1.evil.example."""
    client, _, _ = app_client
    r = client.get("/api/meta",
                   headers={"Origin": "http://127.0.0.1.evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_cors_still_allows_the_dashboard_origin(app_client):
    client, _, _ = app_client
    r = client.get("/api/meta", headers={"Origin": "http://localhost"})
    assert r.headers.get("Access-Control-Allow-Origin") == "http://localhost"


# ── server start options ─────────────────────────────────────────────

def test_with_dashboard_false_suppresses_the_dashboard(monkeypatch):
    """`dashboard` defaults True, so `dashboard or with_dashboard` was always
    true and the flag could never suppress it — the header's Start button
    spawned a second dashboard."""
    from miniproxy import server

    calls = []
    monkeypatch.setattr(server, "_read_pid", lambda: 1234)
    monkeypatch.setattr(server, "_process_exists", lambda pid: True)
    monkeypatch.setattr(server, "_pid_matches", lambda pid, needle: True)
    monkeypatch.setattr(server, "_read_port", lambda: 8080)
    monkeypatch.setattr(server, "_ensure_dashboard",
                        lambda *a, **k: calls.append(a) or {"url": "http://x"})

    r = server.start(dashboard=True, with_dashboard=False)
    assert "dashboard" not in r, r
    assert calls == []

    r2 = server.start(dashboard=True, with_dashboard=True)
    assert r2.get("dashboard") == {"url": "http://x"}
    assert len(calls) == 1


def test_state_write_survives_a_missing_directory(tmp_path):
    """Writing the pid/port/host files was the last step of a start, so a
    missing directory left mitmdump running with no PID file."""
    from miniproxy import server

    target = tmp_path / "does" / "not" / "exist" / "mitmdump.host"
    server._write_state(target, "127.0.0.1")
    assert target.read_text() == "127.0.0.1"


# ── CLI aliases ──────────────────────────────────────────────────────

def test_web_alias_copies_scope_nargs():
    """`nargs` was not copied, so `miniproxy web --scope a b` was rejected
    while `miniproxy start --scope a b` worked."""
    import argparse

    from miniproxy.__main__ import _same_option

    src = argparse.ArgumentParser()
    src.add_argument("--scope", nargs="*", default=None)
    dst = argparse.ArgumentParser()
    dst.add_argument("--scope", **_same_option(src, "--scope"))

    assert dst.parse_args(["--scope", "a.example", "b.example"]).scope == [
        "a.example", "b.example"]
    # A bare --scope must not raise either.
    assert dst.parse_args(["--scope"]).scope == []


def test_host_filter_matches_a_url_with_a_port(db):
    """The SQL host slice keeps the port while host_of() strips it, so an
    exact comparison made `host=127.0.0.1` match nothing on
    `http://127.0.0.1:5347/` — every capture on a non-default port became
    unfilterable. Caught by smoking the installed wheel, not by the suite.
    """
    db.store_request("GET", "http://127.0.0.1:5347/login", {}, "")
    db.store_request("GET", "https://example.com:8443/a", {}, "")
    db.store_request("GET", "https://example.com/b", {}, "")

    assert db.count_logs(host="127.0.0.1") == 1
    assert db.count_logs(host="example.com") == 2
    assert db.count_logs(exclude_host="127.0.0.1") == 2
