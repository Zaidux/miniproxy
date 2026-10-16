"""CLI tests for `miniproxy noise` — rules and cleanup.

These run the real argparse entry point against a temp capture DB, so the
verb wiring, the confirmation gate and the exit codes are all covered.
"""
from __future__ import annotations

import sqlite3

import pytest

from miniproxy.__main__ import main


@pytest.fixture()
def noisy_db(tmp_path, monkeypatch):
    """A small capture DB with browser noise plus two target rows."""
    db_path = tmp_path / "proxy.db"
    monkeypatch.setenv("MINIPROXY_DB_PATH", str(db_path))
    rows = [
        ("GET", "https://target.example/api/users", 200, "application/json"),
        ("GET", "https://target.example/login", 200, "text/html"),
        ("GET", "https://img-getpocket.cdn.mozilla.net/1/x.jpeg", 200, "image/jpeg"),
        ("GET", "https://incoming.telemetry.mozilla.org/v1/ping", 200, "text/plain"),
        ("GET", "https://target.example/app.css", 200, "text/css"),
    ]
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
        method TEXT NOT NULL, url TEXT NOT NULL, headers TEXT, body TEXT,
        response_code INTEGER, response_headers TEXT, response_body TEXT,
        content_type TEXT, ttfb_ms REAL, total_ms REAL,
        request_body_len INTEGER, response_body_len INTEGER,
        highlight TEXT, note TEXT)""")
    for method, url, code, ct in rows:
        conn.execute(
            "INSERT INTO requests (timestamp, method, url, response_code, "
            "content_type, response_headers, response_body, request_body_len, "
            "response_body_len) VALUES (?,?,?,?,?,?,?,0,0)",
            ("2026-01-01T00:00:00+00:00", method, url, code, ct, "{}", "{}", ),
        )
    conn.commit()
    conn.close()
    return db_path


def _count(db_path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    finally:
        conn.close()


class TestNoiseList:
    def test_bundled_rules_listed_disabled(self, noisy_db, capsys):
        assert main(["noise", "list"]) == 0
        out = capsys.readouterr().out
        assert "incoming.telemetry.mozilla.org" in out
        assert "(bundled)" in out
        assert "0/" in out  # everything ships disabled

    def test_db_flag_is_honored(self, tmp_path, noisy_db, capsys):
        other = tmp_path / "other.db"
        assert main(["noise", "list", "--db", str(other)]) == 0
        assert other.is_file()


class TestNoiseAddRemove:
    def test_add_creates_enabled_rule(self, noisy_db, capsys):
        assert main(["noise", "add", "ads.example.com"]) == 0
        assert "added rule" in capsys.readouterr().out
        main(["noise", "list"])
        out = capsys.readouterr().out
        assert "ads.example.com" in out

    def test_add_requires_a_host(self, noisy_db):
        # argparse enforces the minimum itself, so this is an argparse exit.
        with pytest.raises(SystemExit) as exc:
            main(["noise", "add"])
        assert exc.value.code == 2

    def test_add_rejects_path(self, noisy_db, capsys):
        assert main(["noise", "add", "example.com/a/b"]) == 2
        assert "error" in capsys.readouterr().err

    def test_rm_normalizes_wildcard(self, noisy_db, capsys):
        # Stored with a wildcard, removed by the bare domain either way.
        main(["noise", "add", "*.youtube.com"])
        assert main(["noise", "rm", "youtube.com"]) == 0
        assert main(["noise", "rm", "youtube.com"]) == 1

    def test_rm_missing_rule(self, noisy_db, capsys):
        assert main(["noise", "rm", "never.example"]) == 1
        assert "no rule for" in capsys.readouterr().err


class TestNoiseEnableDisable:
    def test_enable_all_with_no_hosts(self, noisy_db, capsys):
        assert main(["noise", "enable"]) == 0
        out = capsys.readouterr().out
        assert "all rules" in out
        main(["noise", "list"])
        # Every bundled rule is now on.
        tail = capsys.readouterr().out.strip().splitlines()[-1]
        enabled, total = tail.split()[0].split("/")
        assert enabled == total

    def test_disable_all(self, noisy_db, capsys):
        main(["noise", "enable"])
        capsys.readouterr()
        assert main(["noise", "disable"]) == 0
        main(["noise", "list"])
        tail = capsys.readouterr().out.strip().splitlines()[-1]
        assert tail.strip().startswith("0/")

    def test_toggle_single_rule(self, noisy_db, capsys):
        main(["noise", "add", "one.example"])
        assert main(["noise", "disable", "one.example"]) == 0
        assert "1 rule(s): 1 disabled" in capsys.readouterr().out
        assert main(["noise", "enable", "one.example"]) == 0
        assert "1 enabled" in capsys.readouterr().out

    def test_enable_unknown_host(self, noisy_db, capsys):
        assert main(["noise", "enable", "nope.example"]) == 1
        assert "no matching rules" in capsys.readouterr().err


class TestNoiseScan:
    def test_scan_reports_without_deleting(self, noisy_db, capsys):
        assert main(["noise", "scan"]) == 0
        out = capsys.readouterr().out
        assert "would be removed" in out
        assert "Nothing was deleted" in out
        assert _count(noisy_db) == 5

    def test_scan_reflects_enabled_rules(self, noisy_db, capsys):
        main(["noise", "enable"])
        capsys.readouterr()
        main(["noise", "scan"])
        out = capsys.readouterr().out
        # pocket image + telemetry ping + app.css = 3 of 5
        assert "3 capture(s) would be removed" in out
        assert "2 kept" in out
        assert _count(noisy_db) == 5


class TestNoiseClean:
    def test_requires_yes_flag(self, noisy_db, capsys):
        main(["noise", "enable"])
        capsys.readouterr()
        assert main(["noise", "clean"]) == 1
        assert "--yes" in capsys.readouterr().out
        assert _count(noisy_db) == 5

    def test_clean_deletes_noise_and_keeps_target(self, noisy_db, capsys, tmp_path):
        main(["noise", "enable"])
        capsys.readouterr()
        assert main(["noise", "clean", "--yes"]) == 0
        assert "removed 3" in capsys.readouterr().out
        assert _count(noisy_db) == 2
        # A backup was written next to the DB.
        assert list(tmp_path.glob("*.noise-backup-*.db"))

    def test_keep_host_protects_it(self, noisy_db, capsys):
        main(["noise", "enable"])
        capsys.readouterr()
        assert main(["noise", "clean", "--yes",
                     "--keep-host", "target.example"]) == 0
        # All 5 rows belong to target.example once noise hosts are protected.
        assert _count(noisy_db) == 3  # the static app.css is still noise

    def test_clean_noop(self, tmp_path, capsys):
        # A capture DB with only clean, non-static target rows.
        path = tmp_path / "clean.db"
        import os

        os.environ["MINIPROXY_DB_PATH"] = str(path)
        from miniproxy.addon.db import Database

        d = Database(path)
        rid = d.store_request("GET", "https://target.example/api", {}, "")
        d.update_response(rid, 200, {}, '{"ok":1}', "application/json")
        try:
            assert main(["noise", "clean", "--yes"]) == 0
            assert "nothing to clean" in capsys.readouterr().out
            assert d.count_logs() == 1
        finally:
            os.environ.pop("MINIPROXY_DB_PATH", None)

    def test_backup_contains_the_deleted_rows(self, noisy_db, capsys, tmp_path):
        main(["noise", "enable"])
        capsys.readouterr()
        main(["noise", "clean", "--yes"])
        out = capsys.readouterr().out
        backup = next(tmp_path.glob("*.noise-backup-*.db"))
        conn = sqlite3.connect(backup)
        try:
            # Restorable: the pre-clean rows are all in the backup.
            assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 5
        finally:
            conn.close()