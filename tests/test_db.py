"""Unit tests for the SQLite capture layer (addon/db.py)."""
from __future__ import annotations

import json

import pytest

from miniproxy.addon.db import MAX_BODY_BYTES, Database, STATUS_CLASSES


class TestBasics:
    def test_store_and_read(self, db):
        rid = db.store_request("GET", "https://x.test/a", {"Host": "x.test"}, "hello")
        row = db.get_request(rid)
        assert row["method"] == "GET"
        assert row["url"] == "https://x.test/a"
        assert json.loads(row["headers"]) == {"Host": "x.test"}
        assert row["body"] == "hello"

    def test_update_response_records_lengths(self, db):
        rid = db.store_request("POST", "https://x.test/b", {}, "req-body")
        db.update_response(rid, 200, {"CT": "text/plain"}, "resp-body", "text/plain",
                           ttfb_ms=1.5, total_ms=9.5)
        row = db.get_request(rid)
        assert row["response_code"] == 200
        assert row["request_body_len"] == len("req-body")
        assert row["response_body_len"] == len("resp-body")
        assert row["ttfb_ms"] == 1.5 and row["total_ms"] == 9.5

    def test_bodies_are_capped_with_original_length_kept(self, db):
        big = "X" * (MAX_BODY_BYTES + 50_000)
        rid = db.store_request("POST", "https://x.test/big", {}, big)
        db.update_response(rid, 200, {}, big, "application/json")
        row = db.get_request(rid)
        assert len(row["body"]) == MAX_BODY_BYTES
        assert row["request_body_len"] == len(big)
        assert len(row["response_body"]) == MAX_BODY_BYTES
        assert row["response_body_len"] == len(big)

    def test_error_marker(self, db):
        rid = db.store_request("GET", "https://x.test/err", {}, "")
        db.update_response_error(rid, "connection reset")
        row = db.get_request(rid)
        assert row["response_code"] == 0
        assert json.loads(row["response_headers"])["_error"] == "connection reset"

    def test_clear_removes_everything(self, db):
        rid = db.store_request("GET", "https://x.test/c", {}, "")
        db.update_response(rid, 200, {}, "b", "text/plain")
        db.store_intruder_results([{"request_id": rid, "payload": "p",
                                    "method": "GET", "url": "https://x.test/c",
                                    "headers": {}, "body": "",
                                    "response_code": 200, "response_body": "x",
                                    "response_headers": {}}])
        assert db.clear() == 1
        assert db.get_logs() == []
        assert db.get_intruder_results(rid) == []

    def test_count_logs(self, db):
        assert db.count_logs() == 0
        for i in range(3):
            db.store_request("GET", f"https://x.test/{i}", {}, "")
        assert db.count_logs() == 3


class TestServerSideFilters:
    @pytest.fixture()
    def seeded(self, db):
        ids = {}
        ids["get200"] = db.store_request("GET", "https://api.test/users?page=1", {}, "")
        db.update_response(ids["get200"], 200, {}, "{}", "application/json")
        ids["post404"] = db.store_request("POST", "https://api.test/login", {}, "")
        db.update_response(ids["post404"], 404, {}, "nope", "text/html")
        ids["pending"] = db.store_request("GET", "https://api.test/stream", {}, "")
        ids["err"] = db.store_request("GET", "https://api.test/dead", {}, "")
        db.update_response_error(ids["err"], "conn refused")
        return ids

    def test_method_filter(self, db, seeded):
        urls = {r["method"] for r in db.get_logs(method="get")}  # case-insensitive
        assert urls == {"GET"}
        assert all(r["method"] == "POST" for r in db.get_logs(method="POST"))

    def test_status_classes(self, db, seeded):
        assert [r["id"] for r in db.get_logs(status_class="2")] == [seeded["get200"]]
        assert [r["id"] for r in db.get_logs(status_class="4")] == [seeded["post404"]]
        assert [r["id"] for r in db.get_logs(status_class="pending")] == [seeded["pending"]]
        assert [r["id"] for r in db.get_logs(status_class="0")] == [seeded["err"]]

    def test_url_substring_case_insensitive(self, db, seeded):
        rows = db.get_logs(url_substr="USERS")
        assert len(rows) == 1 and rows[0]["id"] == seeded["get200"]

    def test_filters_combine(self, db, seeded):
        rows = db.get_logs(method="GET", status_class="2", url_substr="users")
        assert len(rows) == 1

    def test_invalid_status_class_raises(self, db, seeded):
        with pytest.raises(ValueError):
            db.get_logs(status_class="9")
        with pytest.raises(ValueError):
            db.get_logs(status_class="drop table")

    def test_status_classes_constant_is_complete(self):
        assert STATUS_CLASSES == {"2", "3", "4", "5", "0", "pending"}


class TestPruneThrottle:
    def test_store_request_does_not_prune_every_time(self, db_path, monkeypatch):
        from miniproxy.addon import db as dbmod

        calls = {"n": 0}
        real_prune = Database.prune

        def counting_prune(self):
            calls["n"] += 1
            return real_prune(self)

        monkeypatch.setattr(Database, "prune", counting_prune)
        d = Database(db_path)
        d._min_prune_interval = 60.0
        for i in range(20):
            d.store_request("GET", f"https://x/{i}", {}, "")
        assert calls["n"] <= 1, "prune must be throttled, not per-insert"

    def test_vacuum_failure_does_not_raise(self, db_path, monkeypatch):
        import sqlite3

        d = Database(db_path)
        real_connect = sqlite3.connect

        def flaky_connect(*a, **k):
            conn = real_connect(*a, **k)
            orig_execute = conn.execute

            class FlakyConn:
                # sqlite3.Connection attrs are read-only, so delegate instead
                def execute(self, sql, *aa, **kk):
                    if "VACUUM" in sql:
                        raise sqlite3.OperationalError("database is locked")
                    return orig_execute(sql, *aa, **kk)

                def __getattr__(self, name):
                    return getattr(conn, name)

            return FlakyConn()

        monkeypatch.setattr("miniproxy.addon.db.sqlite3.connect", flaky_connect)
        d.max_db_bytes = 1  # force the vacuum branch
        d.max_age_days = 0
        d.max_rows = 0
        d.store_request("GET", "https://x/v", {}, "")
        d.prune()  # must not raise

    def test_concurrent_writes_survive(self, db):
        import threading

        def worker(n):
            for i in range(10):
                db.store_request("GET", f"https://x/{n}-{i}", {}, "")

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert db.count_logs() == 40


class TestConfigKv:
    def test_set_get_delete_roundtrip(self, db):
        db.set_config("favorite", "burp")
        assert db.get_config("favorite") == "burp"
        assert db.get_config("missing", "fallback") == "fallback"
