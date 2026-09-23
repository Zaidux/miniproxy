"""API tests for the Flask dashboard (app.py) — exports, filters, auth,
background intruder, proxy-state endpoints."""
from __future__ import annotations

import json
import time

import pytest


@pytest.fixture()
def seeded_db(db):
    rid = db.store_request("GET", "https://api.test/users?page=2", {"Host": "api.test"}, "")
    db.update_response(rid, 200, {"Content-Type": "application/json"},
                       '{"users": []}', "application/json", ttfb_ms=10.0, total_ms=42.0)
    rid2 = db.store_request("POST", "https://api.test/login", {}, "u=a&p=b")
    db.update_response(rid2, 401, {"Content-Type": "application/json"},
                       '{"error": "bad creds"}', "application/json")
    return rid


class TestLogEndpoints:
    def test_logs_and_detail(self, app_client, seeded_db):
        client, db, _ = app_client
        r = client.get("/api/logs")
        assert r.status_code == 200
        rows = r.get_json()
        assert len(rows) == 2 and rows[0]["id"] == 2  # newest first

        r = client.get(f"/api/logs/{seeded_db}")
        assert r.status_code == 200
        assert r.get_json()["response_body"] == '{"users": []}'

    def test_detail_404(self, app_client):
        client, _, _ = app_client
        assert client.get("/api/logs/9999").status_code == 404

    def test_server_side_filters(self, app_client, seeded_db):
        client, _, _ = app_client
        assert [r["method"] for r in client.get("/api/logs?method=POST").get_json()] == ["POST"]
        assert client.get("/api/logs?status=4").get_json()[0]["id"] == 2
        assert client.get("/api/logs?url=users").get_json()[0]["id"] == 1
        assert client.get("/api/logs?status=7").status_code == 400
        assert client.get("/api/logs/count?method=GET").get_json() == {"count": 1}


class TestExports:
    def test_har_structure(self, app_client, seeded_db):
        client, _, _ = app_client
        r = client.get("/api/export/har")
        assert r.status_code == 200
        assert r.headers["Content-Disposition"].startswith("attachment")
        har = r.get_json()
        entry = next(e for e in har["log"]["entries"] if e["_miniproxyId"] == 1)
        assert entry["request"]["method"] == "GET"
        assert entry["request"]["queryString"] == [{"name": "page", "value": "2"}]
        assert entry["response"]["status"] == 200
        assert entry["response"]["content"]["text"] == '{"users": []}'
        assert entry["timings"]["wait"] == 10.0

    def test_har_honors_filters(self, app_client, seeded_db):
        client, _, _ = app_client
        entries = client.get("/api/export/har?method=POST").get_json()["log"]["entries"]
        assert [e["request"]["method"] for e in entries] == ["POST"]

    def test_json_export(self, app_client, seeded_db):
        client, _, _ = app_client
        r = client.get("/api/export/json")
        rows = r.get_json()
        assert len(rows) == 2 and rows[0]["id"] == 2

    def test_db_snapshot(self, app_client, seeded_db):
        client, _, _ = app_client
        r = client.get("/api/export/db")
        assert r.status_code == 200
        assert r.data[:15] == b"SQLite format 3"

    def test_body_download_falls_back_to_request_body(self, app_client, seeded_db):
        client, _, _ = app_client
        r = client.get("/api/export/body/2")  # login: response body exists
        assert r.status_code == 200
        assert 'filename="login.json"' in r.headers["Content-Disposition"]
        assert r.data == b'{"error": "bad creds"}'
        assert client.get("/api/export/body/9999").status_code == 404

    def test_safe_filename(self, app_client, seeded_db):
        from miniproxy.app import _safe_filename

        assert _safe_filename('../../etc/passwd"') == "etcpasswd"
        assert _safe_filename("///") == "miniproxy"


class TestTokenAuth:
    @pytest.fixture()
    def tokened_client(self, app_client, monkeypatch):
        client, db, appmod = app_client
        monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", "sekret")
        return client

    def test_mutating_endpoints_require_token(self, tokened_client, seeded_db):
        client = tokened_client
        assert client.post("/api/clear").status_code == 401
        assert client.post("/api/clear", headers={"X-MiniProxy-Token": "nope"}).status_code == 401
        assert client.post("/api/clear", headers={"X-MiniProxy-Token": "sekret"}).status_code == 200

    def test_token_via_query_param(self, tokened_client, seeded_db):
        assert tokened_client.post("/api/proxy/toggle?token=sekret",
                                   json={"action": "start"}).status_code in (200, 503)

    def test_reads_stay_open(self, tokened_client, seeded_db):
        assert tokened_client.get("/api/logs").status_code == 200
        assert tokened_client.get("/api/meta").status_code == 200


class TestClear:
    def test_clear(self, app_client, seeded_db):
        client, db, _ = app_client
        r = client.post("/api/clear")
        assert r.status_code == 200 and r.get_json()["removed"] == 2
        assert db.get_logs() == []


class TestBackgroundIntruder:
    def test_full_lifecycle(self, app_client, seeded_db):
        client, db, _ = app_client
        r = client.post("/api/intruder/start",
                        json={"request_id": 1,
                              "wordlist": ["aa", "bb", "cc", "dd"]})
        assert r.status_code == 202 and r.get_json()["started"]

        for _ in range(100):
            st = client.get("/api/intruder/status").get_json()
            if not st["running"]:
                break
            time.sleep(0.05)
        assert st["count"] == 4 and not st["error"]
        assert len(st["results"]) == 4
        # persisted for the detail panes
        assert len(client.get("/api/intruder/results/1").get_json()) == 4

    def test_conflict_while_running(self, app_client, seeded_db, monkeypatch):
        import threading

        client, _, appmod = app_client

        gate = threading.Event()

        def slow_send(self, modified):
            gate.wait(timeout=5)
            return {"response_code": 200, "response_body": "x",
                    "response_headers": {}, "method": "GET",
                    "url": modified["url"], "headers": {}, "body": ""}

        # patch at class level so bound-method dispatch inside run_attack works
        from miniproxy.intruder import Intruder

        monkeypatch.setattr(Intruder, "_send", slow_send)
        r = client.post("/api/intruder/start",
                        json={"request_id": 1, "wordlist": ["a", "b"]})
        assert r.status_code == 202
        r2 = client.post("/api/intruder/start",
                         json={"request_id": 1, "wordlist": ["c"]})
        assert r2.status_code == 409
        gate.set()
        for _ in range(100):
            if not client.get("/api/intruder/status").get_json()["running"]:
                break
            time.sleep(0.05)

    def test_start_validation(self, app_client, seeded_db):
        client, _, _ = app_client
        assert client.post("/api/intruder/start", json={}).status_code == 400
        assert client.post("/api/intruder/start",
                           json={"request_id": 1}).status_code == 400
        assert client.post("/api/intruder/start",
                           json={"request_id": 999, "wordlist": ["a"]}).status_code == 404

    def test_wordlist_too_large_rejected(self, app_client, seeded_db):
        client, _, _ = app_client
        r = client.post("/api/intruder/start",
                        json={"request_id": 1, "wordlist": ["w"] * 1001})
        assert r.status_code == 202  # accepted, fails in the worker
        for _ in range(100):
            st = client.get("/api/intruder/status").get_json()
            if not st["running"]:
                break
            time.sleep(0.05)
        assert "too large" in (st["error"] or "")


class TestRepeater:
    def test_rejects_bad_input(self, app_client):
        client, _, _ = app_client
        assert client.post("/api/repeater/send", json={}).status_code == 400
        assert client.post("/api/repeater/send",
                           json={"url": ""}).status_code == 400
        r = client.post("/api/repeater/send",
                        json={"method": "GET", "url": "http://127.0.0.1:1/x",
                              "headers": {}, "body": ""})
        assert r.status_code == 500 and "error" in r.get_json()
