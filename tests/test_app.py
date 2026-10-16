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


class TestAnnotationAndNoiseEndpoints:
    """Highlight/note PATCH, host rollup, and the noise rule/clean endpoints."""

    def test_patch_highlight_and_note(self, app_client, seeded_db):
        client, db, _ = app_client
        r = client.patch(f"/api/logs/{seeded_db}",
                         json={"highlight": "#3fb950", "note": "IDOR check"})
        assert r.status_code == 200
        assert r.get_json()["highlight"] == "#3fb950"
        assert r.get_json()["note"] == "IDOR check"
        # Only the supplied keys change.
        assert db.get_request(seeded_db)["highlight"] == "#3fb950"

    def test_patch_note_keeps_highlight(self, app_client, seeded_db):
        client, db, _ = app_client
        client.patch(f"/api/logs/{seeded_db}", json={"highlight": "#58a6ff"})
        client.patch(f"/api/logs/{seeded_db}", json={"note": "keep color"})
        assert db.get_request(seeded_db)["highlight"] == "#58a6ff"
        assert db.get_request(seeded_db)["note"] == "keep color"

    def test_patch_clear_highlight(self, app_client, seeded_db):
        client, db, _ = app_client
        client.patch(f"/api/logs/{seeded_db}", json={"highlight": "#f85149"})
        client.patch(f"/api/logs/{seeded_db}", json={"highlight": ""})
        assert db.get_request(seeded_db)["highlight"] is None

    def test_patch_rejects_offpalette_color(self, app_client, seeded_db):
        """Colors are interpolated into a style attribute, so this is the
        stored-XSS guard."""
        client, db, _ = app_client
        r = client.patch(f"/api/logs/{seeded_db}",
                         json={"highlight": "#3fb950;background:url(//evil)"})
        assert r.status_code == 400
        assert db.get_request(seeded_db)["highlight"] is None

    def test_patch_404(self, app_client):
        client, db, _ = app_client
        assert client.patch("/api/logs/9999", json={"highlight": "#3fb950"}).status_code == 404

    def test_host_filter_endpoints(self, app_client, seeded_db):
        client, db, _ = app_client
        assert client.get("/api/logs?host=api.test").get_json() == [
            *[r for r in client.get("/api/logs").get_json()]
        ]
        assert client.get("/api/logs?host=nope").get_json() == []
        assert client.get("/api/logs/count?host=api.test").get_json() == {"count": 2}
        hosts = client.get("/api/hosts").get_json()["hosts"]
        assert hosts[0]["host"] == "api.test"
        assert hosts[0]["count"] == 2

    def test_hide_static_filter_endpoints(self, app_client, seeded_db):
        client, db, _ = app_client
        rid = db.store_request("GET", "https://api.test/app.css", {}, "")
        db.update_response(rid, 200, {}, "body{}", "text/css")
        assert client.get("/api/logs/count").get_json() == {"count": 3}
        assert client.get("/api/logs/count?hide_static=1").get_json() == {"count": 2}
        assert client.get("/api/logs/count?hide_static=0").get_json() == {"count": 3}
        # Only the css row disappears.
        assert [r["id"] for r in client.get("/api/logs?hide_static=1").get_json()] == [2, 1]

    def test_highlighted_only_filter_endpoint(self, app_client, seeded_db):
        client, db, _ = app_client
        assert client.get("/api/logs/count?highlighted_only=1").get_json() == {"count": 0}
        client.patch(f"/api/logs/{seeded_db}", json={"highlight": "#39c5cf"})
        assert client.get("/api/logs/count?highlighted_only=1").get_json() == {"count": 1}

    def test_noise_rules_crud(self, app_client, seeded_db):
        client, db, _ = app_client
        assert client.get("/api/noise/rules").get_json()["palette"]
        # Bundled rules ship disabled.
        assert not any(r["enabled"] for r in client.get("/api/noise/rules").get_json()["rules"])

        r = client.post("/api/noise/rules", json={"value": "ads.example.com"})
        assert r.status_code == 201
        rule = [x for x in r.get_json()["rules"] if x["value"] == "ads.example.com"][0]
        assert rule["enabled"] == 1

        # Now capture-time blocking works.
        rid = db.store_request("GET", "https://ads.example.com/x", {}, "")
        assert db.is_noise("https://ads.example.com/x")

        client.patch(f"/api/noise/rules/{rule['id']}", json={"enabled": False})
        assert not db.is_noise("https://ads.example.com/x")

        assert client.delete(f"/api/noise/rules/{rule['id']}").status_code == 200
        assert client.delete(f"/api/noise/rules/{rule['id']}").status_code == 404

    def test_noise_rule_validation(self, app_client):
        client, db, _ = app_client
        assert client.post("/api/noise/rules", json={"value": ""}).status_code == 400
        assert client.post("/api/noise/rules", json={"value": "a/b"}).status_code == 400

    def test_enable_builtin_bundle(self, app_client, seeded_db):
        client, db, _ = app_client
        r = client.post("/api/noise/rules", json={"enable_builtin": True})
        assert all(x["enabled"] for x in r.get_json()["rules"])
        assert db.is_noise("https://incoming.telemetry.mozilla.org/v1/ping")

    def test_noise_scan_does_not_delete(self, app_client, seeded_db):
        client, db, _ = app_client
        client.post("/api/noise/rules", json={"enable_builtin": True})
        scan = client.get("/api/noise/scan").get_json()
        assert "matched" in scan and "keep" in scan
        assert db.count_logs() == 2  # nothing removed by a scan

    def test_noise_clean_requires_confirmation(self, app_client, seeded_db):
        client, db, _ = app_client
        client.post("/api/noise/rules", json={"enable_builtin": True})
        r = client.post("/api/noise/clean", json={})
        assert r.status_code == 400
        assert r.get_json()["error"] == "confirmation required"
        assert db.count_logs() == 2

    def test_noise_clean_with_confirmation(self, app_client, seeded_db):
        client, db, _ = app_client
        rid = db.store_request("GET", "https://incoming.telemetry.mozilla.org/v1/p", {}, "")
        db.update_response(rid, 200, {}, "x", "text/plain")
        client.post("/api/noise/rules", json={"enable_builtin": True})
        r = client.post("/api/noise/clean", json={"confirm": True})
        assert r.status_code == 200
        assert r.get_json()["removed"] == 1
        assert db.count_logs() == 2  # only the telemetry row went

    def test_noise_clean_rejects_bad_keep_hosts(self, app_client):
        client, db, _ = app_client
        r = client.post("/api/noise/clean", json={"confirm": True, "keep_hosts": "nope"})
        assert r.status_code == 400

    def test_exports_honor_new_filters(self, app_client, seeded_db):
        client, db, _ = app_client
        client.patch(f"/api/logs/{seeded_db}", json={"highlight": "#e3b341"})
        har = client.get("/api/export/har?highlighted_only=1").get_json()
        assert len(har["log"]["entries"]) == 1
        assert client.get("/api/export/json?host=api.test").get_json()


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
        try:
            assert tokened_client.post("/api/proxy/toggle?token=sekret",
                                       json={"action": "start"}).status_code in (200, 503)
        finally:
            # Starting spawns a real mitmdump. Without this stop the process
            # outlives the suite, and enough leaked runs exhaust the port
            # range — which then fails unrelated port/proxy tests in later
            # runs, looking like flaky random failures.
            tokened_client.post("/api/proxy/toggle?token=sekret",
                                json={"action": "stop"})

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
        """Oversized wordlists are refused synchronously.

        This used to be accepted with a 202 and then fail inside the worker,
        which meant the UI showed "attack started" before reporting an error.
        The size is known at request time, so the refusal happens up front.
        """
        client, _, _ = app_client
        r = client.post("/api/intruder/start",
                        json={"request_id": 1, "wordlist": ["w"] * 1001})
        assert r.status_code == 400
        assert "too large" in r.get_json()["error"]
        # No job was left behind in a running state.
        assert client.get("/api/intruder/status").get_json()["running"] is False

    def test_pitchfork_crosses_lists(self, app_client, seeded_db):
        """Different wordlists per placeholder — the pitchfork attack."""
        client, _, _ = app_client
        r = client.post("/api/intruder/start", json={
            "request_id": 1, "mode": "pitchfork",
            "lists": {"user": ["a", "b"], "pass": ["1", "2", "3"]},
        })
        assert r.status_code == 202
        assert r.get_json()["total"] == 6
        for _ in range(200):
            st = client.get("/api/intruder/status").get_json()
            if not st["running"]:
                break
            time.sleep(0.05)
        assert st["mode"] == "pitchfork"
        assert len(st["results"]) == 6
        # Each result names both substituted values, and all six combinations
        # are distinct — that is the whole point of pitchfork over "one word
        # into every position".
        labels = [x["payload"] for x in st["results"]]
        assert len(set(labels)) == 6
        assert all("user=" in l and "pass=" in l for l in labels)

    def test_pitchfork_rejects_bad_input(self, app_client, seeded_db):
        client, _, _ = app_client
        assert client.post("/api/intruder/start", json={
            "request_id": 1, "mode": "pitchfork", "lists": {},
        }).status_code == 400
        assert client.post("/api/intruder/start", json={
            "request_id": 1, "mode": "pitchfork", "lists": {"u": []},
        }).status_code == 400
        assert client.post("/api/intruder/start", json={
            "request_id": 1, "mode": "pitchfork", "lists": "nope",
        }).status_code == 400
        # 40000 combinations exceeds the cap.
        assert client.post("/api/intruder/start", json={
            "request_id": 1, "mode": "pitchfork",
            "lists": {"a": ["x"] * 200, "b": ["y"] * 200},
        }).status_code == 400


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
