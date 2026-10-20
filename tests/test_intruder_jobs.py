"""Attacks that outlive the browser (and the dashboard).

The user asked to be able to start a long run and walk away. Two things had to
be true for that:

  * the work queue is persisted, so the run does not depend on a page staying
    open, and a dashboard restart continues from where it stopped rather than
    losing the attack;
  * results are flushed as they arrive, so progress is visible and a crash
    costs at most one chunk.

These tests drive the real runner with `_send` patched (no network), asserting
on the database, which is the source of truth for a durable job.
"""
from __future__ import annotations

import time

import pytest

from miniproxy.intruder import Intruder


def _fast_send(self, modified):
    return {
        "response_code": 200, "response_body": "ok", "response_headers": {},
        "method": modified["method"], "url": modified["url"],
        "headers": modified["headers"], "body": modified["body"],
    }


def _wait_done(client, job_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/intruder/jobs/{job_id}").get_json()
        if job and job.get("status") != "running":
            return job
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} never finished")


@pytest.fixture()
def marker_capture(app_client):
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://t/l?u=§user§",
                           headers={}, body="")
    return client, db, appmod, cap


# ── the queue is persisted before anything is sent ───────────────────

def test_start_records_the_whole_queue(marker_capture, monkeypatch):
    client, db, appmod, cap = marker_capture
    monkeypatch.setattr(Intruder, "_send", _fast_send)
    r = client.post("/api/intruder/start", json={
        "request_id": cap, "wordlist": ["a", "b", "c"]})
    assert r.status_code == 202, r.get_json()
    job_id = r.get_json()["job_id"]

    job = db.get_intruder_job(job_id)
    assert job is not None
    assert job["total"] == 3
    assert job["status"] in ("running", "done")
    # The queue itself is stored, which is what makes resuming possible.
    assert [i["word"] for i in __import__("json").loads(job["items"])] == ["a", "b", "c"]


def test_results_are_persisted_with_the_job(marker_capture, monkeypatch):
    client, db, appmod, cap = marker_capture
    monkeypatch.setattr(Intruder, "_send", _fast_send)
    r = client.post("/api/intruder/start", json={
        "request_id": cap, "wordlist": [f"w{i}" for i in range(25)]})
    job_id = r.get_json()["job_id"]
    job = _wait_done(client, job_id)
    assert job["status"] == "done"
    assert job["count"] == 25
    assert job["progress"] == 25
    # Every row is tagged with the job that produced it.
    assert len(db.intruder_job_results(job_id)) == 25


def test_progress_is_visible_while_running(marker_capture, monkeypatch):
    """The point of flushing mid-run: progress is observable, not all-or-nothing."""
    client, db, appmod, cap = marker_capture
    seen = []

    def slow_send(self, modified):
        seen.append(modified["url"])
        time.sleep(0.01)
        return _fast_send(self, modified)

    monkeypatch.setattr(Intruder, "_send", slow_send)
    r = client.post("/api/intruder/start", json={
        "request_id": cap, "wordlist": [f"w{i}" for i in range(40)]})
    job_id = r.get_json()["job_id"]

    partial = None
    for _ in range(200):
        st = client.get("/api/intruder/status").get_json()
        if 0 < (st.get("progress") or 0) < 40:
            partial = st
            break
        time.sleep(0.01)
    assert partial is not None, "progress never appeared between 0 and 40"
    assert partial["running"] is True
    assert 0 < partial["count"] < 40

    _wait_done(client, job_id)


# ── resume after a restart ───────────────────────────────────────────

def test_a_running_job_resumes_from_where_it_stopped(marker_capture, monkeypatch):
    """A restart leaves status='running'; the next status poll continues it.

    Only the remaining items are sent — the completed ones are not re-run.
    """
    client, db, appmod, cap = marker_capture
    monkeypatch.setattr(Intruder, "_send", _fast_send)
    items = [{"word": f"w{i}", "payloads": None, "label": f"w{i}"}
             for i in range(10)]
    job_id = db.create_intruder_job(
        request_id=cap, mode="single",
        base={"method": "GET", "url": "https://t/l?u=§user§",
              "headers": {}, "body": ""},
        items=items)
    # Simulate a restart after four items.
    db.update_intruder_job(job_id, progress=4)

    # The status poll is what resumes (see _resume_intruder_jobs).
    client.get("/api/intruder/status")
    job = _wait_done(client, job_id)
    assert job["status"] == "done"
    assert job["progress"] == 10
    assert job["count"] == 6, "should send only the remaining six, not all ten"


def test_a_finished_job_is_not_resumed(marker_capture, monkeypatch):
    client, db, appmod, cap = marker_capture
    monkeypatch.setattr(Intruder, "_send", _fast_send)
    items = [{"word": "a", "payloads": None, "label": "a"}]
    job_id = db.create_intruder_job(
        request_id=cap, mode="single",
        base={"method": "GET", "url": "https://t/l?u=§user§",
              "headers": {}, "body": ""},
        items=items)
    db.update_intruder_job(job_id, status="done", progress=1)
    client.get("/api/intruder/status")
    time.sleep(0.1)
    assert db.get_intruder_job(job_id)["status"] == "done"
    assert db.intruder_job_results(job_id) == []


# ── cancel ───────────────────────────────────────────────────────────

def test_cancel_keeps_the_results_collected(marker_capture, monkeypatch):
    client, db, appmod, cap = marker_capture

    def slow_send(self, modified):
        time.sleep(0.02)
        return _fast_send(self, modified)

    monkeypatch.setattr(Intruder, "_send", slow_send)
    r = client.post("/api/intruder/start", json={
        "request_id": cap, "wordlist": [f"w{i}" for i in range(60)]})
    job_id = r.get_json()["job_id"]
    time.sleep(0.15)  # let a chunk or two land

    c = client.post("/api/intruder/cancel")
    assert c.status_code == 200, c.get_json()
    assert c.get_json()["job_id"] == job_id

    job = _wait_done(client, job_id, timeout=8)
    assert job["status"] == "cancelled"
    assert job["count"] > 0, "cancelling threw away the collected results"
    assert job["count"] < 60


def test_cancel_with_nothing_running_is_a_404(app_client):
    client, _, _ = app_client
    assert client.post("/api/intruder/cancel").status_code == 404


# ── reattaching ──────────────────────────────────────────────────────

def test_status_reports_a_job_the_page_can_reattach_to(marker_capture, monkeypatch):
    client, db, appmod, cap = marker_capture
    monkeypatch.setattr(Intruder, "_send", _fast_send)
    r = client.post("/api/intruder/start", json={
        "request_id": cap, "wordlist": ["a", "b"]})
    job_id = r.get_json()["job_id"]
    _wait_done(client, job_id)

    st = client.get("/api/intruder/status").get_json()
    assert st["job_id"] == job_id
    assert st["request_id"] == cap
    assert st["status"] == "done"
    assert len(st["results"]) == 2
    assert st["durable"] is True


def test_second_start_is_refused_while_one_runs(marker_capture, monkeypatch):
    client, db, appmod, cap = marker_capture

    def slow_send(self, modified):
        time.sleep(0.05)
        return _fast_send(self, modified)

    monkeypatch.setattr(Intruder, "_send", slow_send)
    first = client.post("/api/intruder/start", json={
        "request_id": cap, "wordlist": [f"w{i}" for i in range(30)]})
    assert first.status_code == 202
    second = client.post("/api/intruder/start", json={
        "request_id": cap, "wordlist": ["x"]})
    assert second.status_code == 409, second.get_json()
    client.post("/api/intruder/cancel")
    _wait_done(client, first.get_json()["job_id"], timeout=8)


# ── the `{{name}}` alias ─────────────────────────────────────────────

def test_double_brace_markers_are_accepted_everywhere(marker_capture, monkeypatch):
    """`§` cannot be typed on a phone keyboard, so {{name}} is an alias."""
    client, db, appmod, cap = marker_capture
    monkeypatch.setattr(Intruder, "_send", _fast_send)
    r = client.post("/api/intruder/start", json={
        "request_id": cap,
        "base": {"url": "https://t/l?u={{user}}", "headers": {}, "body": ""},
        "wordlist": ["admin"]})
    assert r.status_code == 202, r.get_json()
    job = _wait_done(client, r.get_json()["job_id"])
    rows = db.intruder_job_results(job["job_id"])
    assert rows[0]["url"] == "https://t/l?u=admin", rows[0]["url"]


def test_engine_treats_both_marker_forms_identically():
    i = Intruder()
    assert i.find_placeholders("?a={{x}}&b=§y§") == ["x", "y"]
    assert (i.replace_placeholders("?a={{x}}&b=§y§", "", {"x": "1", "y": "2"})
            == "?a=1&b=2")


def test_clear_drops_finished_jobs_but_keeps_a_running_one(marker_capture):
    """After Clear, reattaching to a "finished — 0 requests" job is confusing
    and wrong. A running job's row must survive, because its thread is still
    writing progress into it."""
    client, db, appmod, cap = marker_capture
    done = db.create_intruder_job(
        request_id=cap, mode="single",
        base={"method": "GET", "url": "https://t/?u=§u§", "headers": {}, "body": ""},
        items=[{"word": "a", "payloads": None, "label": "a"}])
    db.update_intruder_job(done, status="done", progress=1)
    live = db.create_intruder_job(
        request_id=cap, mode="single",
        base={"method": "GET", "url": "https://t/?u=§u§", "headers": {}, "body": ""},
        items=[{"word": "b", "payloads": None, "label": "b"}])

    db.clear()
    assert db.get_intruder_job(done) is None
    assert db.get_intruder_job(live) is not None


# ── replaying a request must not lie about its body ─────────────────
#
# A captured Content-Length describes the captured body. Editing the body (or
# a textarea normalising CRLF) leaves it stale, and the server then reads the
# wrong number of bytes: too few and it stops mid-part, too many and it waits.
# PortSwigger's avatar lab reported "Missing parameter 'csrf'" for exactly this.

def test_repeater_recomputes_content_length(app_client):
    import socket
    import threading

    received = {}

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                data += conn.recv(4096)
            head, _, rest = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
            while len(rest) < length:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                rest += chunk
            received["length"] = length
            received["body"] = rest[:length]
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        finally:
            conn.close()
            srv.close()

    threading.Thread(target=serve, daemon=True).start()

    client, _, _ = app_client
    body = "x" * 40
    r = client.post("/api/repeater/send", json={
        "method": "POST",
        # deliberately the stale captured value
        "headers": {"Content-Length": "999", "Content-Type": "text/plain"},
        "url": f"http://127.0.0.1:{port}/x",
        "body": body,
    })
    assert r.status_code == 200, r.get_json()
    assert received.get("length") == len(body), received
    assert received.get("body") == body.encode(), received


def test_intruder_ignores_a_captured_content_length():
    """Same defect in the fuzzing path: the payload changes the body length."""
    from miniproxy.intruder import Intruder

    i = Intruder()
    mod = i._apply_payload(
        {"method": "POST", "url": "https://t/x",
         "headers": {"Content-Length": "533", "Content-Type": "text/plain"},
         "body": "csrf=§t§"}, "abc")
    headers = {k.lower(): v for k, v in mod["headers"].items()}
    assert "content-length" not in headers, headers
    assert "transfer-encoding" not in headers, headers
    assert "content-type" in headers, headers
