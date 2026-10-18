"""Diffing two Intruder results against each other.

Intruder results live in `intruder_results` — a separate table with a separate
id space from captures — so the Diff tab could not reach them, even though
"which of these responses is the odd one out?" is exactly what the Diff engine
exists to answer.

The tests here cover the plumbing that made that possible and, just as
importantly, the guards that stop the id spaces being crossed:

  * results must carry their own row id (the client has nothing else to
    address them by);
  * a capture and an Intruder result must not be diffed against each other;
  * the pre-existing capture routes must behave exactly as they did.
"""
from __future__ import annotations

import time

import pytest

BODY_VALID = '{"error":"Invalid password"}'
BODY_NOISE = '{"error":"Invalid username that is not registered at all"}'


def _result(request_id, payload, url, code, body, headers=None):
    return {
        "request_id": request_id, "payload": payload, "method": "GET",
        "url": url, "headers": {}, "body": "", "response_code": code,
        "response_body": body, "response_headers": headers or {},
    }


@pytest.fixture()
def seeded(app_client):
    """One capture with two Intruder results that differ in status and size."""
    client, db, _ = app_client
    rid = db.store_request(method="GET", url="https://t/login?u=1",
                           headers={}, body="")
    db.store_intruder_results([
        _result(rid, "user=admin", "https://t/login?u=admin&p=x", 302,
                BODY_VALID, {"Location": "/home"}),
        _result(rid, "user=nobody", "https://t/login?u=nobody&p=x", 200, BODY_NOISE),
        _result(rid, "user=eve", "https://t/login?u=eve&p=x", 200, BODY_NOISE),
    ])
    return client, db, rid


# ── ids ─────────────────────────────────────────────────────────────

def test_store_intruder_results_stamps_row_ids(db):
    """The same list object is handed to the DB and then to the client, so
    the id is attached in place — without it the UI cannot ask for a
    diff of two of its own results."""
    rid = db.store_request(method="GET", url="https://t/l", headers={}, body="")
    rows = [_result(rid, f"u{i}", f"https://t/l?u={i}", 200, "x")
            for i in range(3)]
    db.store_intruder_results(rows)
    ids = [r.get("id") for r in rows]
    assert all(isinstance(i, int) for i in ids), ids
    assert len(set(ids)) == 3, ids


def test_get_intruder_result_fetches_one_row(seeded):
    _, db, _ = seeded
    row = db.get_intruder_result(1)
    assert row is not None
    assert row["payload"] == "user=admin"
    assert db.get_intruder_result(9999) is None


def test_stored_ids_match_what_the_client_would_see(seeded):
    client, db, _ = seeded
    listed = client.get("/api/intruder/results/1").get_json()
    for r in listed:
        assert db.get_intruder_result(r["id"])["payload"] == r["payload"]


# ── the diff route ──────────────────────────────────────────────────

def test_diff_of_two_results_names_the_enumeration_signal(seeded):
    client, _, _ = seeded
    r = client.get("/api/diff/intruder/1/2?include_bodies=1")
    assert r.status_code == 200
    d = r.get_json()
    assert d["status"] == "different"
    assert d["identical"] is False
    # The whole lab finding, in one summary.
    assert "302" in d["summary"] and "200" in d["summary"], d["summary"]
    assert "Invalid password" in d["summary"], d["summary"]
    assert "Invalid username" in d["summary"], d["summary"]
    # And structurally, in the JSON body diff.
    assert d["mode"] == "json"
    assert [c["path"] for c in d["body"]["changed"]] == ["error"]


def test_diff_reports_the_query_param_that_changed(seeded):
    client, _, _ = seeded
    d = client.get("/api/diff/intruder/1/2").get_json()
    assert "1 param(s)" in d["summary"], d["summary"]


def test_diff_reports_the_header_that_vanished(seeded):
    """admin got a 302 with Location: /home; the fake user got a plain 200.
    A has a header B does not, so it is reported as *removed* from B's side —
    naming it as "added" would read backwards in the diff."""
    client, _, _ = seeded
    d = client.get("/api/diff/intruder/1/2").get_json()
    assert [h["name"].lower() for h in d["headers"]["removed"]] == ["location"]
    assert d["headers"]["added"] == []


def test_diff_of_identical_results_says_same(app_client):
    """Identical means identical: same URL, same status, same body. The two
    seeded rows differ by their username param, so they are correctly
    "different" — proving the engine is not just comparing bodies."""
    client, db, _ = app_client
    rid = db.get_intruder_results(1)
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://t/l", headers={}, body="")
    same = dict(_result(cap, "a", "https://t/l", 200, "identical body"))
    same2 = dict(_result(cap, "b", "https://t/l", 200, "identical body"))
    db.store_intruder_results([same, same2])
    a, b = same["id"], same2["id"]
    d = client.get(f"/api/diff/intruder/{a}/{b}").get_json()
    assert d["status"] == "same"
    assert d["identical"] is True
    assert d["headers"]["identical"] is True
    assert d["params"]["identical"] is True


def test_same_status_different_param_is_still_reported_different(seeded):
    """`status` is the status-code verdict only. The two noise rows are both
    200 with the same body, but their username param differs — so `identical`
    must still be False and the param named. Reading `status` alone would
    wrongly conclude the two responses were the same."""
    client, _, _ = seeded
    d = client.get("/api/diff/intruder/2/3").get_json()
    assert d["status"] == "same", "both are 200"
    assert d["identical"] is False, "differing username param was not detected"
    assert [c["name"] for c in d["params"]["changed"]] == ["u"]


def test_body_is_withheld_unless_asked_for(seeded):
    """Keeps the default payload small enough to render instantly."""
    client, _, _ = seeded
    d = client.get("/api/diff/intruder/1/2").get_json()
    assert "body" not in d
    assert d["body_withheld"] is True


def test_bodies_endpoint_returns_both_sides(seeded):
    client, _, _ = seeded
    d = client.get("/api/diff/intruder/1/2/bodies").get_json()
    assert d["a"]["response_body"] == BODY_VALID
    assert d["b"]["response_body"] == BODY_NOISE


def test_explicit_mode_is_honoured(seeded):
    client, _, _ = seeded
    d = client.get("/api/diff/intruder/1/2?mode=token").get_json()
    assert d["mode"] == "token"


def test_invalid_mode_is_rejected(seeded):
    client, _, _ = seeded
    r = client.get("/api/diff/intruder/1/2?mode=nope")
    assert r.status_code == 400
    assert "invalid diff mode" in r.get_json()["error"]


# ── guards: never compare a row with itself or with nothing ─────────

def test_comparing_a_result_with_itself_is_refused(seeded):
    """A mis-click must not return a confident 'identical'."""
    client, _, _ = seeded
    r = client.get("/api/diff/intruder/1/1")
    assert r.status_code == 400
    assert "two different" in r.get_json()["error"]


def test_a_missing_result_is_a_404_naming_the_id(seeded):
    client, _, _ = seeded
    r = client.get("/api/diff/intruder/1/999")
    assert r.status_code == 404
    assert "999" in r.get_json()["error"]


def test_error_wording_distinguishes_the_two_id_spaces(seeded):
    """A capture id and a result id can both be '1'. The message must say
    which kind of row is missing."""
    client, _, rid = seeded
    intr = client.get("/api/diff/intruder/1/999").get_json()["error"]
    cap = client.get(f"/api/diff/{rid}/999").get_json()["error"]
    assert "Intruder result" in intr, intr
    assert intr != cap and "capture" in cap, (intr, cap)


# ── no regression on the capture routes ─────────────────────────────

def test_capture_diff_still_works(app_client):
    """The capture routes were refactored onto the shared helper; this proves
    they behave exactly as before."""
    client, db, _ = app_client
    a = db.store_request(method="GET", url="https://t/login", headers={}, body="")
    b = db.store_request(method="GET", url="https://t/login", headers={}, body="")
    d = client.get(f"/api/diff/{a}/{b}").get_json()
    assert d["status"] == "same"
    assert d["identical"] is True


def test_capture_same_row_still_refuses(seeded):
    client, _, rid = seeded
    r = client.get(f"/api/diff/{rid}/{rid}")
    assert r.status_code == 400
    assert "two different captures" in r.get_json()["error"]


def test_capture_bodies_still_work(seeded):
    client, db, rid = seeded
    db.store_request(method="GET", url="https://t/x", headers={}, body="")
    d = client.get(f"/api/diff/{rid}/{rid + 1}/bodies").get_json()
    assert "a" in d and "b" in d

def _spy(appmod, monkeypatch, seen, pitchfork=False):
    """Replace the intruder with a recorder. The real attack runs in a daemon
    thread, so the POST returns before run_attack has been called."""
    class Spy:
        MAX_WORDS = 1000
        MAX_COMBOS = 10_000

        # The durable runner drives attacks through run_items (one call per
        # flushed chunk), so that is the seam to record.
        def run_items(self, base, items, target_id):
            seen.update(base)
            return [{"request_id": target_id, "payload": i.get("label", ""),
                     "method": "GET", "url": base["url"], "headers": {},
                     "body": "", "response_code": 200,
                     "response_body": "x", "response_headers": {}}
                    for i in items]

        def build_items_single(self, wordlist):
            return [{"word": w, "payloads": None, "label": w} for w in wordlist]

        def build_items_pitchfork(self, lists):
            return [{"word": "", "payloads": {"u": "a"}, "label": "u=a"}]

        run_attack = run_items
        run_pitchfork = run_items

    monkeypatch.setattr(appmod, "intruder", Spy())
    return Spy


def _start_and_wait(client, payload, timeout=5.0):
    """POST the attack and wait for the background thread to record its base."""
    r = client.post("/api/intruder/start", json=payload)
    assert r.status_code in (200, 202), r.get_json()
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = client.get("/api/intruder/status").get_json()
        if st and not st.get("running"):
            return st
        time.sleep(0.05)
    raise AssertionError("attack never finished")


def test_edited_url_overrides_the_stored_capture(app_client, monkeypatch):
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://stored/original?u=§user§",
                           headers={}, body="")
    seen = {}
    _spy(appmod, monkeypatch, seen)
    _start_and_wait(client, {
        "request_id": cap,
        "base": {"method": "POST", "url": "https://edited/lab?u=§user§",
                 "headers": {"X-Test": "1"}, "body": "u=§user§"},
        "wordlist": ["admin"],
    })
    assert seen.get("url") == "https://edited/lab?u=§user§", seen
    assert seen.get("method") == "POST", seen
    assert seen.get("headers") == {"X-Test": "1"}, seen
    assert seen.get("body") == "u=§user§", seen


def test_omitted_base_falls_back_to_the_stored_capture(app_client, monkeypatch):
    """Older clients send only request_id; that path must keep working."""
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://stored/original?u=§user§",
                           headers={}, body="")
    seen = {}
    _spy(appmod, monkeypatch, seen)
    _start_and_wait(client, {"request_id": cap, "wordlist": ["a"]})
    assert seen.get("url") == "https://stored/original?u=§user§", seen


def test_empty_url_override_does_not_blank_the_capture(app_client, monkeypatch):
    """A cleared URL field must not produce a request with no URL."""
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://stored/x?u=§user§",
                           headers={}, body="")
    seen = {}
    _spy(appmod, monkeypatch, seen)
    _start_and_wait(client, {"request_id": cap,
                             "base": {"url": "   ", "headers": {}},
                             "wordlist": ["a"]})
    assert seen.get("url") == "https://stored/x?u=§user§", seen


def test_headers_can_be_cleared_deliberately(app_client, monkeypatch):
    """Clearing headers is different from omitting them."""
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://stored/y?u=§user§",
                           headers={}, body="")
    seen = {}
    _spy(appmod, monkeypatch, seen)
    _start_and_wait(client, {"request_id": cap,
                             "base": {"url": "https://edited/z?u=§user§", "headers": {}},
                             "wordlist": ["a"]})
    assert seen.get("url") == "https://edited/z?u=§user§", seen
    assert seen.get("headers") == {}, seen


# ── a request with nothing to substitute into is refused ────────────
#
# The dashboard checks this before starting, but a client-side guard cannot
# protect against a page loaded before an upgrade: old JavaScript sends only
# `request_id`, the server falls back to the stored capture, and a capture
# with no marker produced 101 byte-identical requests that looked exactly like
# a finished attack. This is the same check, enforced server-side.

def test_markerless_request_is_refused(app_client, monkeypatch):
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://t/login",
                           headers={"Cookie": "session=x"}, body="")
    called = []
    _spy(appmod, monkeypatch, {})
    monkeypatch.setattr(appmod, "intruder", type("S", (), {
        "MAX_WORDS": 1000, "MAX_COMBOS": 10_000,
        "run_items": lambda self, b, i, t: called.append(b) or [],
        "build_items_single": lambda self, w: [{"word": x, "payloads": None,
                                                "label": x} for x in w],
        "build_items_pitchfork": lambda self, l: [],
    })())
    r = client.post("/api/intruder/start",
                    json={"request_id": cap, "wordlist": ["admin", "bob"]})
    assert r.status_code == 400, r.get_json()
    assert "placeholder" in r.get_json()["error"], r.get_json()
    assert called == [], "an attack was started anyway"


def test_pitchfork_with_markers_only_in_one_position_actually_runs(app_client, monkeypatch):
    """A marker in the URL counts, even with an empty body."""
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://t/login", headers={}, body="")
    seen = {}
    _spy(appmod, monkeypatch, seen)
    _start_and_wait(client, {
        "request_id": cap,
        "base": {"url": "https://t/login?user=§user§"},
        "mode": "pitchfork", "lists": {"user": ["a"]},
    })
    assert seen.get("url") == "https://t/login?user=§user§", seen


def test_marker_in_a_header_counts(app_client, monkeypatch):
    """_apply_payload substitutes into header names and values too."""
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://t/x", headers={}, body="")
    seen = {}
    _spy(appmod, monkeypatch, seen)
    _start_and_wait(client, {
        "request_id": cap,
        "base": {"url": "https://t/x", "headers": {"X-Token": "§tok§"}},
        "wordlist": ["abc"],
    })
    assert seen.get("headers") == {"X-Token": "§tok§"}, seen


def test_stored_capture_with_markers_is_accepted_without_overrides(app_client, monkeypatch):
    """The old client path still works when the capture itself has markers."""
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://t/l?u=§u§", headers={}, body="")
    seen = {}
    _spy(appmod, monkeypatch, seen)
    _start_and_wait(client, {"request_id": cap, "wordlist": ["a"]})
    assert seen.get("url") == "https://t/l?u=§u§", seen


def test_non_numeric_request_id_is_a_400_not_a_500(app_client):
    """`int("abc")` propagated out of the route as a 500."""
    client, _, _ = app_client
    r = client.post("/api/intruder/start",
                    json={"request_id": "abc", "wordlist": ["a"]})
    assert r.status_code == 400, r.status_code
    assert "integer" in r.get_json()["error"]


def test_marker_only_in_a_header_satisfies_the_guard(app_client, monkeypatch):
    """The guard checks header names and values, which _apply_payload also
    substitutes into."""
    client, db, appmod = app_client
    cap = db.store_request(method="GET", url="https://t/x", headers={}, body="")
    seen = {}
    _spy(appmod, monkeypatch, seen)
    _start_and_wait(client, {
        "request_id": cap,
        "base": {"url": "https://t/x", "headers": {"Authorization": "Bearer §t§"}},
        "wordlist": ["abc"],
    })
    assert seen.get("headers") == {"Authorization": "Bearer §t§"}, seen
