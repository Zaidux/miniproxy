"""Behavioral regressions for MiniProxy's capture/persistence core."""
from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from mitmproxy import http

from miniproxy.addon.db import Database, MAX_BODY_BYTES
from miniproxy.addon.intercept_addon import (
    InterceptAddon,
    _consume_decision,
    _push_decision,
    _retire_pending,
    resolve_intercept_state_paths,
)
from miniproxy.addon.proxy import MiniProxyAddon, _is_api_content, _API_CONTENT_TYPES


class RewriteDB:
    def __init__(self, rule):
        self.rule = rule
        self.stored = None

    def is_noise(self, _url):
        return False

    def get_rewrite_rules(self, **_kwargs):
        return [self.rule]

    def store_request(self, *args, **kwargs):
        if args:
            kwargs = dict(zip(("method", "url", "headers", "body"), args)) | kwargs
        self.stored = kwargs
        return 1


def _capture_addon(rule, scope=None):
    addon = MiniProxyAddon.__new__(MiniProxyAddon)
    addon.db = RewriteDB(rule)
    addon.scope = scope
    addon.scope_mode = "block"
    addon.allowed_scope = None
    addon.excluded_scope = None
    return addon


def test_structured_suffix_content_types_are_captured():
    assert "application/json" in _API_CONTENT_TYPES
    for value in (
        "application/problem+json",
        "application/vnd.api+json; charset=utf-8",
        "application/graphql-response+json",
        "application/soap+xml",
    ):
        assert _is_api_content(value), value
    assert not _is_api_content("text/event-stream")
    assert not _is_api_content("application/octet-stream")
    assert not _is_api_content("image/svg+xml")


def test_structured_response_body_and_duplicate_headers_are_persisted(db):
    addon = MiniProxyAddon.__new__(MiniProxyAddon)
    addon.db = db
    req = http.Request.make("GET", "https://api.test/problem")
    rid = db.store_request("GET", req.pretty_url, {}, "")
    response = http.Response.make(
        422,
        b'{"error":"bad"}',
        http.Headers([
            (b"Content-Type", b"application/problem+json"),
            (b"Set-Cookie", b"a=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT"),
            (b"Set-Cookie", b"b=2"),
        ]),
    )
    flow = SimpleNamespace(request=req, response=response, _miniproxy_id=rid)

    addon.responseheaders(flow)
    assert not response.stream
    addon.response(flow)

    row = db.get_request(rid)
    assert row["response_body"] == '{"error":"bad"}'
    assert row["response_body_state"] == "complete"
    fields = json.loads(row["response_headers_raw"])
    assert [v for n, v in fields if n.lower() == "set-cookie"] == [
        "a=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT",
        "b=2",
    ]
    # Frozen/legacy consumers still receive the object-shaped field.
    assert isinstance(json.loads(row["response_headers"]), dict)


def test_streamed_body_has_truthful_omission_state(db):
    addon = MiniProxyAddon.__new__(MiniProxyAddon)
    addon.db = db
    rid = db.store_request("GET", "https://api.test/file", {}, "")
    response = http.Response.make(
        200, b"binary", {"Content-Type": "application/octet-stream"}
    )
    flow = SimpleNamespace(response=response, _miniproxy_id=rid)

    addon.responseheaders(flow)
    assert response.stream is True
    addon.response(flow)

    row = db.get_request(rid)
    assert row["response_body"] is None
    assert row["response_body_len"] is None
    assert row["response_body_state"] == "omitted"
    assert row["response_body_omitted_reason"] == "content_type_policy"
    assert row["flow_outcome"] == "completed"


def test_body_caps_count_utf8_bytes_and_keep_valid_text(tmp_path, monkeypatch):
    monkeypatch.setenv("MINIPROXY_MAX_BODY_BYTES", "7")
    db = Database(tmp_path / "bytes.db")
    body = "😀😀😀"
    rid = db.store_request("POST", "https://x.test", {}, body)
    db.update_response(rid, 200, {}, body, "application/json")
    row = db.get_request(rid)
    assert row["request_body_len"] == 12
    assert row["response_body_len"] == 12
    assert row["body"] == "😀"
    assert row["response_body"] == "😀"
    assert len(row["body"].encode()) <= 7
    assert row["request_body_state"] == "truncated"
    assert row["response_body_state"] == "truncated"


def test_host_rewrite_survives_unscoped_full_hook():
    addon = _capture_addon({
        "target": "header", "kind": "exact", "match": "Host",
        "replace": "rewritten.test", "enabled": 1,
    })
    request = http.Request.make(
        "GET", "https://acme.test/path", headers={"Host": "acme.test"}
    )
    flow = SimpleNamespace(request=request, response=None)

    addon.request(flow)

    assert flow.response is None
    assert request.host == "acme.test"  # connection routing is unchanged
    assert request.headers["Host"] == "rewritten.test"
    assert request.pretty_url == "https://rewritten.test/path"
    assert addon.db.stored["url"] == "https://rewritten.test/path"
    assert addon.db.stored["headers"]["Host"] == "rewritten.test"


def test_host_rewrite_is_scope_checked_on_actual_final_authority():
    addon = _capture_addon({
        "target": "header", "kind": "exact", "match": "Host",
        "replace": "outside.test", "enabled": 1,
    }, scope=["acme.test"])
    request = http.Request.make(
        "GET", "https://acme.test/path", headers={"Host": "acme.test"}
    )
    flow = SimpleNamespace(request=request, response=None)

    addon.request(flow)

    assert flow.response.status_code == 403
    assert addon.db.stored is None


def _intercept_addon(db, state_file, decision_file, decision):
    addon = InterceptAddon.__new__(InterceptAddon)
    addon.db = db
    addon.scope = None
    addon.scope_mode = "skip"
    addon.allowed_scope = None
    addon.excluded_scope = None
    addon._intercept_enabled = True
    addon._rules = []
    addon._lock = __import__("threading").Lock()
    addon.state_file = state_file
    addon.decision_file = decision_file

    async def decide(_flow_id):
        return decision

    addon._wait_for_decision = decide
    return addon


def _flow(url="https://acme.test/a"):
    request = http.Request.make(
        "POST", url, content=b"old", headers={"X-Original": "yes"}
    )
    return SimpleNamespace(
        request=request,
        response=None,
        intercept=Mock(),
        resume=Mock(),
        kill=Mock(),
    )


def test_modified_intercept_stores_exact_sent_request_and_retires_queue(
    tmp_path, db,
):
    state = tmp_path / "state" / "intercept_queue.json"
    decisions = tmp_path / "state" / "intercept_decisions.json"
    addon = _intercept_addon(db, state, decisions, {
        "action": "modify",
        "modified_request": {
            "method": "PUT",
            "url": "https://changed.test/new",
            "headers": {"Host": "changed.test", "X-New": "2"},
            "body": "new-body",
        },
    })
    addon._init_queue()
    addon._init_decisions()
    flow = _flow()

    asyncio.run(addon.request(flow))

    row = db.get_request(flow._miniproxy_id)
    assert row["method"] == "PUT"
    assert row["url"] == "https://changed.test/new"
    assert row["body"] == "new-body"
    assert json.loads(row["headers"])["X-New"] == "2"
    assert row["intercept_action"] == "modified"
    assert json.loads(state.read_text())["pending"] == []
    flow.resume.assert_called_once()
    flow.kill.assert_not_called()


def test_intercept_toggle_off_still_captures_without_pausing(tmp_path, db):
    state = tmp_path / "off" / "intercept_queue.json"
    decisions = tmp_path / "off" / "intercept_decisions.json"
    addon = _intercept_addon(db, state, decisions, None)
    addon._intercept_enabled = False
    addon._init_queue()
    addon._init_decisions()
    addon._wait_for_decision = Mock(side_effect=AssertionError("must not wait"))
    flow = _flow()

    asyncio.run(addon.request(flow))

    row = db.get_request(flow._miniproxy_id)
    assert row["url"] == flow.request.pretty_url
    flow.intercept.assert_not_called()
    flow.resume.assert_not_called()
    assert json.loads(state.read_text())["pending"] == []


@pytest.mark.parametrize(
    "decision,action,outcome,resumed,killed",
    [
        (None, "timed_out_forwarded", "pending", True, False),
        ({"action": "drop"}, "dropped", "dropped", False, True),
    ],
)
def test_intercept_timeout_and_drop_have_explicit_outcomes(
    tmp_path, db, decision, action, outcome, resumed, killed,
):
    state = tmp_path / action / "intercept_queue.json"
    decisions = tmp_path / action / "intercept_decisions.json"
    addon = _intercept_addon(db, state, decisions, decision)
    addon._init_queue()
    addon._init_decisions()
    flow = _flow()

    asyncio.run(addon.request(flow))

    row = db.get_request(flow._miniproxy_id)
    assert row["intercept_action"] == action
    assert row["flow_outcome"] == outcome
    assert bool(flow.resume.called) is resumed
    assert bool(flow.kill.called) is killed
    assert json.loads(state.read_text())["pending"] == []


def test_intercept_state_is_private_and_decisions_are_atomically_retired(tmp_path):
    state_dir = tmp_path / "session-state"
    queue, decisions = resolve_intercept_state_paths(state_dir)
    assert queue.parent == state_dir.resolve()
    assert decisions.parent == state_dir.resolve()

    assert _push_decision("id", {"action": "forward"}, decisions)
    assert stat.S_IMODE(decisions.stat().st_mode) == 0o600
    assert _consume_decision("id", decisions) == {"action": "forward"}
    assert _consume_decision("id", decisions) is None

    queue.write_text(json.dumps({
        "pending": [{"id": "id"}, {"id": "other"}, {"id": "id"}],
        "mode": "intercept",
    }))
    assert _retire_pending("id", queue)
    assert [x["id"] for x in json.loads(queue.read_text())["pending"]] == ["other"]


def test_path_deployed_legacy_queue_paths_remain_supported(tmp_path, monkeypatch):
    monkeypatch.delenv("MINIPROXY_INTERCEPT_STATE_DIR", raising=False)
    deployed = tmp_path / "deployed-addon"
    deployed.mkdir()
    (deployed / "intercept_queue.json").write_text('{"pending":[]}')
    queue, decisions = resolve_intercept_state_paths(addon_dir=deployed)
    assert queue == deployed / "intercept_queue.json"
    assert decisions == deployed / "intercept_decisions.json"


def test_har_uses_ordered_raw_headers_and_capture_state(app_client):
    client, db, _ = app_client
    rid = db.store_request(
        "GET", "https://x.test", {"X-Test": "a, b"}, "",
        raw_headers=[["X-Test", "a"], ["X-Test", "b"]],
    )
    db.update_response_light(
        rid, 200, {"Set-Cookie": "a=1, b=2"}, "application/octet-stream",
        raw_headers=[["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]],
        omitted_reason="content_type_policy",
    )

    entry = client.get(f"/api/export/har?id={rid}").get_json()["log"]["entries"][0]
    assert entry["request"]["headers"] == [
        {"name": "X-Test", "value": "a"},
        {"name": "X-Test", "value": "b"},
    ]
    assert entry["response"]["headers"] == [
        {"name": "Set-Cookie", "value": "a=1"},
        {"name": "Set-Cookie", "value": "b=2"},
    ]
    assert entry["response"]["_bodyCaptureState"] == "omitted"
    assert entry["response"]["bodySize"] == -1
    assert entry["response"]["_bodyStoredSize"] == 0
    assert "content_type_policy" in entry["response"]["content"]["comment"]


def test_default_large_ascii_cap_is_still_exact(db):
    body = "x" * (MAX_BODY_BYTES + 1)
    rid = db.store_request("POST", "https://x.test", {}, body)
    assert len(db.get_request(rid)["body"].encode()) == MAX_BODY_BYTES
