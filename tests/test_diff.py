"""Tests for the response-diffing engine.

The feature's whole value is answering access-control questions quickly, so
the tests focus on: does it name the thing that changed, does it degrade
gracefully on non-JSON, and does it never claim two things are identical when
they are not.
"""
from __future__ import annotations

import json

import pytest

from miniproxy.diff import (
    diff_captures,
    diff_char,
    diff_headers,
    diff_json,
    diff_token,
    diff_url_params,
)


def row(**kw) -> dict:
    base = {
        "id": 1, "method": "GET", "url": "https://x.example/api/me",
        "response_code": 200, "response_headers": "{}",
        "response_body": "", "body": "",
    }
    base.update(kw)
    return base


# ── JSON ────────────────────────────────────────────────────────────

def test_json_detects_changed_field():
    a = row(response_body=json.dumps({"user": {"id": 1, "role": "user"}}))
    b = row(response_body=json.dumps({"user": {"id": 1, "role": "admin"}}))
    d = diff_captures(a, b)
    assert d["mode"] == "json"
    paths = {c["path"]: c for c in d["body"]["changed"]}
    assert "user.role" in paths
    assert paths["user.role"]["a"] == "user"
    assert paths["user.role"]["b"] == "admin"


def test_json_reports_added_and_removed():
    a = row(response_body=json.dumps({"a": 1, "gone": 2}))
    b = row(response_body=json.dumps({"a": 1, "fresh": 3}))
    d = diff_json(a["response_body"], b["response_body"])
    assert [e["path"] for e in d["added"]] == ["fresh"]
    assert [e["path"] for e in d["removed"]] == ["gone"]
    assert d["changed"] == []


def test_json_nested_lists():
    a = row(response_body=json.dumps({"items": [{"n": "x"}, {"n": "y"}]}))
    b = row(response_body=json.dumps({"items": [{"n": "x"}, {"n": "Z"}]}))
    d = diff_json(a["response_body"], b["response_body"])
    assert d["changed"][0]["path"] == "items.1.n"


def test_json_not_applicable_to_html():
    d = diff_json("<html><body>hi</body></html>", "<html>")
    assert d["applicable"] is False


def test_json_identical():
    same = json.dumps({"a": 1, "b": [1, 2]})
    assert diff_json(same, same)["identical"] is True


# ── char ────────────────────────────────────────────────────────────

def test_char_diff_locates_the_change():
    d = diff_char("token=abc123&x=1", "token=XYZ789&x=1")
    assert d["identical"] is False
    assert d["a_mid"] == "abc123"
    assert d["b_mid"] == "XYZ789"
    assert d["offset"] == 6


def test_char_diff_identical():
    d = diff_char("same body", "same body")
    assert d["identical"] is True
    assert d["a_mid"] == "" and d["b_mid"] == ""


def test_char_diff_pure_insertion():
    d = diff_char("abcdef", "abcXXdef")
    assert d["b_mid"] == "XX"
    assert d["a_mid"] == ""


def test_char_diff_empty_sides():
    assert diff_char("", "")["identical"] is True
    d = diff_char("", "body")
    assert d["identical"] is False
    assert d["b_mid"] == "body"


# ── token ───────────────────────────────────────────────────────────

def test_token_diff_flags_new_words():
    d = diff_token("welcome back alice admin", "welcome back bob")
    changed = [r["token"] for r in d["rows"] if not r["common"]]
    assert set(changed) == {"alice", "admin"}


def test_token_diff_identical():
    assert diff_token("a b c", "a b c")["identical"] is True


def test_token_diff_truncates():
    d = diff_token(" ".join(str(i) for i in range(5000)), "", limit=100)
    assert d["truncated"] is True
    assert len(d["rows"]) == 100


# ── headers ─────────────────────────────────────────────────────────

def test_header_diff_case_insensitive():
    a = row(response_headers=json.dumps({"Content-Type": "text/html"}))
    b = row(response_headers=json.dumps({"content-type": "text/html"}))
    assert diff_headers(a["response_headers"], b["response_headers"])["identical"] is True


def test_header_diff_names_changed():
    a = row(response_headers=json.dumps({"Set-Cookie": "a=1"}))
    b = row(response_headers=json.dumps({"Set-Cookie": "a=2", "X-New": "y"}))
    d = diff_headers(a["response_headers"], b["response_headers"])
    assert [e["name"] for e in d["changed"]] == ["set-cookie"]
    assert [e["name"] for e in d["added"]] == ["x-new"]


def test_header_diff_handles_garbage():
    assert diff_headers("not json", None)["identical"] is True


# ── url params ──────────────────────────────────────────────────────

def test_param_diff_names_the_flipped_param():
    a = row(url="https://x.example/api?user=alice&role=user")
    b = row(url="https://x.example/api?user=alice&role=admin")
    d = diff_url_params(a["url"], b["url"])
    assert [e["name"] for e in d["changed"]] == ["role"]
    assert d["changed"][0]["a"] == "user"
    assert d["changed"][0]["b"] == "admin"


def test_param_diff_added_and_removed():
    a = row(url="https://x.example/api?a=1&b=2")
    b = row(url="https://x.example/api?a=1&c=3")
    d = diff_url_params(a["url"], b["url"])
    assert [e["name"] for e in d["added"]] == ["c"]
    assert [e["name"] for e in d["removed"]] == ["b"]


def test_param_diff_detects_path_change():
    a = row(url="https://x.example/api/v1/me")
    b = row(url="https://x.example/api/v2/me")
    assert diff_url_params(a["url"], b["url"])["path_changed"] is True


# ── combined ────────────────────────────────────────────────────────

def test_access_control_scenario_end_to_end():
    """The canonical IDOR check: same user, role flipped."""
    a = row(id=10, response_code=200,
            response_body=json.dumps({"name": "wiener", "role": "user"}),
            url="https://acct.web-security-academy.net/my-account?user=wiener")
    b = row(id=11, response_code=200,
            response_body=json.dumps({"name": "wiener", "role": "admin"}),
            url="https://acct.web-security-academy.net/my-account?user=wiener")
    d = diff_captures(a, b)
    assert d["status"] == "same"
    assert d["mode"] == "json"
    assert not d["identical"]
    assert "role" in d["summary"]
    assert d["body"]["changed"][0]["path"] == "role"


def test_status_change_is_flagged():
    d = diff_captures(row(response_code=200), row(response_code=403))
    assert d["status"] == "different"
    assert "403" in d["summary"]


def test_true_identical_reports_identical():
    payload = json.dumps({"a": 1})
    same = row(response_body=payload, response_code=200)
    d = diff_captures(same, dict(same, id=2))
    assert d["identical"] is True
    assert d["summary"] == "identical"


def test_auto_falls_back_to_token_for_html():
    a = row(response_body="<p>role=user</p>")
    b = row(response_body="<p>role=admin</p>")
    d = diff_captures(a, b)
    assert d["mode"] == "token"
    # The token diff reports tokens present in A but missing from B, so the
    # changed token is `user` (the value A had), not `admin` (B's value).
    changed = [r["token"] for r in d["body"]["rows"] if not r["common"]]
    assert "user" in changed
    assert "admin" not in changed


def test_explicit_mode_forced():
    a = row(response_body=json.dumps({"a": 1}))
    b = row(response_body=json.dumps({"a": 2}))
    assert diff_captures(a, b, mode="char")["mode"] == "char"
    assert diff_captures(a, b, mode="token")["mode"] == "token"


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        diff_captures(row(), row(), mode="sideways")


def test_missing_bodies_do_not_crash():
    d = diff_captures(row(), row(id=2))
    assert d["identical"] is True
    assert "mode" in d


def test_one_side_empty_body():
    a = row(response_body="secret token here")
    b = row(response_body="")
    d = diff_captures(a, b)
    assert not d["identical"]
    assert d["a"]["length"] > 0 and d["b"]["length"] == 0