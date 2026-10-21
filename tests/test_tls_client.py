"""Browser-TLS replay for the Repeater.

Bot management binds a clearance cookie to the client's TLS handshake, not just
its IP and User-Agent, so a plain HTTP client is re-challenged however complete
its headers are. Replaying with a real browser fingerprint is the only way
through — when the profile matches the browser that obtained the cookie.

These tests do not touch the network: the fingerprint mechanism is proven
separately (distinct JA3/JA4 per profile, verified against a peer that reports
them). What is pinned here is the behaviour around it — validation, dispatch,
fallback when the optional dependency is absent, and telling the user *why* a
403 came back instead of showing a bare status code.
"""
from __future__ import annotations

import pytest

from miniproxy import tls_client


# ── profile validation ───────────────────────────────────────────────

@pytest.mark.parametrize("value", ["", None, "none", "off", "requests", "  "])
def test_no_profile_means_a_plain_request(value):
    assert tls_client.normalize_profile(value) is None


@pytest.mark.skipif(not tls_client.available(), reason="curl_cffi not installed")
@pytest.mark.parametrize("value", ["chrome", "firefox147", "safari", "CHROME"])
def test_known_profiles_are_accepted(value):
    assert tls_client.normalize_profile(value) == value.strip().lower()


@pytest.mark.skipif(not tls_client.available(), reason="curl_cffi not installed")
def test_unknown_profile_raises_instead_of_silently_falling_back():
    """A typo must not quietly send a fingerprint the user did not choose."""
    with pytest.raises(tls_client.TlsClientError) as exc:
        tls_client.normalize_profile("netscape")
    assert "unknown TLS profile" in str(exc.value)
    assert "chrome" in str(exc.value), "the error should list valid choices"


def test_missing_dependency_explains_the_install(monkeypatch):
    monkeypatch.setattr(tls_client, "AVAILABLE", False)
    with pytest.raises(tls_client.TlsClientError) as exc:
        tls_client.normalize_profile("chrome")
    assert "pip install" in str(exc.value)
    # And plain replay still works without it.
    assert tls_client.normalize_profile("") is None


def test_send_without_the_dependency_raises(monkeypatch):
    monkeypatch.setattr(tls_client, "AVAILABLE", False)
    with pytest.raises(tls_client.TlsClientError):
        tls_client.send("GET", "https://example.com", {})


# ── challenge detection ─────────────────────────────────────────────

def test_cloudflare_header_marks_a_challenge():
    assert tls_client.looks_like_challenge(
        403, {"Cf-Mitigated": "challenge"}, "") is True


def test_cloudflare_page_marks_a_challenge():
    assert tls_client.looks_like_challenge(
        403, {}, "<html><title>Just a moment...</title>") is True
    assert tls_client.looks_like_challenge(
        503, {}, "Checking your browser before accessing") is True


def test_real_transport_errors_are_not_challenges():
    """A timeout (status 0) or a genuine 403 from the app is not a bot wall."""
    assert tls_client.looks_like_challenge(0, {}, "") is False
    assert tls_client.looks_like_challenge(
        403, {"content-type": "application/json"}, '{"error":"forbidden"}') is False
    assert tls_client.looks_like_challenge(
        200, {}, "<title>Just a moment</title>") is False, "200 is not a challenge"


# ── the API contract ────────────────────────────────────────────────

def test_meta_advertises_the_profiles(app_client):
    client, _, _ = app_client
    meta = client.get("/api/meta").get_json()
    assert "tls_available" in meta
    if meta["tls_available"]:
        assert "chrome" in meta["tls_profiles"]
    else:
        assert meta["tls_profiles"] == []


def test_repeater_dispatches_to_the_tls_client(app_client, monkeypatch):
    """The chosen profile must actually reach the TLS client, not be ignored."""
    client, _, _ = app_client
    seen = {}

    def fake_send(method, url, headers, body, **kw):
        seen.update({"method": method, "url": url, "headers": headers,
                     "body": body, **kw})
        return {"status_code": 200, "headers": {}, "body": "ok",
                "final_url": url, "followed": False, "redirects": [],
                "challenge": False, "tls_profile": kw.get("impersonate")}

    monkeypatch.setattr(tls_client, "available", lambda: True)
    monkeypatch.setattr(tls_client, "normalize_profile", lambda v: v or None)
    monkeypatch.setattr(tls_client, "send", fake_send)

    r = client.post("/api/repeater/send", json={
        "method": "POST", "url": "https://t.example/api",
        "headers": {"Content-Type": "application/json", "Content-Length": "999"},
        "body": '{"a":1}', "impersonate": "firefox147"})
    assert r.status_code == 200, r.get_json()
    assert seen["impersonate"] == "firefox147"
    assert seen["url"] == "https://t.example/api"
    # Framing headers are dropped here too.
    assert "Content-Length" not in seen["headers"], seen["headers"]
    assert r.get_json()["tls_profile"] == "firefox147"


def test_repeater_reports_a_challenge(app_client, monkeypatch):
    client, _, _ = app_client
    monkeypatch.setattr(tls_client, "available", lambda: True)
    monkeypatch.setattr(tls_client, "normalize_profile", lambda v: v or None)
    monkeypatch.setattr(tls_client, "send", lambda *a, **k: {
        "status_code": 403, "headers": {"cf-mitigated": "challenge"},
        "body": "<title>Just a moment...</title>", "final_url": "https://x/",
        "followed": False, "redirects": [], "challenge": True,
        "tls_profile": "chrome"})
    d = client.post("/api/repeater/send", json={
        "method": "GET", "url": "https://x/", "headers": {},
        "impersonate": "chrome"}).get_json()
    assert d["challenge"] is True


def test_repeater_plain_path_also_flags_a_challenge(app_client, monkeypatch):
    """A plain request against a bot wall must be explained, not just 403."""
    client, _, appmod = app_client

    class Resp:
        status_code = 403
        headers = {"cf-mitigated": "challenge"}
        text = "<title>Just a moment...</title>"
        history = []
        url = "https://x/"

    monkeypatch.setattr(appmod.requests, "request", lambda **kw: Resp())
    d = client.post("/api/repeater/send", json={
        "method": "GET", "url": "https://x/", "headers": {}}).get_json()
    assert d["challenge"] is True
    assert d["tls_profile"] is None


def test_unknown_profile_is_rejected_by_the_api(app_client):
    client, _, _ = app_client
    if not tls_client.available():
        pytest.skip("curl_cffi not installed")
    r = client.post("/api/repeater/send", json={
        "method": "GET", "url": "https://x/", "headers": {},
        "impersonate": "netscape"})
    assert r.status_code == 400
    assert "unknown TLS profile" in r.get_json()["error"]


def test_tls_error_becomes_a_502_not_a_stack_trace(app_client, monkeypatch):
    client, _, _ = app_client
    monkeypatch.setattr(tls_client, "available", lambda: True)
    monkeypatch.setattr(tls_client, "normalize_profile", lambda v: "chrome")

    def boom(*a, **k):
        raise tls_client.TlsClientError("connection reset")

    monkeypatch.setattr(tls_client, "send", boom)
    r = client.post("/api/repeater/send", json={
        "method": "GET", "url": "https://x/", "headers": {},
        "impersonate": "chrome"})
    assert r.status_code == 502
    assert "connection reset" in r.get_json()["error"]
