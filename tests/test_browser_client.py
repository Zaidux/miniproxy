"""Browser-bridge replay: hand the request to a real browser.

Fingerprint emulation reproduces a handshake; the bridge uses an actual browser,
so TLS, HTTP/2, cookies, UA and any JavaScript challenge state are native. That
is the only replay mode that works when the gate is IP reputation plus a managed
challenge rather than the handshake.

These tests do not launch a browser: they pin the parts that decide behaviour —
header splitting, availability, dispatch, error reporting — and the one real
browser test is opt-in.
"""
from __future__ import annotations

import json
import os

import pytest

from miniproxy import browser_client


# ── header splitting ────────────────────────────────────────────────

def test_headers_the_browser_owns_are_stripped_and_reported():
    """A page cannot set Host/Cookie/UA; dropping them silently would make a
    replay look faithful when the browser substituted its own."""
    usable, dropped = browser_client.settable_headers({
        "Host": "example.com",
        "Cookie": "session=x",
        "User-Agent": "fake",
        "Content-Length": "42",
        "Sec-Fetch-Site": "same-origin",
        "Accept-Encoding": "gzip",
        "X-Custom": "kept",
        "Content-Type": "application/json",
    })
    assert usable == {"X-Custom": "kept", "Content-Type": "application/json"}
    assert set(d.lower() for d in dropped) == {
        "host", "cookie", "user-agent", "content-length",
        "sec-fetch-site", "accept-encoding"}


def test_case_insensitive_and_empty():
    usable, dropped = browser_client.settable_headers({"host": "x", "X-A": "1"})
    assert usable == {"X-A": "1"} and dropped == ["host"]
    assert browser_client.settable_headers({}) == ({}, [])


# ── availability ────────────────────────────────────────────────────

def test_explicit_path_wins(monkeypatch, tmp_path):
    fake = tmp_path / "chrome"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("MINIPROXY_BROWSER_PATH", str(fake))
    monkeypatch.setattr(browser_client, "_BROWSER_CACHE", {})
    assert browser_client.find_browser() == str(fake)


def test_missing_explicit_path_is_not_silently_ignored(monkeypatch):
    monkeypatch.setenv("MINIPROXY_BROWSER_PATH", "/nonexistent/chrome")
    monkeypatch.setattr(browser_client, "_BROWSER_CACHE", {})
    assert browser_client.find_browser() is None


def test_availability_requires_playwright(monkeypatch):
    monkeypatch.setattr(browser_client, "PLAYWRIGHT", False)
    assert browser_client.available() is False
    with pytest.raises(browser_client.BrowserError) as exc:
        browser_client.send("GET", "https://x/", {})
    assert "Playwright" in str(exc.value)


def test_send_without_a_browser_explains_the_fix(monkeypatch):
    monkeypatch.setattr(browser_client, "PLAYWRIGHT", True)
    monkeypatch.setattr(browser_client, "DEFAULT_CDP_URL", "")
    monkeypatch.setattr(browser_client, "find_browser", lambda: None)
    monkeypatch.setattr(browser_client, "available", lambda: False)
    with pytest.raises(browser_client.BrowserError) as exc:
        browser_client.send("GET", "https://x/", {})
    msg = str(exc.value)
    assert "MINIPROXY_BROWSER_PATH" in msg or "MINIPROXY_BROWSER_CDP" in msg


# ── the API contract ────────────────────────────────────────────────

def test_meta_reports_browser_availability(app_client):
    client, _, _ = app_client
    meta = client.get("/api/meta").get_json()
    assert "browser_available" in meta


def test_repeater_dispatches_browser_mode(app_client, monkeypatch):
    """`impersonate: "browser"` must reach the bridge, not the TLS client."""
    client, _, _ = app_client
    seen = {}

    def fake_send(method, url, headers, body, **kw):
        seen.update({"method": method, "url": url, "headers": headers,
                     "body": body, **kw})
        return {"status_code": 200, "headers": {"x": "1"}, "body": "ok",
                "final_url": url, "followed": False, "redirects": [],
                "challenge": False, "tls_profile": None, "browser": True,
                "dropped_headers": ["Cookie"]}

    monkeypatch.setattr(browser_client, "send", fake_send)
    r = client.post("/api/repeater/send", json={
        "method": "POST", "url": "https://t.example/api",
        "headers": {"Cookie": "s=1", "Content-Type": "application/json",
                    "Content-Length": "999"},
        "body": '{"a":1}', "impersonate": "browser"})
    assert r.status_code == 200, r.get_json()
    assert seen["url"] == "https://t.example/api"
    assert seen["body"] == '{"a":1}'
    # Framing headers are stripped before the bridge sees them, too.
    assert "Content-Length" not in seen["headers"], seen["headers"]
    d = r.get_json()
    assert d["browser"] is True
    assert d["dropped_headers"] == ["Cookie"]


def test_browser_error_is_a_502_not_a_traceback(app_client, monkeypatch):
    client, _, _ = app_client

    def boom(*a, **k):
        raise browser_client.BrowserError("no browser found")

    monkeypatch.setattr(browser_client, "send", boom)
    r = client.post("/api/repeater/send", json={
        "method": "GET", "url": "https://x/", "headers": {},
        "impersonate": "browser"})
    assert r.status_code == 502
    assert "no browser found" in r.get_json()["error"]


def test_browser_mode_works_without_curl_cffi(app_client, monkeypatch):
    """The bridge is independent of the TLS extra: a machine with a browser but
    no curl_cffi must still be able to use it."""
    client, _, _ = app_client
    from miniproxy import tls_client

    monkeypatch.setattr(tls_client, "available", lambda: False)
    monkeypatch.setattr(browser_client, "send", lambda *a, **k: {
        "status_code": 200, "headers": {}, "body": "ok", "final_url": "https://x/",
        "followed": False, "redirects": [], "challenge": False,
        "tls_profile": None, "browser": True, "dropped_headers": []})
    r = client.post("/api/repeater/send", json={
        "method": "GET", "url": "https://x/", "headers": {},
        "impersonate": "browser"})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["browser"] is True


# ── a real browser, when one is present ─────────────────────────────

pytestmark_real = pytest.mark.skipif(
    not browser_client.available(), reason="no browser available")


@pytestmark_real
def test_real_browser_makes_a_request():
    """Opt-in smoke test: one GET through the actual browser."""
    r = browser_client.send(
        "GET", "https://tls.peet.ws/api/all", {},
        timeout=90)
    assert r["status_code"] == 200, r
    info = json.loads(r["body"])
    # The peer must see a browser's HTTP/2 fingerprint, not Python's.
    assert info["tls"]["ja4"].endswith("h2_8daaf6152771_806a8c22fdea") or \
        "h2" in info["tls"]["ja4"]
    # And not the headless giveaway.
    assert "HeadlessChrome" not in (info.get("user_agent") or "")
