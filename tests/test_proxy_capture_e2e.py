"""End-to-end capture tests for the mitmdump addon.

These run the real addon against a real mitmdump process and assert that
traffic actually lands in the DB — and that noise rules actually stop it.

The failure this guards against is invisible in unit tests: an exception in
``MiniProxyAddon.request`` is reported by mitmdump as an "Addon error" and
then *silently swallowed*, leaving a proxy that routes traffic but captures
nothing. That is exactly the bug class the v4 "capture is always on" work
set out to kill, so it needs a real-process test.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request

import pytest

mitmdump = pytest.importorskip("mitmproxy") and __import__("shutil").which("mitmdump")
pytestmark = pytest.mark.skipif(not mitmdump, reason="mitmdump not installed")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _rows(db_path: str) -> list[tuple]:
    """Captured rows, tolerating a not-yet-created DB.

    mitmdump creates the capture DB when the addon is constructed, which can
    be a moment after the proxy socket starts accepting. Treating a missing
    table as "nothing captured yet" keeps the polling helpers from blowing up
    on a race that is not the test's subject.
    """
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    try:
        return list(conn.execute("SELECT id, url FROM requests ORDER BY id"))
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return []
        raise
    finally:
        conn.close()


def _launch(tmp_path, extra_env: dict[str, str] | None = None):
    """Start mitmdump with the real addon; returns the fixture dict."""
    db = tmp_path / "cap.db"
    addon = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "src", "miniproxy", "addon", "proxy.py"))
    port = _free_port()
    env = dict(
        os.environ,
        MINIPROXY_DB_PATH=str(db),
        PYTHONPATH=os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "src")),
        **(extra_env or {}),
    )
    proc = subprocess.Popen(
        [mitmdump, "-s", addon, "--listen-host", "127.0.0.1",
         "--listen-port", str(port), "--set", "block_global=false"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            if proc.poll() is not None:
                pytest.fail(f"mitmdump died:\n{proc.stdout.read()}")
            time.sleep(0.3)
    else:
        proc.kill()
        pytest.fail("mitmdump never started listening")
    return {"proc": proc, "db": str(db), "port": port, "addon": addon}


def _shutdown(live):
    live["proc"].terminate()
    try:
        live["proc"].stdout.read()
    except Exception:
        pass
    live["proc"].wait(timeout=10)


@pytest.fixture()
def live_proxy(tmp_path):
    live = _launch(tmp_path)
    yield live
    _shutdown(live)


def _fetch(port: int, url: str) -> None:
    """Plain-HTTP request *through the proxy* (no CA needed).

    The proxy is passed explicitly rather than relying on ``http_proxy``: a
    CI box may already export one, and urllib's default opener would then
    silently send the request somewhere else — which reads as "the addon
    captured nothing" rather than "the test never used the proxy".
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
    )
    try:
        opener.open(urllib.request.Request(url), timeout=20)
    except Exception:
        pass  # status/SSL is irrelevant; we only care what was captured


def test_live_traffic_is_captured(live_proxy):
    """A proxied request MUST appear in the capture DB.

    Regression test for a silently-swallowed `UnboundLocalError` in the noise
    gate, which made the proxy route traffic while capturing nothing at all.
    """
    before = len(_rows(live_proxy["db"]))
    _fetch(live_proxy["port"], "http://example.com/")
    deadline = time.time() + 15
    while time.time() < deadline and len(_rows(live_proxy["db"])) == before:
        time.sleep(0.4)
    rows = _rows(live_proxy["db"])
    assert len(rows) > before, (
        "no capture written — the addon is likely throwing and mitmdump is "
        "swallowing it"
    )
    assert any("example.com" in url for _, url in rows)


def test_addon_raises_nothing(live_proxy):
    """The addon's stderr must not contain an 'Addon error' traceback."""
    _fetch(live_proxy["port"], "http://example.com/")
    time.sleep(3)
    live_proxy["proc"].terminate()
    out = live_proxy["proc"].stdout.read()
    live_proxy["proc"].wait(timeout=10)
    assert "Addon error" not in out, f"addon raised:\n{out}"
    assert "Traceback" not in out, f"traceback in addon:\n{out}"


def test_noise_rule_blocks_capture_but_still_proxies(live_proxy):
    """An enabled noise rule must keep the flow out of the DB.

    The traffic still has to be proxied — the gate stops the capture, not the
    request.
    """
    from miniproxy.addon.db import Database

    db = Database(live_proxy["db"])
    db.add_noise_rule("noisy.example.test", enabled=True)

    before = len(_rows(live_proxy["db"]))
    _fetch(live_proxy["port"], "http://noisy.example.test/x")
    _fetch(live_proxy["port"], "http://clean.example.test/x")
    deadline = time.time() + 15
    while time.time() < deadline and len(_rows(live_proxy["db"])) == before:
        time.sleep(0.4)
    time.sleep(2)
    urls = [u for _, u in _rows(live_proxy["db"])]
    assert not any("noisy.example.test" in u for u in urls), \
        "noise rule did not block the capture"
    assert any("clean.example.test" in u for u in urls), \
        "the clean control request was not captured"


def test_disabled_rule_does_not_block(live_proxy):
    """Rules ship disabled — an unenabled rule must capture normally."""
    from miniproxy.addon.db import Database

    db = Database(live_proxy["db"])
    db.add_noise_rule("optin.example.test", enabled=False)

    before = len(_rows(live_proxy["db"]))
    _fetch(live_proxy["port"], "http://optin.example.test/x")
    deadline = time.time() + 15
    while time.time() < deadline and len(_rows(live_proxy["db"])) == before:
        time.sleep(0.4)
    urls = [u for _, u in _rows(live_proxy["db"])]
    assert any("optin.example.test" in u for u in urls), \
        "a disabled noise rule blocked the capture"


def test_scope_guard_still_blocks_before_noise(tmp_path):
    """With a scope set, out-of-scope hosts are skipped, noise rules or not.

    Scope is read once at addon construction, so this needs its own proxy
    rather than mutating os.environ under a running one.
    """
    live = _launch(tmp_path, {
        # _load_scope() parses this as JSON, not as whitespace-separated text.
        "MINIPROXY_SCOPE": json.dumps(["*.allowed.example.test"]),
        "MINIPROXY_SCOPE_MODE": "skip",
    })
    try:
        _fetch(live["port"], "http://denied.example.test/x")
        _fetch(live["port"], "http://ok.allowed.example.test/x")
        deadline = time.time() + 15
        while time.time() < deadline and not _rows(live["db"]):
            time.sleep(0.4)
        time.sleep(2)
        urls = [u for _, u in _rows(live["db"])]
        assert not any("denied.example.test" in u for u in urls), \
            "scope guard did not skip the out-of-scope host"
        assert any("ok.allowed.example.test" in u for u in urls), \
            "in-scope control request was not captured"
    finally:
        _shutdown(live)


def test_noise_and_scope_compose(tmp_path):
    """An in-scope host matched by a noise rule is still skipped."""
    from miniproxy.addon.db import Database

    live = _launch(tmp_path, {
        "MINIPROXY_SCOPE": "*.allowed.example.test",
        "MINIPROXY_SCOPE_MODE": "skip",
    })
    try:
        Database(live["db"]).add_noise_rule("noisy.allowed.example.test", enabled=True)
        _fetch(live["port"], "http://noisy.allowed.example.test/x")
        _fetch(live["port"], "http://clean.allowed.example.test/x")
        deadline = time.time() + 15
        while time.time() < deadline and not _rows(live["db"]):
            time.sleep(0.4)
        time.sleep(2)
        urls = [u for _, u in _rows(live["db"])]
        assert not any("noisy.allowed.example.test" in u for u in urls)
        assert any("clean.allowed.example.test" in u for u in urls)
    finally:
        _shutdown(live)