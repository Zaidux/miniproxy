"""XSS regression tests for the dashboard's client-side rendering.

The capture DB holds attacker-controlled data by definition: a response body,
a URL and a header value are all things the target server chose. The
dashboard builds HTML strings (rather than DOM nodes) in a dozen places, so
every interpolation of DB data has to go through esc().

These tests inject a payload that breaks out of an attribute and executes,
then assert it is inert in the rendered DOM.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from playwright.sync_api import sync_playwright

TEMPLATE = "/root/projects/miniproxy/src/miniproxy/templates/index.html"
NODE = shutil.which("node")
CHROME = shutil.which("google-chrome") or shutil.which("chromium")

# Fits an HTML attribute, breaks out of it, then opens a tag that would run.
PAYLOAD = 'x"><img src=x onerror="window.__pwned=1">'
# A URL-shaped payload (the table's title/host/path come from the URL).
URL_PAYLOAD = 'https://evil.example/a?q=x"><img src=y onerror="window.__pwned=1>'
NOTE_PAYLOAD = '"><img src=z onerror="window.__pwned=1">'

pytestmark = pytest.mark.skipif(
    not (NODE and CHROME), reason="node + chrome required"
)


@pytest.fixture()
def dashboard(tmp_path):
    """Serve the real dashboard over a seeded DB carrying XSS payloads."""
    import os
    import sqlite3
    import sys
    import time
    import urllib.request

    db = tmp_path / "proxy.db"
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL,
        headers TEXT, body TEXT, response_code INTEGER,
        response_headers TEXT, response_body TEXT, content_type TEXT,
        ttfb_ms REAL, total_ms REAL, request_body_len INTEGER,
        response_body_len INTEGER, highlight TEXT, note TEXT)""")
    conn.execute(
        "INSERT INTO requests (timestamp, method, url, headers, body,"
        " response_code, response_headers, response_body, content_type,"
        " ttfb_ms, total_ms, request_body_len, response_body_len,"
        " highlight, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("2026-01-01T00:00:00+00:00", "POST", URL_PAYLOAD,
         json.dumps({"X-Evil": PAYLOAD}), PAYLOAD,
         200, json.dumps({"X-Evil": PAYLOAD}), PAYLOAD,
         "text/html", 5.0, 12.0, len(PAYLOAD), len(PAYLOAD),
         "#3fb950", NOTE_PAYLOAD),
    )
    conn.commit()
    conn.close()

    port = 5231
    env = dict(os.environ, MINIPROXY_DB_PATH=str(db),
               PYTHONPATH="/root/projects/miniproxy/src")
    proc = subprocess.Popen(
        [sys.executable, "-m", "miniproxy", "dashboard", "--port", str(port),
         "--host", "127.0.0.1"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            urllib.request.urlopen(base + "/api/meta", timeout=1)
            break
        except Exception:
            time.sleep(0.3)
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def test_capture_data_never_executes(dashboard):
    """A malicious URL / header / body / note must render as text."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(dashboard + "/", wait_until="networkidle")
        page.wait_for_timeout(1500)

        assert page.evaluate("window.__pwned") is None, "XSS fired in the table"

        # Select the row: this renders request+response headers, both bodies,
        # the note and the highlight bar.
        page.click("#liveb tr")
        page.wait_for_timeout(800)
        assert page.evaluate("window.__pwned") is None, "XSS fired in the detail pane"

        # Exercise every body view (Pretty/Raw/Hex build DOM differently).
        for pane in ("req", "resp"):
            page.click(f'.dtab[data-pane="p-{pane}"]')
            page.wait_for_timeout(200)
            for view in ("pretty", "raw", "hex"):
                page.click(f'#p-{pane} .btab[data-view="{view}"]')
                page.wait_for_timeout(200)
                assert page.evaluate("window.__pwned") is None, f"XSS in p-{pane}/{view}"

        # The Note tab renders the stored note.
        page.click('.dtab[data-pane="p-note"]')
        page.wait_for_timeout(300)
        assert page.evaluate("window.__pwned") is None, "XSS in the note tab"

        # The Log tab and the picker modal build their rows differently.
        page.click('.tab[data-tab="log"]')
        page.wait_for_timeout(700)
        assert page.evaluate("window.__pwned") is None, "XSS in the log tab"

        page.click('.tab[data-tab="repeater"]')
        page.wait_for_timeout(400)
        page.click("#rsel-btn")
        page.wait_for_timeout(900)
        assert page.evaluate("window.__pwned") is None, "XSS in the picker modal"

        # The payload is present as inert text, proving it was not stripped.
        table_html = page.inner_html("#liveb")
        assert "<img src=x" in table_html or "onerror" in table_html, \
            "payload was silently dropped instead of escaped"

        assert not errors, f"page errors: {errors}"
        browser.close()


def test_highlight_color_cannot_inject_css():
    """The row highlight is interpolated into a style attribute.

    The server rejects off-palette colors, but the client must not be the
    only thing standing between a stored value and a CSS injection.
    """
    js = re.search(r"<script>\n(.*)\n</script>",
                   open(TEMPLATE).read(), re.S).group(1)
    def grab(name):
        start = js.index(f"function {name}(")
        return js[start:js.index("\n}", start) + 2]
    start = js.index("const HL_TINTS")
    tints = js[start:js.index("};", start) + 2]
    pstart = js.index("const HL_PALETTE")
    palette = js[pstart:js.index("];", pstart) + 2]
    script = "\n".join([palette, tints, grab("hlTint"), grab("rowHlStyle")])
    script += (
        "\nconst evil = 'x\";background:url(//evil)';"
        "\nconsole.log(JSON.stringify({"
        "  evil: rowHlStyle(evil),"
        "  good: rowHlStyle('#3fb950'),"
        "  empty: rowHlStyle('')"
        "}));"
    )
    r = subprocess.run([NODE, "-e", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)

    # An off-palette value must emit nothing at all, so it cannot reach the
    # style attribute even if it somehow got stored.
    assert out["evil"] == "", f"off-palette color leaked into style: {out['evil']!r}"
    assert out["empty"] == ""
    # A palette value renders the two custom properties, nothing else.
    assert out["good"] == ' style="--hl:#3fb950;--hl-tint:rgba(63,185,80,.13)"', out["good"]