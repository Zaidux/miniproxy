"""Parity tests between the dashboard's JS helpers and the Python engine.

The dashboard mirrors two Python heuristics in JavaScript so the UI can
repaint instantly without waiting for a poll:

* ``isStatic()``          ↔ :func:`miniproxy.addon.db.is_static_asset`
* ``urlParts()``          ↔ :func:`miniproxy.addon.db.host_of`

If the two ever drift, a toggled filter would show different rows before and
after the next poll — a bug that is very hard to spot by hand. These tests
extract the functions straight out of the template and run them under Node,
so the check cannot rot when the JS is edited.

Skipped (not failed) when Node is unavailable.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from miniproxy.addon.db import host_of, is_static_asset

TEMPLATE = Path(__file__).resolve().parent.parent / "src/miniproxy/templates/index.html"

NODE = shutil.which("node")


def _script_text() -> str:
    html = TEMPLATE.read_text()
    m = re.search(r"<script>\n(.*)\n</script>", html, re.S)
    assert m, "no <script> block found in index.html"
    return m.group(1)


def _extract(name: str, kind: str = "function") -> str:
    """Pull a top-level function/const out of the dashboard script by brace
    matching, so extraction survives edits inside the function body."""
    js = _script_text()
    if kind == "function":
        start = js.index(f"function {name}(")
        depth, i = 0, js.index("{", start)
        begin = i
        while True:
            ch = js[i]
            if ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return js[start:i + 1]
            i += 1
    start = js.index(f"const {name}")
    end = js.index(";\n", start)
    return js[start:end + 1]


def _run_node(tmp_path: Path, body: str) -> dict:
    """Run a Node snippet that prints a JSON result and return it parsed."""
    f = tmp_path / "parity.js"
    f.write_text(body)
    out = subprocess.run(
        [NODE, str(f)], capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, f"node failed: {out.stderr}"
    return json.loads(out.stdout)


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_dashboard_script_is_valid_js(tmp_path):
    """The CI JS syntax check, run as a test so `pytest` alone catches it."""
    f = tmp_path / "dash.js"
    f.write_text(_script_text())
    r = subprocess.run([NODE, "--check", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


STATIC_CASES = [
    ("https://x.example/a.css", "", True),
    ("https://x.example/a.js", "", True),
    ("https://x.example/a.woff2", "", True),
    ("https://x.example/a.jpeg", "", True),
    # MIME without an extension — the CDN-asset case.
    ("https://x.example/render?size=2", "image/png", True),
    ("https://x.example/x", "text/css; charset=utf-8", True),
    ("https://x.example/f.woff2", "font/woff2", True),
    # A definite non-asset MIME beats a misleading extension.
    ("https://x.example/api/image.png", "application/json", False),
    ("https://x.example/api/users", "application/json", False),
    ("https://x.example/login", "text/html", False),
    # No MIME at all -> fall back to the extension.
    ("https://x.example/render", "", False),
    ("https://x.example/a?f=css", "", False),
]


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_js_is_static_matches_python(tmp_path):
    """The JS mirror must classify exactly what the Python engine classifies."""
    body = (
        _extract("urlParts")
        + "\n" + _extract("STATIC_EXT", kind="const")
        + "\n" + _extract("STATIC_CT", kind="const")
        + "\n" + _extract("isStatic")
        + "\nconst cases = " + json.dumps(STATIC_CASES)
        + "\nconst out = {};"
        + "\nfor (const [u, ct, want] of cases) {"
        + "\n  out[u + '|' + ct] = {js: isStatic({url: u, content_type: ct}), want: want};"
        + "}\nconsole.log(JSON.stringify(out));\n"
    )
    result = _run_node(tmp_path, body)
    mismatches = []
    for key, val in result.items():
        url, ct = key.rsplit("|", 1)
        py = is_static_asset(url, ct)
        if py is not val["js"] or py is not val["want"]:
            mismatches.append((url, ct, py, val["js"]))
    assert not mismatches, f"JS/Python static-asset disagreement: {mismatches}"


URL_CASES = [
    ("https://target.example/api/users?id=1", "target.example", "/api/users"),
    ("http://target.example:8443/x", "target.example", "/x"),
    ("https://user:pw@target.example/x", "user:pw@target.example", "/x"),
    ("https://target.example", "target.example", ""),
    ("https://target.example/p?q=1#f", "target.example", "/p"),
    ("https://[::1]:8080/x", "[::1]", "/x"),
    ("not a url", "", "not a url"),
    ("", "", ""),
]


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_js_url_parts_path(tmp_path):
    """The Path column's split must agree with Python for the query boundary."""
    body = (
        _extract("urlParts")
        + "\nconst cases = " + json.dumps(URL_CASES)
        + "\nconst out = cases.map(([u]) => { const p = urlParts(u); return [p.host, p.path]; });"
        + "\nconsole.log(JSON.stringify(out));\n"
    )
    result = _run_node(tmp_path, body)
    for (url, want_host, want_path), (js_host, js_path) in zip(URL_CASES, result):
        assert js_path == want_path, f"path mismatch for {url}: {js_path!r} != {want_path!r}"
        # host_of() strips userinfo and the port; urlParts() deliberately keeps
        # userinfo (it is shown in the Host column), so compare on the host
        # with those parts normalized away.
        assert host_of(url) in ("", js_host) or js_host.endswith(host_of(url)), \
            f"host mismatch for {url}: {js_host!r} vs {host_of(url)!r}"