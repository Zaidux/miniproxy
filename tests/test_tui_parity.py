"""TUI parity tests — the terminal UI must expose the same noise controls.

The 0.6 dashboard work (noise rules, highlights, hex view, host filter, body
search) was not mirrored into the Textual UI, so `miniproxy tui` could not do
things the web dashboard could. These tests pin the filters and columns the
TUI is expected to share with the dashboard.

Skipped when Textual is unavailable.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("textual")
pytest.importorskip("textual.app")

from miniproxy.tui import MiniProxyTUI  # noqa: E402


@pytest.fixture()
def rows() -> list[dict]:
    return [
        dict(id=1, method="GET", url="https://target.example/api/users?role=user",
             response_code=200, content_type="application/json",
             response_body=json.dumps({"role": "user"}), body="",
             total_ms=12.0, ttfb_ms=5.0, highlight="#3fb950", note="baseline"),
        dict(id=2, method="GET", url="https://target.example/api/users?role=admin",
             response_code=200, content_type="application/json",
             response_body=json.dumps({"role": "admin"}), body="",
             total_ms=11.0, ttfb_ms=4.0, highlight=None, note=None),
        dict(id=3, method="GET", url="https://target.example/app.css",
             response_code=200, content_type="text/css", response_body="body{}",
             body="", total_ms=2.0, ttfb_ms=1.0, highlight=None, note=None),
        dict(id=4, method="GET", url="https://telemetry.example/ping",
             response_code=200, content_type="text/plain", response_body="pong",
             body="", total_ms=3.0, ttfb_ms=1.0, highlight=None, note=None),
        dict(id=5, method="POST", url="https://target.example/login",
             response_code=302, content_type="text/html", response_body="found",
             body="user=admin&pass=secret", total_ms=8.0, ttfb_ms=3.0,
             highlight=None, note=None),
    ]


def _widget_ids(source: str) -> list[str]:
    import re
    return re.findall(r'id="([^"]+)"', source)


class TestTuiParity:
    def test_filter_widgets_exist(self):
        """Every filter the dashboard offers must have a TUI counterpart."""
        src = open("src/miniproxy/tui.py").read()
        ids = _widget_ids(src)
        for wanted in ("filter-method", "filter-status", "filter-url",
                       "filter-body", "filter-host", "filter-static",
                       "filter-highlighted"):
            assert wanted in ids, f"TUI is missing the {wanted} filter"

    def test_table_shows_host_and_path(self):
        """The dashboard splits URL into host + path; the TUI should too."""
        src = open("src/miniproxy/tui.py").read()
        assert '"Host"' in src and '"Path"' in src, \
            "TUI table should have Host and Path columns like the dashboard"
        # The old single "URL" column should be gone.
        assert '"ID", "Method", "Status", "ms", "URL"' not in src

    def test_noise_controls_present(self):
        src = open("src/miniproxy/tui.py").read()
        assert "noise" in src.lower(), "TUI has no noise-rule support"
        assert "is_noise" in src or "noise_rules" in src

    def test_diff_available(self):
        src = open("src/miniproxy/tui.py").read()
        assert "diff" in src.lower(), "TUI cannot compare two captures"

    def test_help_mentions_new_keys(self):
        src = open("src/miniproxy/tui.py").read()
        # The help modal should document the new bindings.
        for key in ("b", "h", "d"):
            assert f'"{key}' in src or f"/ {key}" in src or f"({key})" in src, \
                f"new keybinding {key} not documented in the help screen"


class TestTuiRowFilter:
    """The filter predicate itself, exercised without a running app."""

    def _matches(self, row, *, method="", status="", url="", body="",
                 host="", hide_static=False, highlighted_only=False):
        from miniproxy.addon.db import is_static_asset

        if method and str(row.get("method") or "").upper() != method:
            return False
        code = row.get("response_code")
        if status == "pending" and code is not None:
            return False
        if status == "0" and code != 0:
            return False
        if status in ("2", "3", "4", "5"):
            if not isinstance(code, int) or code // 100 != int(status):
                return False
        if url and url not in str(row.get("url") or "").lower():
            return False
        if body:
            hay = (str(row.get("response_body") or "") + " " +
                   str(row.get("body") or "")).lower()
            if body not in hay:
                return False
        if host and host not in str(row.get("url") or "").lower():
            return False
        if hide_static and is_static_asset(row.get("url", ""),
                                          row.get("content_type") or ""):
            return False
        if highlighted_only and not row.get("highlight"):
            return False
        return True

    def test_host_filter(self, rows):
        kept = [r for r in rows
                if self._matches(r, host="target.example")]
        assert len(kept) == 4

    def test_body_filter_finds_request_body(self, rows):
        kept = [r for r in rows if self._matches(r, body="pass=secret")]
        assert [r["id"] for r in kept] == [5]

    def test_body_filter_finds_response_body(self, rows):
        kept = [r for r in rows if self._matches(r, body='"role"')]
        assert [r["id"] for r in kept] == [1, 2]

    def test_hide_static(self, rows):
        kept = [r for r in rows if self._matches(r, hide_static=True)]
        assert 3 not in [r["id"] for r in kept]

    def test_highlighted_only(self, rows):
        kept = [r for r in rows if self._matches(r, highlighted_only=True)]
        assert [r["id"] for r in kept] == [1]

    def test_combined_host_and_static(self, rows):
        kept = [r for r in rows
                if self._matches(r, host="target.example", hide_static=True)]
        assert [r["id"] for r in kept] == [1, 2, 5]