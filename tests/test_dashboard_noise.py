"""Tests for the dashboard's noise model, annotations and host/path filters.

Covers the three-layer noise defense (capture-time rules, query-time filters,
cleanup-time deletion) plus row highlighting and the new list endpoints.
"""
from __future__ import annotations

import pytest

from miniproxy.addon.db import (
    DEFAULT_NOISE_HOSTS,
    HIGHLIGHT_COLORS,
    Database,
    host_of,
    is_static_asset,
    is_valid_highlight,
)


@pytest.fixture()
def db(tmp_path) -> Database:
    d = Database(tmp_path / "t.db")
    rows = [
        # (method, url, code, content_type, body)
        ("GET", "https://target.example/api/users?id=1", 200, "application/json", '{"ok":1}'),
        ("POST", "https://target.example/login", 302, "text/html", ""),
        ("GET", "https://target.example/static/app.css", 200, "text/css", "body{}"),
        ("GET", "https://img-getpocket.cdn.mozilla.net/132x132/x.jpeg", 200, "image/jpeg", "JPEGDATA"),
        ("GET", "https://incoming.telemetry.mozilla.org/v1/ping", 200, "text/plain", ""),
        ("GET", "https://i.ytimg.com/vi/abc/hq.jpg", 200, "image/jpeg", "JPEGDATA"),
        ("GET", "https://fonts.gstatic.com/s/x.woff2", 200, "font/woff2", "FONT"),
        # No extension, image MIME — the case extension-matching misses.
        ("GET", "https://target.example/render?size=2", 200, "image/png", "PNG"),
    ]
    for method, url, code, ct, body in rows:
        rid = d.store_request(method=method, url=url, headers={}, body="")
        d.update_response(rid, code, {}, body, ct, ttfb_ms=1.0, total_ms=2.0)
    return d


# ── host_of / is_static_asset ───────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("https://target.example/a/b?c=1", "target.example"),
    ("http://target.example:8080/x", "target.example"),
    ("https://user:pw@target.example/x", "target.example"),
    ("https://[::1]:8080/x", "[::1]"),
    ("not a url", ""),
    ("", ""),
])
def test_host_of(url, expected):
    assert host_of(url) == expected


@pytest.mark.parametrize("url,ct,static", [
    ("https://x.example/a.css", "", True),
    ("https://x.example/a.js", "", True),
    ("https://x.example/a.woff2", "", True),
    ("https://x.example/a.jpeg", "", True),
    # MIME beats a missing extension (CDN asset URLs).
    ("https://x.example/render?size=2", "image/png", True),
    ("https://x.example/x", "text/css; charset=utf-8", True),
    ("https://x.example/api/users", "application/json", False),
    ("https://x.example/api/users", "text/html", False),
    # No extension, no MIME -> not static.
    ("https://x.example/render", "", False),
    # A dynamic route that merely ends in .png but returns JSON is kept.
    ("https://x.example/api/image.png", "application/json", False),
    # Query junk must not be mistaken for an extension.
    ("https://x.example/a?f=css", "", False),
])
def test_is_static_asset(url, ct, static):
    assert is_static_asset(url, ct) is static


def test_sql_hide_static_matches_python(db):
    """The SQL filter and the Python heuristic must agree exactly.

    The dashboard mirrors is_static_asset() in JavaScript for instant
    repaints; if SQL and Python disagreed, the "Hide static" chip would show
    different rows before and after the next poll.
    """
    sql = {r["id"] for r in db.get_logs(limit=1000, hide_static=True)}
    python = {
        r["id"] for r in db.get_logs(limit=1000)
        if not is_static_asset(r["url"], r["content_type"] or "")
    }
    assert sql == python


# ── Host filters ────────────────────────────────────────────────────

def test_count_host(db):
    assert db.count_logs() == 8
    assert db.count_logs(host="target.example") == 4
    # Subdomain-sensitive: img-getpocket is cdn.mozilla.net, telemetry is
    # mozilla.org — a filter must not conflate them.
    assert db.count_logs(host="mozilla.org") == 1
    assert db.count_logs(host="mozilla.net") == 1
    assert db.count_logs(host="mozilla") == 2


def test_host_filter_ignores_path_lookalikes(db):
    """/render must not match a host filter that looks like a path segment."""
    assert db.count_logs(host="render") == 0
    assert db.count_logs(host="login") == 0
    assert db.count_logs(host="target.example") == 4


def test_exclude_host(db):
    assert db.count_logs(exclude_host="mozilla.org") == 7
    assert db.count_logs(exclude_host="target.example") == 4


def test_host_and_hide_static_combine(db):
    assert db.count_logs(host="mozilla.org", hide_static=True) == 1


def test_list_hosts(db):
    hosts = {h["host"]: h for h in db.list_hosts()}
    assert hosts["img-getpocket.cdn.mozilla.net"]["count"] == 1
    assert hosts["img-getpocket.cdn.mozilla.net"]["static"] == 1
    assert hosts["target.example"]["count"] == 4
    # The JSON one must not be counted as static; the css/png ones must be.
    assert hosts["target.example"]["static"] == 2
    # Busiest first.
    counts = [h["count"] for h in db.list_hosts()]
    assert counts == sorted(counts, reverse=True)


# ── Highlights / notes ──────────────────────────────────────────────

def test_highlight_roundtrip(db):
    row = db.get_logs(limit=1)[0]
    assert db.set_highlight(row["id"], "#3fb950") is True
    assert db.get_request(row["id"])["highlight"] == "#3fb950"
    assert db.set_highlight(row["id"], None) is True
    assert db.get_request(row["id"])["highlight"] is None


@pytest.mark.parametrize("color", HIGHLIGHT_COLORS)
def test_every_palette_color_accepted(db, color):
    row = db.get_logs(limit=1)[0]
    assert db.set_highlight(row["id"], color) is True


@pytest.mark.parametrize("bad", [
    "red", "#fff", "rgb(1,2,3)", "expression(alert(1))",
    "#3fb950; background:url(x)", "javascript:alert(1)",
])
def test_bad_highlight_rejected(db, bad):
    """Colors land in a style attribute, so anything off-palette is refused."""
    row = db.get_logs(limit=1)[0]
    with pytest.raises(ValueError):
        db.set_highlight(row["id"], bad)
    assert db.get_request(row["id"])["highlight"] is None


@pytest.mark.parametrize("empty", ["", None])
def test_empty_highlight_clears(db, empty):
    """Empty/None is the documented 'clear', not a validation error."""
    row = db.get_logs(limit=1)[0]
    db.set_highlight(row["id"], "#58a6ff")
    assert db.set_highlight(row["id"], empty) is True
    assert db.get_request(row["id"])["highlight"] is None


def test_highlight_is_case_insensitive(db):
    row = db.get_logs(limit=1)[0]
    assert is_valid_highlight("#3FB950")
    assert db.set_highlight(row["id"], "#3FB950") is True


def test_highlighted_only_filter(db):
    assert db.count_logs(highlighted_only=True) == 0
    row = db.get_logs(limit=1)[0]
    db.set_highlight(row["id"], "#f85149")
    assert db.count_logs(highlighted_only=True) == 1
    assert db.get_logs(highlighted_only=True)[0]["id"] == row["id"]


def test_annotate_partial_update(db):
    """Setting a note must not clear the highlight and vice versa."""
    row = db.get_logs(limit=1)[0]
    db.set_highlight(row["id"], "#58a6ff")
    db.annotate(row["id"], note="csrf check")
    assert db.get_request(row["id"])["highlight"] == "#58a6ff"
    db.annotate(row["id"], highlight="#f778ba")
    assert db.get_request(row["id"])["note"] == "csrf check"
    db.annotate(row["id"], note="")
    assert db.get_request(row["id"])["note"] is None


def test_get_highlights_map(db):
    ids = [r["id"] for r in db.get_logs(limit=3)]
    db.set_highlight(ids[0], "#e3b341")
    db.set_highlight(ids[1], "#39c5cf")
    m = db.get_highlights()
    assert m == {ids[0]: "#e3b341", ids[1]: "#39c5cf"}


# ── Noise rules ─────────────────────────────────────────────────────

def test_bundled_rules_seeded_disabled(db):
    rules = {r["value"]: r for r in db.list_noise_rules()}
    for host in DEFAULT_NOISE_HOSTS:
        assert host in rules
        # Seeded disabled: a built-in list must never silently drop captures.
        assert rules[host]["enabled"] == 0
        assert rules[host]["builtin"] == 1


def test_seeding_is_idempotent(db):
    before = len(db.list_noise_rules())
    Database(db.db_path)
    assert len(db.list_noise_rules()) == len(db.list_noise_rules())
    assert before == len(db.list_noise_rules())


def test_add_and_enable_rule(db):
    rid = db.add_noise_rule("telemetry.example.com")
    assert db.is_noise("https://telemetry.example.com/x") is True
    assert db.is_noise("https://target.example/x") is False
    # Disable it again.
    db.set_noise_rule_enabled(rid, False)
    assert db.is_noise("https://telemetry.example.com/x") is False


def test_rule_wildcard_and_suffix(db):
    db.add_noise_rule("*.ads.example.com")
    assert db.is_noise("https://track.ads.example.com/x") is True
    db.add_noise_rule("cdn.example.net")
    assert db.is_noise("https://static.cdn.example.net/a.png") is True
    assert db.is_noise("https://example.net/a.png") is False


def test_plain_rule_value_covers_subdomains(db):
    """A bare domain is a suffix match, so subdomains are covered too."""
    db.add_noise_rule("example.com")
    assert db.is_noise("https://a.example.com/x") is True
    assert db.is_noise("https://example.com/x") is True
    # …but not a lookalike that merely contains it.
    assert db.is_noise("https://notexample.com/x") is False


@pytest.mark.parametrize("bad", ["", "   ", "has/slash"])
def test_bad_rule_values(db, bad):
    with pytest.raises(ValueError):
        db.add_noise_rule(bad)


def test_rule_kind_validated(db):
    with pytest.raises(ValueError):
        db.add_noise_rule("x.example", kind="bogus")


def test_delete_rule(db):
    rid = db.add_noise_rule("gone.example")
    assert db.delete_noise_rule(rid) is True
    assert db.is_noise("https://gone.example/x") is False
    assert db.delete_noise_rule(rid) is False


def test_enable_all_rules(db):
    db.enable_all_noise_rules(True)
    assert all(r["enabled"] for r in db.list_noise_rules())
    assert db.is_noise("https://incoming.telemetry.mozilla.org/v1/ping") is True
    db.enable_all_noise_rules(False)
    assert not any(r["enabled"] for r in db.list_noise_rules())


def test_is_noise_uses_host_not_path(db):
    """Only the host decides; a noise-looking path segment must not match."""
    db.add_noise_rule("ads.example.com")
    assert db.is_noise("https://target.example/ads.example.com/x") is False
    assert db.is_noise("https://ads.example.com/anything") is True


# ── Scan / clean ────────────────────────────────────────────────────

def test_scan_is_a_dry_run(db):
    before = db.count_logs()
    db.enable_all_noise_rules(True)
    scan = db.scan_noise()
    assert db.count_logs() == before  # nothing was deleted
    assert scan["matched"] + scan["keep"] == before
    # Matched: app.css + /render(image/png) + pocket jpeg + ytimg jpeg
    # + gstatic woff2 (static) + the telemetry ping (enabled noise host).
    assert scan["matched"] == 6
    # Kept: the JSON API row and the text/html login row.
    assert scan["keep"] == 2


def test_scan_counts_static_assets_even_without_rules(db):
    scan = db.scan_noise()
    by_host = {b["host"]: b["removed"] for b in scan["by_host"]}
    assert by_host["target.example"] == 2  # css + image/png
    assert by_host["img-getpocket.cdn.mozilla.net"] == 1


def test_clean_removes_and_backs_up(db):
    db.enable_all_noise_rules(True)
    result = db.clean_noise()
    assert result["removed"] == 6
    assert db.count_logs() == 2
    # The two surviving rows are the API call and the login page.
    assert db.count_logs(host="target.example") == 2
    assert db.count_logs(host="target.example", hide_static=True) == 2
    from pathlib import Path
    assert Path(result["backup"]).is_file()


def test_clean_keep_hosts_protects(db):
    db.add_noise_rule("target.example")
    db.clean_noise(keep_hosts=["target.example"])
    assert db.count_logs(host="target.example") == 4


def test_clean_without_backup(tmp_path):
    d = Database(tmp_path / "t.db")
    rid = d.store_request(method="GET", url="https://x.example/a.css", headers={}, body="")
    d.update_response(rid, 200, {}, "{}", "text/css")
    result = d.clean_noise(backup=False)
    assert result["removed"] == 1
    assert result["backup"] == ""
    assert d.count_logs() == 0


def test_clean_cascades_intruder_results(db):
    db.enable_all_noise_rules(True)
    victim = db.get_logs(limit=1)[0]
    dbid = victim["id"]
    db.store_intruder_results([{
        "request_id": dbid, "payload": "p", "method": "GET",
        "url": "https://target.example/api/users?id=1",
        "response_code": 200,
    }])
    assert db.get_intruder_results(dbid)
    db.clean_noise(keep_hosts=["target.example"])
    assert db.get_intruder_results(dbid)  # protected by keep_hosts


# ── Count correctness ───────────────────────────────────────────────

def test_count_matches_list_length(db):
    for flt in ({}, {"hide_static": True}, {"host": "target.example"},
                {"method": "GET"}, {"status_class": "2"}, {"highlighted_only": True}):
        assert db.count_logs(**flt) == len(db.get_logs(limit=10_000, **flt)), flt


def test_invalid_status_class_still_raises(db):
    with pytest.raises(ValueError):
        db.count_logs(status_class="9")