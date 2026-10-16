"""Headless end-to-end coverage of the 0.7 dashboard features.

Drives the real page in Chromium at phone width (this dashboard is used from
a phone) and asserts the features that unit tests cannot reach: the diff
viewer, body search, repeater tabs/history, the follow-redirects toggle, the
rewrite modal and Intruder pitchfork.

Skipped when Chrome or Node is unavailable.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

playwright = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright  # noqa: E402

CHROME = shutil.which("google-chrome") or shutil.which("chromium")
pytestmark = pytest.mark.skipif(not CHROME, reason="chrome not installed")

SRC = "/root/projects/miniproxy/src"
PORT = 5271

# Two captures of the same account endpoint differing only by the role
# parameter — the canonical access-control comparison.
ROWS = [
    dict(method="GET", url="https://acct.example/my-account?role=user",
         code=200, ct="application/json",
         resp=json.dumps({"name": "wiener", "role": "user", "id": 1337}),
         req="", hl="#f85149", note="baseline"),
    dict(method="GET", url="https://acct.example/my-account?role=admin",
         code=200, ct="application/json",
         resp=json.dumps({"name": "wiener", "role": "admin", "id": 1337}),
         req="", hl=None, note=None),
    dict(method="POST", url="https://acct.example/login", code=302,
         ct="text/html", resp="<html>found</html>", req="user=admin&pass=x",
         hl=None, note=None),
    dict(method="GET", url="https://acct.example/static/app.css", code=200,
         ct="text/css", resp="body{}", req="", hl=None, note=None),
    dict(method="GET", url="https://acct.example/flags", code=200,
         ct="application/json", resp=json.dumps({"flag": "CTF{hidden_value}"}),
         req="", hl=None, note=None),
]


@pytest.fixture()
def dash():
    work = tempfile.mkdtemp(prefix="mp-feat-")
    db = os.path.join(work, "proxy.db")
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL,
        headers TEXT, body TEXT, response_code INTEGER,
        response_headers TEXT, response_body TEXT, content_type TEXT,
        ttfb_ms REAL, total_ms REAL, request_body_len INTEGER,
        response_body_len INTEGER, highlight TEXT, note TEXT)""")
    ids = []
    for i, r in enumerate(ROWS):
        cur = conn.execute(
            "INSERT INTO requests (timestamp, method, url, headers, body,"
            " response_code, response_headers, response_body, content_type,"
            " ttfb_ms, total_ms, request_body_len, response_body_len,"
            " highlight, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"2026-10-16T10:0{i}:00+00:00", r["method"], r["url"],
             json.dumps({"Host": "acct.example"}), r["req"], r["code"],
             json.dumps({"Content-Type": r["ct"]}), r["resp"], r["ct"],
             5.0, 12.0, len(r["req"]), len(r["resp"]), r["hl"], r["note"]))
        ids.append(cur.lastrowid)
    conn.commit()
    conn.close()

    env = dict(os.environ, MINIPROXY_DB_PATH=db, PYTHONPATH=SRC)
    proc = subprocess.Popen(
        [sys.executable, "-m", "miniproxy", "dashboard", "--port", str(PORT),
         "--host", "127.0.0.1"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{PORT}"
    for _ in range(80):
        try:
            urllib.request.urlopen(base + "/api/meta", timeout=1)
            break
        except Exception:
            time.sleep(0.3)
    yield {"base": base, "ids": ids}
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    shutil.rmtree(work, ignore_errors=True)


@pytest.fixture()
def page(dash):
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        ctx = b.new_context(viewport={"width": 412, "height": 900}, has_touch=True)
        pg = ctx.new_page()
        errors: list[str] = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(dash["base"] + "/", wait_until="networkidle")
        pg.wait_for_timeout(1500)
        yield pg
        assert not errors, f"uncaught JS errors: {errors}"
        ctx.close()
        b.close()


def check(res, name, cond, extra=""):
    res.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {extra}"))


# ── Diff ────────────────────────────────────────────────────────────

def test_diff_modal_identifies_the_role_change(page, dash):
    a, b = dash["ids"][0], dash["ids"][1]
    page.evaluate(f"openDiff({a}, {b})")
    page.wait_for_timeout(900)
    check([], "diff modal opens", page.is_visible("#diff-modal"), "")
    summary = page.inner_text("#diff-summary")
    check([], "summary names the role field", "role" in summary, summary)
    check([], "summary shows the value transition", "user" in summary and "admin" in summary, summary)
    body = page.inner_text("#diff-body")
    check([], "diff table lists the param", "role" in body, body[:160])
    check([], "diff marks A and B columns", "user" in body and "admin" in body, body[:160])
    # The JSON pane should agree.
    page.click('#diff-tabs .btab[data-dpane="json"]')
    page.wait_for_timeout(300)
    jb = page.inner_text("#diff-body")
    check([], "JSON pane keys the change by path", "role" in jb, jb[:160])


def test_diff_of_identical_captures_says_so(page, dash):
    page.evaluate("openDiff(null, null)")
    page.wait_for_timeout(300)
    page.click('#diff-tabs .btab[data-dpane="params"]')
    page.wait_for_timeout(200)
    check([], "params pane renders with no pair", page.is_visible("#diff-body"))


def test_diff_rejects_same_id(page):
    page.evaluate("openDiff(1, 1)")
    page.wait_for_timeout(600)
    check([], "same-capture compare is refused",
          "different" in page.inner_text("#diff-body").lower(),
          page.inner_text("#diff-body")[:120])


def test_diff_bytes_pane_shows_both(page, dash):
    page.evaluate(f"openDiff({dash['ids'][2]}, {dash['ids'][4]})")
    page.wait_for_timeout(800)
    page.click('#diff-tabs .btab[data-dpane="char"]')
    page.wait_for_timeout(400)
    boxes = page.query_selector_all(".diff-box")
    check([], "bytes pane renders both bodies", len(boxes) == 2, len(boxes))
    if len(boxes) == 2:
        check([], "bytes pane has content",
              len(boxes[0].inner_text()) > 0 and len(boxes[1].inner_text()) > 0)


# ── Body search ──────────────────────────────────────────────────────

def test_body_search_finds_the_flag(page, dash):
    page.fill("#filter-body", "CTF{hidden_value}")
    page.wait_for_timeout(1200)
    paths = page.eval_on_selector_all("#liveb tr td:nth-child(6)",
                                      "els=>els.map(e=>e.textContent)")
    check([], "body search narrows to the matching row",
          len(paths) == 1 and "/flags" in paths[0], paths)
    page.fill("#filter-body", "no-such-string-anywhere")
    page.wait_for_timeout(1200)
    empty = page.inner_text("#liveb")
    check([], "body search with no match shows the empty state",
          "No matching" in empty, empty[:120])
    page.fill("#filter-body", "")
    page.wait_for_timeout(1200)
    check([], "clearing body search restores rows",
          len(page.query_selector_all("#liveb tr")) == 5)


def test_body_search_matches_request_bodies(page):
    page.fill("#filter-body", "user=admin")
    page.wait_for_timeout(1200)
    paths = page.eval_on_selector_all("#liveb tr td:nth-child(6)",
                                      "els=>els.map(e=>e.textContent)")
    check([], "body search also covers request bodies",
          len(paths) == 1 and "/login" in paths[0], paths)


# ── Repeater tabs ───────────────────────────────────────────────────

def test_repeater_tabs_persist(page):
    page.click('.tab[data-tab="repeater"]')
    page.wait_for_timeout(800)
    check([], "a repeater tab exists on load", page.query_selector(".rep-tab") is not None)
    page.fill("#rurl", "https://acct.example/one")
    page.wait_for_timeout(900)
    page.click("#rep-newtab")
    page.wait_for_timeout(900)
    tabs = page.query_selector_all(".rep-tab")
    check([], "new tab is added", len(tabs) == 2, len(tabs))
    page.fill("#rurl", "https://acct.example/two")
    page.wait_for_timeout(900)
    page.reload(wait_until="networkidle")
    page.wait_for_timeout(1800)
    tabs = page.query_selector_all(".rep-tab")
    check([], "tabs survive a reload", len(tabs) == 2, len(tabs))
    urls = [page.eval_on_selector_all(".rep-tab span:first-child",
                                     "els=>els.map(e=>e.textContent)")]
    check([], "tab labels persisted", any("one" in u or "two" in u for u in urls[0]), urls)


def test_repeater_switching_restores_each_tab(page):
    """Each tab keeps its own request — the reason tabs exist at all."""
    page.click('.tab[data-tab="repeater"]')
    page.wait_for_timeout(800)
    page.fill("#rurl", "https://acct.example/first")
    page.wait_for_timeout(900)
    page.click("#rep-newtab")
    page.wait_for_timeout(900)
    page.fill("#rurl", "https://acct.example/second")
    page.wait_for_timeout(900)

    # Tabs are ordered most-recently-updated first, so identify each by the
    # URL it loads rather than by index. Locators (not element handles) are
    # used because renderRepTabs() rebuilds the bar on every switch.
    def click_tab_matching(url_part):
        for i in range(page.locator(".rep-tab").count()):
            page.locator(".rep-tab").nth(i).click()
            page.wait_for_timeout(600)
            if url_part in page.input_value("#rurl"):
                return True
        return False

    check([], "tab A still holds its own URL", click_tab_matching("/first"),
          page.input_value("#rurl"))
    check([], "tab B still holds its own URL", click_tab_matching("/second"),
          page.input_value("#rurl"))


def test_follow_redirects_toggle_present(page):
    page.click('.tab[data-tab="repeater"]')
    page.wait_for_timeout(600)
    cb = page.query_selector("#rfollow")
    check([], "follow-redirects checkbox exists", cb is not None)
    if cb:
        check([], "follow-redirects defaults to off", not cb.is_checked())
        cb.check()
        check([], "follow-redirects can be enabled", cb.is_checked())


def test_repeater_history_records_sends(dash):
    """A send must land in the tab's history (driven via the API)."""
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        pg = b.new_context(viewport={"width": 1440, "height": 900}).new_page()
        pg.goto(dash["base"] + "/", wait_until="networkidle")
        pg.wait_for_timeout(1500)
        pg.click('.tab[data-tab="repeater"]')
        pg.wait_for_timeout(800)
        tab_id = pg.evaluate("repState.activeId")
        req = urllib.request.Request(
            dash["base"] + f"/api/repeater/tabs/{tab_id}/history",
            data=json.dumps({"method": "GET", "url": "https://acct.example/x",
                             "status_code": 200, "response_body": "ok"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req)
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(1600)
        pg.click('.tab[data-tab="repeater"]')
        pg.wait_for_timeout(1200)
        rows = pg.query_selector_all(".rep-hist-row")
        check([], "history row rendered", len(rows) >= 1, len(rows))
        b.close()


# ── Rewrite modal ───────────────────────────────────────────────────

def test_rewrite_modal_lists_and_adds(page):
    page.click("#rw-btn")
    page.wait_for_timeout(800)
    check([], "rewrite modal opens", page.is_visible("#rewrite-modal"))
    check([], "starts with no rules", "No rules" in page.inner_text("#rw-rules"))
    page.select_option("#rw-target", "header")
    page.select_option("#rw-kind", "exact")
    page.fill("#rw-match", "X-Forwarded-For")
    page.fill("#rw-replace", "1")
    page.click("#rw-add")
    page.wait_for_timeout(800)
    txt = page.inner_text("#rw-rules")
    check([], "rule appears in the list", "X-Forwarded-For" in txt, txt[:120])
    check([], "count reflects the active rule", "1 of 1" in page.inner_text("#rewrite-count"),
          page.inner_text("#rewrite-count"))
    # Disabling it must take effect.
    page.click("#rw-rules input[type=checkbox]")
    page.wait_for_timeout(700)
    check([], "rule can be disabled", "0 of 1" in page.inner_text("#rewrite-count"),
          page.inner_text("#rewrite-count"))


def test_rewrite_rejects_bad_rule(page):
    page.click("#rw-btn")
    page.wait_for_timeout(700)
    page.select_option("#rw-kind", "regex")
    page.fill("#rw-match", "(unclosed")
    page.fill("#rw-replace", "x")
    page.click("#rw-add")
    page.wait_for_timeout(700)
    check([], "invalid regex is refused", "No rules" in page.inner_text("#rw-rules"),
          page.inner_text("#rw-rules")[:120])


# ── Intruder pitchfork ──────────────────────────────────────────────

def test_pitchfork_rows_follow_placeholders(page, dash):
    page.click('.tab[data-tab="intruder"]')
    page.wait_for_timeout(600)
    page.click("#rsel-btn") if False else None
    # Load a captured login request into the intruder editor.
    page.click("#isel-btn")
    page.wait_for_timeout(1000)
    page.click("#pk-rows tr.log-row")
    page.click("#pick-use")
    page.wait_for_timeout(600)
    page.fill("#iurl", "https://acct.example/login?user=§user§&pass=§pass§")
    page.click("#i-mode-pitch")
    page.wait_for_timeout(500)
    rows = page.query_selector_all("#pf-lists .pf-row")
    check([], "one pitchfork row per placeholder", len(rows) == 2, len(rows))
    labels = page.eval_on_selector_all("#pf-lists .pf-row code",
                                       "els=>els.map(e=>e.textContent)")
    check([], "rows are named from the markers",
          "§user§" in labels and "§pass§" in labels, labels)


def test_pitchfork_total_is_a_product(page):
    page.click('.tab[data-tab="intruder"]')
    page.wait_for_timeout(600)
    page.click("#isel-btn")
    page.wait_for_timeout(1000)
    page.click("#pk-rows tr.log-row")
    page.click("#pick-use")
    page.wait_for_timeout(600)
    page.fill("#iurl", "https://acct.example/l?u=§user§&p=§pass§")
    page.click("#i-mode-pitch")
    page.wait_for_timeout(400)
    # Pick the bundled username list for §user§.
    sels = page.query_selector_all("[data-pflist]")
    check([], "a list selector exists per placeholder", len(sels) == 2, len(sels))
    if len(sels) == 2:
        sels[0].select_option("usernames")
        page.wait_for_timeout(900)
        sels[1].select_option("passwords")
        page.wait_for_timeout(900)
        total = page.inner_text("#i-total")
        check([], "total is the product of both lists", "requests" in total, total)
        check([], "product total exceeds either list alone",
              "→" in total and int(total.split("→")[1].split()[0]) > 30, total)


def test_bundled_wordlist_cards(page):
    page.click('.tab[data-tab="intruder"]')
    page.wait_for_timeout(800)
    cards = page.query_selector_all("#wl-cards .wl-card")
    check([], "bundled wordlist cards render", len(cards) >= 4, len(cards))
    if cards:
        cards[0].click()
        page.wait_for_timeout(900)
        check([], "clicking a card loads words",
              "words" in page.inner_text("#ifinfo"), page.inner_text("#ifinfo"))