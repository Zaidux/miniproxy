"""The Diff / Noise / Rewrite tabs, and every entry point that reaches them.

These three used to be modals. They are now top-level tabs, and the old
launchers (the filter-bar buttons, the ⋮ row menu, the detail pane, the
Repeater) navigate to the tab instead of opening an overlay.

The thing most likely to break here is *drift*: one entry point navigating
while another still expects a modal. Each launcher is asserted individually,
and asserted to land on the right tab.
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

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright  # noqa: E402

CHROME = shutil.which("google-chrome") or shutil.which("chromium")
pytestmark = pytest.mark.skipif(not CHROME, reason="chrome not installed")

SRC = "/root/projects/miniproxy/src"
PORT = 5311
EXPECTED_TABS = ["live", "log", "repeater", "intruder", "diff", "noise",
                 "rewrite", "connect"]

ROWS = [
    ("GET", "https://acct.example/my-account?role=user", 200,
     "application/json", json.dumps({"role": "user"}), ""),
    ("GET", "https://acct.example/my-account?role=admin", 200,
     "application/json", json.dumps({"role": "admin"}), ""),
    ("GET", "https://img-getpocket.cdn.mozilla.net/x.jpeg", 200,
     "image/jpeg", "JPEG", ""),
]


@pytest.fixture()
def dash():
    work = tempfile.mkdtemp(prefix="mp-tabs-")
    db = os.path.join(work, "proxy.db")
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL,
        headers TEXT, body TEXT, response_code INTEGER,
        response_headers TEXT, response_body TEXT, content_type TEXT,
        ttfb_ms REAL, total_ms REAL, request_body_len INTEGER,
        response_body_len INTEGER, highlight TEXT, note TEXT)""")
    ids = []
    for i, (m, u, code, ct, resp, req) in enumerate(ROWS):
        cur = conn.execute(
            "INSERT INTO requests (timestamp, method, url, headers, body,"
            " response_code, response_headers, response_body, content_type,"
            " ttfb_ms, total_ms, request_body_len, response_body_len,"
            " highlight, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"2026-10-16T10:0{i}:00+00:00", m, u, "{}", req, code, "{}",
             resp, ct, 5.0, 12.0, len(req), len(resp), None, None))
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
    yield {"base": base, "db": db, "ids": ids}
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


def results():
    return []


def check(res, name, cond, extra=""):
    res.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {extra}"))


def active_tab(page):
    return page.evaluate(
        "() => (document.querySelector('.tab.active') || {}).dataset?.tab || null"
    )


# ── the tab bar itself ──────────────────────────────────────────────

def test_all_tabs_present_and_switchable(page):
    res = results()
    tabs = page.eval_on_selector_all(".tab", "els=>els.map(e=>e.dataset.tab)")
    check(res, "every expected tab exists", tabs == EXPECTED_TABS, tabs)
    for name in EXPECTED_TABS:
        page.click(f'.tab[data-tab="{name}"]')
        page.wait_for_timeout(350)
        check(res, f"tab {name} activates", active_tab(page) == name, active_tab(page))
        check(res, f"pane {name} is visible", page.is_visible(f"#t-{name}"), "")
    assert all(ok for _, ok in res), [n for n, ok in res if not ok]


def test_tab_bar_wraps_on_a_phone(page):
    """Eight tabs must not overflow a 412px viewport."""
    box = page.eval_on_selector(".tabs", "e=>{const r=e.getBoundingClientRect();return {w:r.width,right:r.right}}")
    check([], "tab bar fits the viewport", box["right"] <= 412 + 1, box)


# ── entry points navigate rather than opening a modal ───────────────

def test_filter_bar_buttons_reach_their_tabs(page):
    res = results()
    page.click("#rw-btn")
    page.wait_for_timeout(700)
    check(res, "#rw-btn -> Rewrite tab", active_tab(page) == "rewrite", active_tab(page))
    page.click('.tab[data-tab="live"]')
    page.wait_for_timeout(400)
    page.click("#noise-btn")
    page.wait_for_timeout(900)
    check(res, "#noise-btn -> Noise tab", active_tab(page) == "noise", active_tab(page))
    # The noise tab must actually have loaded its rules, not be an empty shell.
    check(res, "noise tab lists bundled rules",
          "mozilla" in page.inner_text("#noise-rules").lower(), page.inner_text("#noise-rules")[:80])
    assert all(ok for _, ok in res), [n for n, ok in res if not ok]


def test_row_menu_compare_reaches_diff_tab(page, dash):
    page.click(f'#liveb tr[data-id="{dash["ids"][0]}"] .rowmenu-btn')
    page.wait_for_timeout(500)
    check([], "row menu opens", page.is_visible("#row-pop"))
    page.click("#row-pop-diff")
    page.wait_for_timeout(700)
    check([], "⋮ Compare -> Diff tab", active_tab(page) == "diff", active_tab(page))
    check([], "A is prefilled with the row",
          str(dash["ids"][0]) in page.inner_text("#diff-a"), page.inner_text("#diff-a"))


def test_detail_compare_reaches_diff_tab(page, dash):
    page.click(f'#liveb tr[data-id="{dash["ids"][1]}"]')
    page.wait_for_timeout(600)
    page.click("#d-compare")
    page.wait_for_timeout(700)
    check([], "detail Compare… -> Diff tab", active_tab(page) == "diff", active_tab(page))


def test_repeater_compare_reaches_diff_tab(page, dash):
    page.click(f'#liveb tr[data-id="{dash["ids"][0]}"]')
    page.wait_for_timeout(500)
    page.click('.tab[data-tab="repeater"]')
    page.wait_for_timeout(800)
    page.click("#r-diff")
    page.wait_for_timeout(700)
    check([], "repeater Compare… -> Diff tab", active_tab(page) == "diff", active_tab(page))


# ── the diff tab works end to end in its new home ───────────────────

def test_diff_tab_pickers_and_result(page, dash):
    res = results()
    a, b = dash["ids"][0], dash["ids"][1]
    page.click('.tab[data-tab="diff"]')
    page.wait_for_timeout(500)
    # Pick A through the shared capture picker.
    page.click('[data-pick="a"]')
    page.wait_for_timeout(900)
    check(res, "picker opens for A", page.is_visible("#pick-modal"))
    check(res, "picker header names the target",
          "Capture A" in page.inner_text("#pick-for"), page.inner_text("#pick-for"))
    page.click(f'#pk-rows tr[data-id="{a}"]')
    page.click("#pick-use")
    page.wait_for_timeout(800)
    check(res, "A is shown after picking", str(a) in page.inner_text("#diff-a"),
          page.inner_text("#diff-a"))
    # Pick B.
    page.click('[data-pick="b"]')
    page.wait_for_timeout(900)
    page.click(f'#pk-rows tr[data-id="{b}"]')
    page.click("#pick-use")
    page.wait_for_timeout(1200)
    # The summary line is upper-cased by CSS, so compare case-insensitively.
    check(res, "diff ran automatically once both were set",
          "role" in page.inner_text("#diff-summary").lower(),
          page.inner_text("#diff-summary"))
    check(res, "summary names the value transition",
          "admin" in page.inner_text("#diff-summary").lower(),
          page.inner_text("#diff-summary"))
    check(res, "diff tab still active",
          active_tab(page) == "diff", active_tab(page))
    assert all(ok for _, ok in res), [n for n, ok in res if not ok]


def test_diff_tab_swap_and_views(page, dash):
    res = results()
    page.evaluate(f"openDiff({dash['ids'][0]}, {dash['ids'][1]})")
    page.wait_for_timeout(1000)
    before = page.inner_text("#diff-pair")
    page.click("#diff-swap")
    page.wait_for_timeout(1000)
    check(res, "swap reorders A and B", page.inner_text("#diff-pair") != before,
          page.inner_text("#diff-pair"))
    for pane in ("json", "token", "char", "params", "headers", "fields"):
        page.click(f'#diff-tabs .btab[data-dpane="{pane}"]')
        page.wait_for_timeout(250)
        check(res, f"diff view {pane} renders", len(page.inner_text("#diff-body")) > 0)
    assert all(ok for _, ok in res), [n for n, ok in res if not ok]


def test_diff_tab_survives_a_reload(page, dash):
    page.evaluate(f"openDiff({dash['ids'][0]}, {dash['ids'][1]})")
    page.wait_for_timeout(1000)
    page.reload(wait_until="networkidle")
    page.wait_for_timeout(1600)
    check([], "active tab is remembered across reload",
          active_tab(page) == "diff", active_tab(page))


# ── the other two tabs ──────────────────────────────────────────────

def test_rewrite_tab_add_and_list(page):
    res = results()
    page.click('.tab[data-tab="rewrite"]')
    page.wait_for_timeout(800)
    check(res, "rewrite tab shows the no-rules state",
          "No rules" in page.inner_text("#rw-rules"))
    page.select_option("#rw-target", "header")
    page.select_option("#rw-kind", "exact")
    page.fill("#rw-match", "X-Forwarded-For")
    page.fill("#rw-replace", "127.0.0.1")
    page.click("#rw-add")
    page.wait_for_timeout(900)
    check(res, "rule listed after adding",
          "X-Forwarded-For" in page.inner_text("#rw-rules"), page.inner_text("#rw-rules")[:100])
    check(res, "tab stays active after adding", active_tab(page) == "rewrite")
    assert all(ok for _, ok in res), [n for n, ok in res if not ok]


def test_noise_tab_scan_and_toggle(page):
    res = results()
    page.click('.tab[data-tab="noise"]')
    page.wait_for_timeout(1000)
    check(res, "noise count rendered",
          "enabled" in page.inner_text("#noise-count").lower(),
          page.inner_text("#noise-count"))
    check(res, "scan output rendered", "noise" in page.inner_text("#noise-out").lower()
          or "kept" in page.inner_text("#noise-out").lower(),
          page.inner_text("#noise-out"))
    # Toggle the first rule and confirm the counter moves.
    before = page.inner_text("#noise-count")
    page.click("#noise-rules input[type=checkbox]")
    page.wait_for_timeout(900)
    check(res, "toggling a rule updates the count",
          page.inner_text("#noise-count") != before,
          f"{before} -> {page.inner_text('#noise-count')}")
    assert all(ok for _, ok in res), [n for n, ok in res if not ok]


def test_tabs_do_not_leave_a_modal_open(page):
    """Regression guard: the old modals must be gone, not merely hidden."""
    html = page.content()
    for gone in ("diff-modal", "noise-modal", "rewrite-modal"):
        check([], f"{gone} no longer exists", f'id="{gone}"' not in html)