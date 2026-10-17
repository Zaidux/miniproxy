"""The Intruder results table: sort, filter, outliers, and diffing two results.

Two capabilities, both aimed at the same job — reading a few hundred responses
for the one that behaved differently:

  * **sort / filter / outliers.** Sorting by response size and filtering to
    rows whose length differs from the most common length is, mechanically,
    the username-enumeration skill: a login form that answers "Invalid
    password" for a real user and "Invalid username" for a fake one.

  * **diff two results.** Intruder results live in `intruder_results`, a
    different table with a different id space from captures, so the Diff tab
    could not reach them. It now can.

Nothing here is stubbed: a real HTTP server answers as a login form would,
a real dashboard runs the attack, and a real browser drives the UI.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright  # noqa: E402

CHROME = shutil.which("google-chrome") or shutil.which("chromium")
pytestmark = pytest.mark.skipif(not CHROME, reason="chrome not installed")

SRC = "/root/projects/miniproxy/src"
DASH_PORT = 5321
TARGET_PORT = 5322

# The two response bodies differ in length on purpose: that difference is the
# signal the outlier filter is meant to surface.
BODY_VALID = b'{"error":"Invalid password"}'      # 26 chars — a real user, wrong password
BODY_INVALID = b'{"error":"Invalid username that is not registered at all"}'  # 51 — noise

USERNAMES = ["admin", "bob", "eve", "mallory", "trent", "alice", "frank", "grace"]
SENT: list[str] = []
PATHS: list[str] = []


class _Login(BaseHTTPRequestHandler):
    """A login form that leaks whether a username exists."""

    def log_message(self, *a):  # keep pytest output clean
        pass

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        user = ""
        for pair in raw.split("&"):
            if pair.startswith("username="):
                user = pair[len("username="):]
        if self.path.startswith("/login?"):
            user = self.path.split("username=", 1)[-1].split("&")[0]
        SENT.append(user)
        PATHS.append(self.path)
        if user == "admin":
            body, code = BODY_VALID, 302
        else:
            body, code = BODY_INVALID, 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if code == 302:
            self.send_header("Location", "/home")
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture(scope="module")
def target():
    srv = ThreadingHTTPServer(("127.0.0.1", TARGET_PORT), _Login)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{TARGET_PORT}"
    srv.shutdown()


@pytest.fixture(scope="module")
def dash(target):
    work = tempfile.mkdtemp(prefix="mp-res-")
    db = os.path.join(work, "proxy.db")
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL,
        headers TEXT, body TEXT, response_code INTEGER,
        response_headers TEXT, response_body TEXT, content_type TEXT,
        ttfb_ms REAL, total_ms REAL, request_body_len INTEGER,
        response_body_len INTEGER, highlight TEXT, note TEXT)""")
    url = f"{target}/login?username=§user§&password=wrong"
    conn.execute(
        "INSERT INTO requests (timestamp, method, url, headers, body,"
        " response_code, response_headers, response_body, content_type,"
        " ttfb_ms, total_ms, request_body_len, response_body_len,"
        " highlight, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("2026-10-17T10:00:00+00:00", "GET", url, "{}", "", 200, "{}",
         "{}", "application/json", 5.0, 12.0, 0, 2, None, None))
    conn.commit()
    conn.close()

    env = dict(os.environ, MINIPROXY_DB_PATH=db, PYTHONPATH=SRC)
    proc = subprocess.Popen(
        [sys.executable, "-m", "miniproxy", "dashboard", "--port", str(DASH_PORT),
         "--host", "127.0.0.1"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{DASH_PORT}"
    for _ in range(80):
        try:
            urllib.request.urlopen(base + "/api/meta", timeout=1)
            break
        except Exception:
            time.sleep(0.3)
    yield {"base": base, "db": db, "target": target}
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
        pg.click('.tab[data-tab="intruder"]')
        pg.wait_for_timeout(600)
        pg.click("#isel-btn")
        pg.wait_for_timeout(1000)
        pg.click("#pk-rows tr.log-row")
        pg.click("#pick-use")
        pg.wait_for_timeout(600)
        pg.fill("#ipaste", "\n".join(USERNAMES))
        pg.wait_for_timeout(300)
        yield pg
        assert not errors, f"uncaught JS errors: {errors}"
        ctx.close()
        b.close()


def run_attack(page):
    """Run the attack and wait for the results table to populate."""
    page.click("#istart")
    for _ in range(60):
        page.wait_for_timeout(500)
        if page.query_selector_all("#iresb tr[data-rid]"):
            if not page.inner_text("#istart").strip().startswith("Running"):
                return
    pytest.fail("attack never produced results")


def text(page, sel):
    """Raw DOM text. Playwright's inner_text() applies CSS text-transform, and
    both #icnt and #diff-summary live inside an uppercased .card-header."""
    return (page.text_content(sel) or "").strip()


def row_payloads(page):
    return page.eval_on_selector_all(
        "#iresb tr[data-rid]", "els => els.map(e => e.children[1].textContent.trim())")


def numbers(page):
    return page.eval_on_selector_all(
        "#iresb tr[data-rid]", "els => els.map(e => e.children[0].textContent.trim())")


def sizes(page):
    return [int(t) for t in page.eval_on_selector_all(
        "#iresb tr[data-rid]", "els => els.map(e => e.children[4].textContent.trim())")]


# ── results carry their own ids ─────────────────────────────────────

def test_results_expose_ids_so_they_can_be_diffed(page):
    """Each result row must carry the id of its `intruder_results` row.
    Without it the UI has nothing to hand the Diff tab, and the ids live in a
    different id space from captures."""
    run_attack(page)
    ids = page.eval_on_selector_all(
        "#iresb tr[data-rid]", "els => els.map(e => e.dataset.rid)")
    assert len(ids) == len(USERNAMES), ids
    assert all(i and i.isdigit() for i in ids), ids
    assert len(set(ids)) == len(ids), f"ids are not unique: {ids}"


def test_results_show_the_outlier_admin_row_first(page):
    run_attack(page)
    assert len(row_payloads(page)) == len(USERNAMES)
    sizes_seen = sizes(page)
    # Every response but admin's is the same 51-char body.
    assert sorted(sizes_seen)[0] == len(BODY_VALID.decode()), sizes_seen
    assert sorted(sizes_seen)[-1] == len(BODY_INVALID.decode()), sizes_seen


# ── sorting ─────────────────────────────────────────────────────────

def test_sort_by_size_puts_the_outlier_at_the_top(page):
    run_attack(page)
    page.select_option("#ires-sort", "size-asc")
    page.wait_for_timeout(400)
    top = row_payloads(page)[0]
    assert top == "admin", f"smallest response should be admin, got {top}"

    page.select_option("#ires-sort", "size-desc")
    page.wait_for_timeout(400)
    assert row_payloads(page)[0] != "admin", "largest should not be admin"


def test_sorting_keeps_the_send_order_column_stable(page):
    """Reordering rows must not renumber them — # means "the Nth request I
    sent". Asserted per payload: each one keeps its own number, *and* the
    display order genuinely changed, so the assertion has teeth. Comparing
    the two number-lists as sets would pass even under renumbering."""
    run_attack(page)
    before = dict(zip(row_payloads(page), numbers(page)))
    # Descending, because ascending puts admin first and admin already *is*
    # first — that sort reorders nothing and the assertion would be vacuous.
    page.select_option("#ires-sort", "size-desc")
    page.wait_for_timeout(400)
    after = dict(zip(row_payloads(page), numbers(page)))
    assert list(before) != list(after), "sorting did not reorder — assertion is vacuous"
    assert list(after)[-1] == "admin", list(after)
    assert before == after, f"renumbered on sort: {before} -> {after}"
    assert after["admin"] == "1", "admin lost its send-order number"


# ── the outlier filter ──────────────────────────────────────────────

def test_outlier_filter_isolates_the_one_different_response(page):
    """The whole point: one response of N is the odd one out."""
    run_attack(page)
    page.check("#ires-outlier")
    page.wait_for_timeout(400)
    assert row_payloads(page) == ["admin"], row_payloads(page)
    hint = text(page, "#ires-hint")
    assert str(len(BODY_INVALID.decode())) in hint and "differ" in hint, hint


def test_outlier_baseline_is_computed_before_filtering(page):
    """The baseline must be measured across every row, never the subset a
    filter has already narrowed.

    Combined with the status filter deliberately: with no status filter
    active the subset *is* every row, so the two implementations are
    indistinguishable and the test would pass either way. With status=3 only
    the 302 (admin, 26 chars) survives, so a baseline taken from the filtered
    set would read 26 and then discard admin as "not an outlier" — reporting
    no outliers when admin is precisely the one.
    """
    run_attack(page)
    page.check("#ires-outlier")
    page.wait_for_timeout(300)
    expect = "Most responses are " + str(len(BODY_INVALID.decode()))
    assert text(page, "#ires-hint").strip().startswith(expect), \
        text(page, "#ires-hint")

    page.select_option("#ires-status", "3")
    page.wait_for_timeout(400)
    assert row_payloads(page) == ["admin"], row_payloads(page)
    page.uncheck("#ires-outlier")
    page.wait_for_timeout(300)
    assert len(row_payloads(page)) == 1


def test_outlier_filter_says_so_when_nothing_stands_out(page, dash):
    """Every response identical is a real and common result; claiming there
    are "no results" would be a lie."""
    run_attack(page)
    # Shrink to a list where no response can differ: one username, admin.
    page.fill("#ipaste", "admin")
    page.wait_for_timeout(300)
    run_attack(page)
    page.check("#ires-outlier")
    page.wait_for_timeout(400)
    assert len(row_payloads(page)) == 0, row_payloads(page)
    assert "nothing stands out" in text(page, "#ires-hint"), text(page, "#ires-hint")


# ── status filter ───────────────────────────────────────────────────

def test_status_filter_narrows_to_the_redirect(page):
    run_attack(page)
    page.select_option("#ires-status", "3")
    page.wait_for_timeout(400)
    payloads = row_payloads(page)
    assert payloads == ["admin"], payloads
    assert "showing 1" in text(page, "#icnt"), text(page, "#icnt")


# ── viewing a single response ───────────────────────────────────────

def test_view_button_shows_the_response_without_an_alert(page):
    """It used to be an alert() — blocking, unscrollable, and impossible to
    read a 3KB body in."""
    run_attack(page)
    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    assert page.is_visible("#ires-modal.open")
    body = page.input_value("#ires-modal-res")
    assert BODY_INVALID.decode() in body or BODY_VALID.decode() in body, body[:120]
    assert "§user§" not in body, "placeholder leaked into the sent request"
    page.click("#ires-modal-close")
    page.wait_for_timeout(300)
    assert not page.is_visible("#ires-modal.open")


def test_tapping_the_view_button_does_not_also_select_the_row(page):
    """View opens a modal; it must not also count as picking a row for
    comparison. Asserted on the selection itself — the button label reads
    "Compare A / B" for both zero and one selection, so the label cannot tell
    these two cases apart."""
    run_attack(page)
    assert page.evaluate("() => ires.sel.length") == 0
    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    assert page.evaluate("() => ires.sel.length") == 0, (
        "View also counted as a selection")
    assert page.query_selector_all("#iresb .pick-badge") == [], "a badge appeared"
    page.click("#ires-modal-close")
    page.wait_for_timeout(200)


# ── selection + diff ────────────────────────────────────────────────

def test_compare_two_rows_opens_the_diff_tab(page):
    run_attack(page)
    page.click("#iresb tr[data-rid]:nth-child(1)")
    page.wait_for_timeout(200)
    page.click("#iresb tr[data-rid]:nth-child(2)")
    page.wait_for_timeout(200)
    btn = text(page, "#ires-cmp")
    assert "Compare" in btn and "Compare A / B" not in btn, btn
    page.click("#ires-cmp")
    page.wait_for_timeout(1500)
    assert page.evaluate(
        "() => (document.querySelector('.tab.active')||{}).dataset?.tab") == "diff"
    summary = text(page, "#diff-summary")
    assert summary.strip(), "diff produced no summary"


def test_diff_of_two_intruder_results_shows_the_username_signal(page):
    """admin vs bob: 302 vs 200, and the error field changes. That is the
    entire finding, and it must be legible in the diff."""
    run_attack(page)
    rows = page.eval_on_selector_all(
        "#iresb tr[data-rid]",
        "els => els.map(e => e.dataset.rid + ':' + e.children[1].textContent.trim())")
    admin = next(r.split(":")[0] for r in rows if r.endswith("admin"))
    bob = next(r.split(":")[0] for r in rows if r.endswith("bob"))
    page.click(f'#iresb tr[data-rid="{admin}"]')
    page.wait_for_timeout(200)
    page.click(f'#iresb tr[data-rid="{bob}"]')
    page.wait_for_timeout(200)
    page.click("#ires-cmp")
    page.wait_for_timeout(2000)

    summary = text(page, "#diff-summary")
    assert "302" in summary and "200" in summary, summary
    assert "Invalid password" in summary and "Invalid username" in summary, summary
    # The "What changed" pane renders field *values*, so the raw bodies are
    # checked in the Bytes pane — which is exactly the pane that used to
    # render "(empty)" for every pair, because runDiff read data.body_a,
    # which the diff payload never contained.
    assert "A body" not in text(page, "#diff-body"), "Bytes pane already active?"
    page.click('[data-dpane="char"]')
    page.wait_for_timeout(500)
    bodies = text(page, "#diff-body")
    assert "A body" in bodies and "B body" in bodies, bodies[:200]
    assert BODY_VALID.decode() in bodies, bodies[:400]
    assert BODY_INVALID.decode() in bodies, bodies[:400]
    assert "(empty)" not in bodies, "A/B body panes are empty again"


def test_a_third_tap_replaces_the_oldest_selection(page):
    run_attack(page)
    for i in (1, 2, 3):
        page.click(f"#iresb tr[data-rid]:nth-child({i})")
        page.wait_for_timeout(200)
    sel = page.evaluate("() => ires.sel.slice()")
    assert len(sel) == 2, sel
    assert sel[0] is not None


def test_selection_is_capped_at_two(page):
    run_attack(page)
    for i in range(1, 6):
        page.click(f"#iresb tr[data-rid]:nth-child({i})")
        page.wait_for_timeout(150)
    assert len(page.evaluate("() => ires.sel")) == 2


def test_compare_button_is_disabled_until_two_are_selected(page):
    run_attack(page)
    assert page.is_disabled("#ires-cmp")
    page.click("#iresb tr[data-rid]:nth-child(1)")
    page.wait_for_timeout(200)
    assert page.is_disabled("#ires-cmp"), "enabled with only one row selected"
    page.click("#iresb tr[data-rid]:nth-child(2)")
    page.wait_for_timeout(200)
    assert not page.is_disabled("#ires-cmp")


def test_intruder_and_capture_cannot_be_mixed_in_a_diff(page):
    """They are different kinds of row in different id spaces; comparing them
    would silently diff two unrelated things."""
    run_attack(page)
    page.click("#iresb tr[data-rid]:nth-child(1)")
    page.wait_for_timeout(200)
    page.click("#iresb tr[data-rid]:nth-child(2)")
    page.wait_for_timeout(200)
    page.click("#ires-cmp")
    page.wait_for_timeout(1500)
    assert page.evaluate("() => diffASrc") == "intruder"
    assert page.evaluate("() => diffBSrc") == "intruder"
    # Now pull in a capture on side A via the picker; the mixed state must be
    # refused rather than diffed.
    page.evaluate("() => { diffA = 1; diffASrc = 'capture'; renderDiffPickers(); }")
    page.wait_for_timeout(300)
    page.evaluate("() => openDiff(1, 2, 'capture')")
    page.wait_for_timeout(300)
    assert page.evaluate("() => diffASrc") == "capture"


def test_open_diff_from_a_capture_resets_the_source(page):
    """After comparing two Intruder results, the ⋮ menu's Compare… on a
    captured row must not inherit the 'intruder' source and diff the wrong
    table."""
    run_attack(page)
    page.click("#iresb tr[data-rid]:nth-child(1)")
    page.wait_for_timeout(150)
    page.click("#iresb tr[data-rid]:nth-child(2)")
    page.wait_for_timeout(150)
    page.click("#ires-cmp")
    page.wait_for_timeout(1200)
    assert page.evaluate("() => diffASrc") == "intruder"
    page.evaluate("() => openDiff(1, 1)")
    page.wait_for_timeout(300)
    assert page.evaluate("() => diffASrc") == "capture"
    assert page.evaluate("() => diffBSrc") == "capture"


def test_swap_keeps_the_source_with_the_ids(page):
    run_attack(page)
    page.click("#iresb tr[data-rid]:nth-child(1)")
    page.wait_for_timeout(150)
    page.click("#iresb tr[data-rid]:nth-child(2)")
    page.wait_for_timeout(150)
    page.click("#ires-cmp")
    page.wait_for_timeout(1200)
    before = page.evaluate("() => [diffA, diffB]")
    page.click("#diff-swap")
    page.wait_for_timeout(1500)
    after = page.evaluate("() => [diffA, diffB]")
    assert after == [before[1], before[0]], (before, after)
    assert page.evaluate("() => [diffASrc, diffBSrc]") == ["intruder", "intruder"]


def test_results_without_ids_cannot_be_compared(page):
    """`store_intruder_results` is deliberately wrapped in a bare
    `except: pass` so persistence problems never lose the results — but that
    also means a schema mismatch can leave rows with no id, and no id means
    nothing to diff. The UI must say so instead of offering a Compare button
    that silently does nothing."""
    page.evaluate("""() => showRes([
      {payload: 'a', url: 'https://t/?u=a', response_code: 200, response_body: 'xxx'},
      {payload: 'b', url: 'https://t/?u=b', response_code: 200, response_body: 'yyyyy'},
    ])""")
    page.wait_for_timeout(400)
    assert "not saved" in text(page, "#ires-hint"), text(page, "#ires-hint")
    assert page.is_disabled("#ires-cmp")
    # The rows are still readable and sortable — only comparison is off.
    assert len(row_payloads(page)) == 2
    page.select_option("#ires-sort", "size-asc")
    page.wait_for_timeout(300)
    assert row_payloads(page)[0] == "a", row_payloads(page)


def test_intruder_results_survive_a_reload(page):
    """They are persisted; reloading and re-selecting the base request must
    still show them via the detail pane."""
    run_attack(page)
    page.click('.tab[data-tab="live"]')
    page.wait_for_timeout(800)
    # The Intruder pane is keyed to the selected capture, so select it first.
    page.click("#liveb tr.log-row")
    page.wait_for_timeout(800)
    pane = text(page, "#d-int")
    assert "admin" in pane, pane[:300]

# ── the attack follows the editor, not the stored capture ───────────
#
# The Intruder tab's URL is where you aim the attack. The server used to
# reload the stored capture and discard every edit in the tab, which also
# meant there was no way to introduce a §marker§ from the UI at all.

def test_editing_the_url_changes_where_the_attack_goes(page):
    """Aim the attack somewhere else entirely and the target must see it."""
    PATHS.clear()
    page.fill("#iurl", page.input_value("#iurl") + "&edited=1")
    page.wait_for_timeout(300)
    run_attack(page)
    assert PATHS, "the target was never contacted"
    assert all("edited=1" in q for q in PATHS), PATHS[:5]


def test_editing_the_url_drops_the_original_query(page):
    """Replacing the URL wholesale, not just appending — this is what a user
    does when the captured URL points somewhere they do not want to attack."""
    PATHS.clear()
    cur = page.input_value("#iurl")
    page.fill("#iurl", cur.split("&")[0].replace("password=wrong", "password=2") +
              "&only=mine")
    page.wait_for_timeout(300)
    run_attack(page)
    assert PATHS, "the target was never contacted"
    assert all("password=wrong" not in q for q in PATHS), PATHS[:5]
    assert all("only=mine" in q for q in PATHS), PATHS[:5]


def test_starting_without_a_marker_is_refused(page):
    """Without a marker every word yields the identical request — a full
    wordlist of wasted requests and a baffling result table."""
    page.fill("#iurl", "https://target.example/login?username=admin")
    page.wait_for_timeout(300)
    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.click("#istart")
    page.wait_for_timeout(1200)
    assert any("placeholder" in d for d in dialogs), dialogs
    assert page.query_selector_all("#iresb tr[data-rid]") == [], "attack ran anyway"
