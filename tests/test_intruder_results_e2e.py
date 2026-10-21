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

        # The SSRF lab shape: `stockApi` names a private address, and exactly
        # one octet answers with an admin interface while the rest refuse.
        if "stockApi=" in raw:
            url = raw.split("stockApi=", 1)[1].split("&", 1)[0]
            import re as _re
            m = _re.search(r"192\.168\.0\.(\d+):8080/admin", url)
            if m and m.group(1) == "150":
                body, code = b'<h1>Admin interface</h1>' + b"x" * 40, 200
            else:
                body, code = b"Could not connect to the stock service", 500
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

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


# Function-scoped on purpose: one test clicks "Clear captures", which deletes
# every row — with a module-scoped DB that left later tests with no capture to
# pick, so they errored during fixture setup for an unrelated reason.
@pytest.fixture()
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


def test_starting_without_a_marker_is_refused_inline(page):
    """Without a marker every word yields the identical request — a full
    wordlist of wasted requests and a baffling result table.

    The refusal is inline and disables Start, rather than a modal: the message
    has to stay visible while you fix the field it names.
    """
    page.fill("#iurl", "https://target.example/login?username=admin")
    page.wait_for_timeout(400)
    warn = text(page, "#inomar")
    assert "No marker yet" in warn, warn
    assert "{{" in warn, "the hint does not show the typeable marker form"
    assert page.is_disabled("#istart"), "Start stayed enabled with no marker"
    assert text(page, "#i-markers") == "0 markers", text(page, "#i-markers")

    # Start is disabled, so there is nothing to click — and no modal to dismiss.
    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    assert page.get_attribute("#istart", "disabled") is not None
    assert dialogs == []
    assert page.query_selector_all("#iresb tr[data-rid]") == [], "attack ran anyway"


def test_one_tap_wraps_the_selected_value_as_a_marker(page):
    """The lab's exact shape: `192.168.0.1` with payloads 1-255. Select the
    octet, tap the marker button — no typing, no modal."""
    page.fill("#iurl", "https://target.example/product?productId=1")
    page.fill("#ibod", "stockApi=http://192.168.0.1:8080/admin")
    page.wait_for_timeout(500)
    assert page.is_disabled("#istart")

    page.evaluate("""() => {
      const el = document.getElementById('ibod');
      const i = el.value.indexOf('192.168.0.1') + '192.168.0.'.length;
      el.focus(); el.setSelectionRange(i, i + 1);
    }""")
    page.click('[data-mark="ibod"]')
    page.wait_for_timeout(400)

    assert page.input_value("#ibod") == "stockApi=http://192.168.0.{{i}}:8080/admin"
    assert text(page, "#i-markers") == "1 marker (i)", text(page, "#i-markers")
    assert not page.is_visible("#inomar"), "the warning did not clear"
    assert not page.is_disabled("#istart"), "Start stayed disabled after marking"

    page.fill("#ipaste", "1-255")
    page.wait_for_timeout(400)
    assert page.evaluate("() => iState.words.length") == 255

    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.click("#istart")
    page.wait_for_timeout(800)
    assert dialogs == [], dialogs
    assert "Attack #" in text(page, "#ijob"), text(page, "#ijob")


def test_marker_button_with_a_caret_inserts_a_marker(page):
    """With no selection, the button inserts a marker at the caret."""
    page.fill("#ibod", "stockApi=http://192.168.0.:8080/admin")
    page.wait_for_timeout(300)
    page.evaluate("""() => {
      const el = document.getElementById('ibod');
      const i = el.value.indexOf('0.:8080') + 2;
      el.focus(); el.setSelectionRange(i, i);
    }""")
    page.click('[data-mark="ibod"]')
    page.wait_for_timeout(300)
    assert "{{i}}" in page.input_value("#ibod")
    assert not page.is_disabled("#istart")


# ── pitchfork rows follow edits to the request ──────────────────────
#
# Rows are derived from the markers in the request. renderPitchRows() used to
# run only on a mode switch, so the empty state promised "add some ... and they
# appear here" and then nothing appeared when you did — you had to toggle the
# mode off and back on.

def test_pitchfork_rows_appear_when_markers_are_typed(page):
    page.fill("#iurl", "https://target.example/login")
    page.wait_for_timeout(250)
    page.click("#i-mode-pitch")
    page.wait_for_timeout(400)
    assert "No §placeholder§" in text(page, "#pf-lists"), text(page, "#pf-lists")

    page.fill("#iurl", "https://target.example/login?u=§user§&p=§pass§")
    page.wait_for_timeout(900)   # debounce is 350ms
    rows = page.query_selector_all("#pf-lists .pf-row")
    assert len(rows) == 2, f"rows did not appear after typing markers: {len(rows)}"


def test_pitchfork_rows_disappear_when_the_marker_is_removed(page):
    page.fill("#iurl", "https://target.example/login?u=§user§&p=§pass§")
    page.wait_for_timeout(250)
    page.click("#i-mode-pitch")
    page.wait_for_timeout(600)
    assert len(page.query_selector_all("#pf-lists .pf-row")) == 2

    page.fill("#iurl", "https://target.example/login?u=§user§")
    page.wait_for_timeout(900)
    rows = page.query_selector_all("#pf-lists .pf-row")
    assert len(rows) == 1, len(rows)
    assert "§user§" in page.inner_text("#pf-lists")


def test_editing_the_request_does_not_close_an_open_paste_box(page):
    """Re-rendering on every request edit would close the paste box and drop
    a half-typed list. Only a change to the *set* of marker names may
    re-render.

    The edit deliberately keeps the same markers (adds an unrelated param), so
    a re-render here is pure loss. Typing into the paste box itself cannot
    trigger this listener — it only watches the request fields.
    """
    page.fill("#iurl", "https://target.example/login?u=§user§&p=§pass§")
    page.wait_for_timeout(250)
    page.click("#i-mode-pitch")
    page.wait_for_timeout(600)
    page.click('[data-pfpaste="user"]')
    page.wait_for_timeout(300)
    page.fill('[data-pftextarea="user"]', "typed words")

    # Edit the request without changing which markers exist.
    page.fill("#iurl", "https://target.example/login?u=§user§&p=§pass§&extra=1")
    page.wait_for_timeout(900)   # longer than the debounce

    assert page.is_visible('[data-pfpbox="user"]'), "an unrelated edit closed the box"
    assert page.input_value('[data-pftextarea="user"]') == "typed words"


# ── the results viewer: navigation and readable width ───────────────

def test_view_modal_steps_through_results(page):
    run_attack(page)
    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    meta = text(page, "#ires-modal-meta")
    assert f"1 / {len(USERNAMES)}" in meta, meta
    assert "admin" in meta, meta

    page.click("#ires-next")
    page.wait_for_timeout(300)
    meta = text(page, "#ires-modal-meta")
    assert f"2 / {len(USERNAMES)}" in meta, meta
    assert "bob" in meta, meta
    assert "username=bob" in page.input_value("#ires-modal-req")


def test_view_modal_prev_disabled_on_first_next_on_last(page):
    run_attack(page)
    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    assert page.is_disabled("#ires-prev"), "Prev enabled on the first result"
    assert not page.is_disabled("#ires-next")
    for _ in range(len(USERNAMES) - 1):
        page.click("#ires-next")
        page.wait_for_timeout(120)
    assert page.is_disabled("#ires-next"), "Next enabled on the last result"
    assert not page.is_disabled("#ires-prev")


def test_view_modal_navigation_follows_the_filter(page):
    """Prev/Next must walk the rows on SCREEN, not the full result set.

    Injected with a hidden row *between* two visible ones, so using the
    unfiltered list for navigation would step into a row the filter excluded —
    where the position indicator has nothing to show and both buttons lock up.
    """
    page.evaluate("""() => showRes([
      {id: 9001, payload: 'first', url: 'https://t/?u=first', response_code: 200,
       response_body: 'aaa'},
      {id: 9002, payload: 'hidden', url: 'https://t/?u=hidden', response_code: 302,
       response_body: 'bbbb'},
      {id: 9003, payload: 'third', url: 'https://t/?u=third', response_code: 200,
       response_body: 'ccccc'},
    ])""")
    page.wait_for_timeout(300)
    page.select_option("#ires-status", "2")
    page.wait_for_timeout(400)
    assert row_payloads(page) == ["first", "third"], row_payloads(page)

    page.click('#iresb [data-rview]')
    page.wait_for_timeout(400)
    assert "1 / 2" in text(page, "#ires-modal-meta"), text(page, "#ires-modal-meta")

    page.click("#ires-next")
    page.wait_for_timeout(300)
    meta = text(page, "#ires-modal-meta")
    assert "2 / 2" in meta, meta
    assert "third" in meta, meta
    assert page.is_disabled("#ires-next"), "stepped past the filtered set"


def test_view_modal_response_takes_the_full_phone_width(page):
    """Two side-by-side panes at 412px leave ~180px each, which is unreadable
    for an HTML body."""
    run_attack(page)
    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    box = page.eval_on_selector("#ires-modal-res", """el => {
        const r = el.getBoundingClientRect();
        return {w: r.width, h: r.height, vw: window.innerWidth};
    }""")
    assert box["w"] > box["vw"] * 0.75, box
    assert box["h"] > 150, box


def test_view_modal_arrow_keys_step_and_escape_closes(page):
    run_attack(page)
    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    page.keyboard.press("ArrowRight")
    page.wait_for_timeout(300)
    assert "2 /" in text(page, "#ires-modal-meta")
    page.keyboard.press("Escape")
    page.wait_for_timeout(300)
    assert not page.is_visible("#ires-modal.open")


def test_identical_urls_are_called_out_as_a_failed_run(page):
    """101 identical rows look like a finished attack. When every request
    carried the same URL, the payload was never substituted — say so."""
    page.evaluate("""() => showRes([
      {id: 9101, payload: 'a', url: 'https://t/login', response_code: 200, response_body: 'x'},
      {id: 9102, payload: 'b', url: 'https://t/login', response_code: 200, response_body: 'x'},
      {id: 9103, payload: 'c', url: 'https://t/login', response_code: 200, response_body: 'x'},
    ])""")
    page.wait_for_timeout(300)
    hint = text(page, "#ires-hint")
    # The check compares the whole request now, so the wording is "identical"
    # rather than "same URL" — a body-only marker makes every URL identical
    # legitimately.
    assert "were identical" in hint, hint
    assert "no payload was substituted" in hint, hint


def test_substituted_urls_do_not_trigger_the_warning(page):
    """The warning must not cry wolf on a healthy run."""
    run_attack(page)
    hint = text(page, "#ires-hint")
    assert "were identical" not in hint, hint


# ── regressions from the pre-release audit ──────────────────────────

def test_marker_name_with_a_quote_cannot_inject_an_attribute(page):
    """esc() escaped & < > but not quotes, and marker names are interpolated
    into double-quoted attributes in the Pitchfork rows. A captured header
    like  X-A: §" onmouseover="alert(1)§  broke out and ran script in a
    dashboard that holds captured credentials."""
    page.fill("#iurl", 'https://t/?a=§" onmouseover="alert(1)§&b=1')
    page.wait_for_timeout(250)
    page.click("#i-mode-pitch")
    page.wait_for_timeout(700)
    injected = page.eval_on_selector(
        "#pf-lists", "el => el.querySelectorAll('[onmouseover]').length")
    assert injected == 0, "a marker name injected an event-handler attribute"
    # The name is still displayed, just inert.
    assert "onmouseover" in page.inner_text("#pf-lists")


def test_start_button_recovers_after_a_server_refusal(page):
    """A refused start must put the button back.

    The handler disabled it, returned on `data.error`, and left it dead until a
    page reload — no poll existed to restore it. A missing marker now disables
    Start before the click, so this exercises a refusal the server returns:
    a pitchfork over the 10,000-combination cap.
    """
    page.fill("#iurl", "https://target.example/login?u=§a§&p=§b§")
    page.wait_for_timeout(300)
    page.click("#i-mode-pitch")
    page.wait_for_timeout(600)
    # 101 x 101 = 10201 combinations, just over the cap.
    page.evaluate("""() => {
      iState.pitch = {
        a: { list: "", label: "pasted", words: Array.from({length: 101}, (_, i) => "u" + i) },
        b: { list: "", label: "pasted", words: Array.from({length: 101}, (_, i) => "p" + i) },
      };
      updateIntruderTotal();
    }""")
    page.wait_for_timeout(300)
    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.click("#istart")
    page.wait_for_timeout(1500)
    assert dialogs and "10000" in dialogs[0], dialogs
    assert not page.is_disabled("#istart"), "Start stayed disabled after the refusal"
    assert "Start attack" in text(page, "#istart"), text(page, "#istart")


def test_identical_urls_are_fine_when_the_marker_is_in_the_body(page):
    """A form POST with the marker in the body has one URL for every request.
    The old check compared URLs only and wrongly declared the wordlist ignored
    — and hid the outlier summary behind that false warning."""
    # Three rows share a size and one differs, so there is a real majority —
    # with two singleton sizes there is no "most common" at all.
    page.evaluate("""() => showRes([
      {id: 9201, payload: 'admin', method: 'POST', url: 'https://t/login',
       body: 'username=admin', response_code: 302, response_body: 'a'},
      {id: 9202, payload: 'bob', method: 'POST', url: 'https://t/login',
       body: 'username=bob', response_code: 200, response_body: 'bbbb'},
      {id: 9203, payload: 'eve', method: 'POST', url: 'https://t/login',
       body: 'username=eve', response_code: 200, response_body: 'bbbb'},
      {id: 9204, payload: 'trent', method: 'POST', url: 'https://t/login',
       body: 'username=trent', response_code: 200, response_body: 'bbbb'},
    ])""")
    page.wait_for_timeout(400)
    hint = text(page, "#ires-hint")
    assert "wordlist was ignored" not in hint, hint
    page.check("#ires-outlier")
    page.wait_for_timeout(400)
    assert row_payloads(page) == ["admin"], row_payloads(page)


def test_json_payload_with_commas_survives_pasting(page):
    """A comma is part of a JSON payload, not a separator."""
    page.fill("#ipaste", '{"user":"admin","pass":"x"}')
    page.wait_for_timeout(400)
    assert page.evaluate("() => iState.words") == ['{"user":"admin","pass":"x"}']


def test_clearing_captures_also_clears_the_results_table(page):
    """Clear deletes every intruder result, but the table kept rendering rows
    whose ids no longer existed, and Compare then 404'd."""
    run_attack(page)
    assert page.query_selector_all("#iresb tr[data-rid]")
    page.on("dialog", lambda d: d.accept())
    page.click("#clear-btn")
    page.wait_for_timeout(1200)
    assert page.query_selector_all("#iresb tr[data-rid]") == []
    assert not page.is_visible("#ires"), "results card still visible"


def test_view_works_when_a_result_was_not_persisted(page):
    """Rows that failed to persist have no id; View used to do nothing at all."""
    page.evaluate("""() => showRes([
      {payload: 'loose', url: 'https://t/?u=loose', response_code: 200,
       response_body: 'VISIBLE-BODY'},
    ])""")
    page.wait_for_timeout(400)
    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    assert page.is_visible("#ires-modal.open"), "View did nothing for an id-less row"
    assert "VISIBLE-BODY" in page.input_value("#ires-modal-res")


def test_outlier_ties_name_every_common_size(page):
    """With sizes 10,10,20,20,30 the old code called 10 "the most common" and
    flagged the equally-common 20s as anomalies."""
    page.evaluate("""() => showRes([
      {id: 9301, payload: 'a', url: 'https://t/?u=a', response_code: 200,
       response_body: 'x'.repeat(10)},
      {id: 9302, payload: 'b', url: 'https://t/?u=b', response_code: 200,
       response_body: 'x'.repeat(10)},
      {id: 9303, payload: 'c', url: 'https://t/?u=c', response_code: 200,
       response_body: 'x'.repeat(20)},
      {id: 9304, payload: 'd', url: 'https://t/?u=d', response_code: 200,
       response_body: 'x'.repeat(20)},
      {id: 9305, payload: 'e', url: 'https://t/?u=e', response_code: 200,
       response_body: 'x'.repeat(30)},
    ])""")
    page.wait_for_timeout(400)
    page.check("#ires-outlier")
    page.wait_for_timeout(400)
    assert row_payloads(page) == ["e"], row_payloads(page)
    hint = text(page, "#ires-hint")
    assert "equally common" in hint and "10" in hint and "20" in hint, hint


def test_clearing_the_last_wordlist_clears_the_product_line(page):
    page.fill("#iurl", "https://t/?u=§user§")
    page.wait_for_timeout(250)
    page.click("#i-mode-pitch")
    page.wait_for_timeout(600)
    page.select_option('[data-pflist="user"]', "usernames")
    page.wait_for_timeout(600)
    assert text(page, "#pf-hint").strip(), "product line did not appear"
    page.select_option('[data-pflist="user"]', "")
    page.wait_for_timeout(400)
    assert text(page, "#pf-hint").strip() == "", text(page, "#pf-hint")


# ── durable attacks: leave the page, come back ──────────────────────

def test_double_brace_markers_work_from_the_editor(page):
    """`§` is untypeable on a phone keyboard, so {{name}} is an alias. Typing
    it must create pitchfork rows and run a real attack."""
    page.fill("#iurl", "https://target.example/login?u={{user}}&p={{pass}}")
    page.wait_for_timeout(250)
    page.click("#i-mode-pitch")
    page.wait_for_timeout(800)
    rows = page.query_selector_all("#pf-lists .pf-row")
    assert len(rows) == 2, f"{{{{...}}}} markers produced {len(rows)} rows"
    labels = page.eval_on_selector_all(
        "#pf-lists .pf-row code", "els => els.map(e => e.textContent)")
    assert "§user§" in labels and "§pass§" in labels, labels


def test_attack_continues_after_leaving_and_reattaches(page):
    """Close/reload the page mid-attack: the run is server-side and its queue is
    persisted, so coming back reattaches instead of losing it."""
    page.fill("#iurl", "https://target.example/login?username=§user§")
    page.wait_for_timeout(250)
    page.fill("#ipaste", "\n".join(f"user{i}" for i in range(40)))
    page.wait_for_timeout(300)
    page.click("#istart")
    page.wait_for_timeout(400)

    # "Leave": a fresh load of the dashboard, as if the tab had been closed.
    page.reload(wait_until="networkidle")
    page.wait_for_timeout(1800)

    note = text(page, "#ijob")
    assert note.strip(), "no job info after reload — the page did not reattach"
    assert "Attack #" in note, note

    # Either still running (progress visible) or already finished; both must
    # end with the full result set.
    for _ in range(60):
        page.wait_for_timeout(500)
        if "finished" in text(page, "#ijob"):
            break
    assert "finished" in text(page, "#ijob"), text(page, "#ijob")
    page.click('.tab[data-tab="intruder"]')
    page.wait_for_timeout(600)
    assert len(page.query_selector_all("#iresb tr[data-rid]")) == 40


def test_results_survive_a_reload_without_rerunning(page):
    """The table is rebuilt from the database, not from memory — so a reload
    shows what the attack produced, and does not send anything again."""
    page.fill("#iurl", "https://target.example/login?username=§user§")
    page.wait_for_timeout(250)
    page.fill("#ipaste", "admin\nbob\neve")
    page.wait_for_timeout(300)
    page.click("#istart")
    for _ in range(40):
        page.wait_for_timeout(300)
        if "finished" in text(page, "#ijob"):
            break
    before = len(page.query_selector_all("#iresb tr[data-rid]"))
    assert before == 3, before

    page.reload(wait_until="networkidle")
    page.wait_for_timeout(2000)
    page.click('.tab[data-tab="intruder"]')
    page.wait_for_timeout(800)
    assert len(page.query_selector_all("#iresb tr[data-rid]")) == 3


# ── SSRF: scanning a private range for the one live host ────────────
#
# The PortSwigger SSRF labs ask for exactly this: a `stockApi` URL whose final
# octet is enumerated 1-255, looking for the single address that answers with
# an admin interface instead of a refusal. Burp does it with a "Numbers"
# payload; here a numeric range in the paste box does the same.

SSRF_ROWS = []


def test_octet_range_finds_the_one_live_host(page, dash):
    """A 1-255 range in the body, one octet answering 200 and the rest 500.

    Mirrors the lab: the parameter is in the POST **body**, so that is where the
    marker goes — the mistake that made the earlier run send identical requests.
    """
    SSRF_ROWS.clear()
    import json as _json

    page.fill("#iurl", dash["target"] + "/product?productId=1")
    page.wait_for_timeout(200)
    page.fill("#ibod", 'stockApi=http://192.168.0.{{i}}:8080/admin')
    page.wait_for_timeout(300)

    # The range expands to 1..255 — no 255-line paste required.
    page.fill("#ipaste", "1-255")
    page.wait_for_timeout(400)
    words = page.evaluate("() => iState.words")
    assert len(words) == 255, len(words)
    assert words[0] == "1" and words[-1] == "255"
    assert "255 words" in text(page, "#ifinfo"), text(page, "#ifinfo")

    page.click("#istart")
    for _ in range(120):
        page.wait_for_timeout(300)
        if "finished" in text(page, "#ijob"):
            break
    assert "finished" in text(page, "#ijob"), text(page, "#ijob")

    page.check("#ires-outlier")
    page.wait_for_timeout(500)
    hits = row_payloads(page)
    assert len(hits) == 1, f"expected exactly one outlier, got {hits}"
    assert hits[0] == "150", hits

    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    req = page.input_value("#ires-modal-req")
    assert "192.168.0.150:8080/admin" in req, req
    assert "192.168.0.{{i}}" not in req, "the marker was not substituted"


def test_numeric_range_forms(page):
    """Burp's Numbers payload, expressed as a line in the paste box."""
    def parse(text):
        return page.evaluate("(t) => parseWordlistText(t)", text)

    assert parse("1-10") == [str(i) for i in range(1, 11)]
    assert parse("1-20:5") == ["1", "6", "11", "16"]
    assert parse("10-1") == [str(i) for i in range(10, 0, -1)]
    assert parse("001-003") == ["001", "002", "003"]
    assert parse("8080-8085")[0] == "8080"
    # Only a whole-line range expands; a payload containing a hyphen is kept.
    assert parse("1-2-3") == ["1-2-3"]
    assert parse("a-b") == ["a-b"]
    assert parse("-5") == ["-5"]
    # Mixed with normal words, and combined with comments.
    assert parse("# scan\n1-3\nadmin") == ["1", "2", "3", "admin"]


def test_range_is_capped_at_the_word_limit(page):
    got = page.evaluate("() => parseWordlistDetailed('1-5000')")
    assert len(got["words"]) == 1000
    assert got["dropped"] == 4000, got["dropped"]
    assert got["words"][0] == "1" and got["words"][-1] == "1000"


def test_winner_can_be_sent_to_the_repeater(page):
    """After finding the outlier, the next step is to edit that exact request —
    the Repeater is already a tab, so the result just hands it over."""
    page.evaluate("""() => showRes([
      {id: 9401, payload: '150', method: 'POST', url: 'http://192.168.0.150:8080/admin',
       headers: '{"Host": "192.168.0.150:8080"}', body: 'stockApi=http://192.168.0.150:8080/admin',
       response_code: 200, response_body: '<h1>Admin</h1>'},
    ])""")
    page.wait_for_timeout(400)
    page.click("#iresb [data-rview]")
    page.wait_for_timeout(400)
    page.click("#ires-rep")
    page.wait_for_timeout(500)

    assert page.is_visible("#rep-modal.open"), "the Repeater did not open"
    assert page.input_value("#m-url") == "http://192.168.0.150:8080/admin"
    assert "192.168.0.150:8080/admin" in page.input_value("#m-bod")
    assert page.input_value("#m-met").upper() == "POST"
    assert "Intruder result" in text(page, "#rep-origin"), text(page, "#rep-origin")


def test_repeater_restores_crlf_for_multipart_bodies(page):
    """A textarea turns CRLF into LF, but multipart parts are delimited by
    CRLF. Captured uploads therefore replayed with broken framing, and the
    server answered "Missing parameter 'csrf'" because the last part was never
    terminated."""
    html = page.evaluate("""() => crlfBody(
        '------b\\nContent-Disposition: form-data; name="csrf"\\n\\nTOKEN\\n------b--\\n',
        'multipart/form-data; boundary=----b')""")
    assert "\r\n" in html, repr(html)
    assert "\nContent-Disposition" not in html.replace("\r\n", ""), repr(html)
    # A plain body is left alone — no stray CRs added.
    plain = page.evaluate("() => crlfBody('a\\nb', 'text/plain')")
    assert plain == "a\nb", repr(plain)
    # And an upload body with no content-type is still detected by its framing.
    detected = page.evaluate("""() => crlfBody('--b\\nX: y\\n\\nz\\n--b--\\n', '')""")
    assert "\r\n" in detected, repr(detected)


# ── browser-TLS replay in the Repeater ──────────────────────────────
#
# Cloudflare binds a clearance cookie to the TLS handshake, so the Repeater
# needs to replay with a real browser fingerprint. The picker must exist, carry
# the choice through to the request, and explain a challenge rather than
# showing a bare 403.

def test_repeater_offers_tls_fingerprints(page):
    page.click('.tab[data-tab="live"]')
    page.wait_for_timeout(400)
    page.click("#liveb tr.log-row")
    page.wait_for_timeout(400)
    page.click("#d-open-rep")
    page.wait_for_timeout(800)
    assert page.is_visible("#rep-modal.open")
    opts = page.eval_on_selector_all("#m-tls option", "els => els.map(e => e.value)")
    assert opts[0] == "", "the first option must be the plain (no TLS) mode"
    meta = page.evaluate("async () => (await api('/api/meta')).data")
    if meta.get("tls_available"):
        assert "chrome" in opts, opts
        assert "firefox" in opts or any(o.startswith("firefox") for o in opts), opts
        assert page.is_visible("#m-tls"), "the picker is hidden"


def test_tls_choice_is_sent_with_the_request(page):
    page.click('.tab[data-tab="live"]')
    page.wait_for_timeout(400)
    page.click("#liveb tr.log-row")
    page.wait_for_timeout(400)
    page.click("#d-open-rep")
    page.wait_for_timeout(800)
    meta = page.evaluate("async () => (await api('/api/meta')).data")
    if not meta.get("tls_available"):
        return
    # Intercept the API call so nothing goes to the network, and prove the
    # selection travelled with the payload.
    page.evaluate("""() => {
      window.__sent = null;
      const orig = window.api;
      window.api = async (url, opts) => {
        if (url === '/api/repeater/send') {
          window.__sent = JSON.parse(opts.body);
          return { ok: true, data: { status_code: 200, headers: {}, body: 'ok',
                                     challenge: false, tls_profile: JSON.parse(opts.body).impersonate } };
        }
        return orig(url, opts);
      };
    }""")
    page.select_option("#m-tls", "chrome")
    page.wait_for_timeout(200)
    page.click("#m-send")
    page.wait_for_timeout(600)
    assert page.evaluate("() => window.__sent.impersonate") == "chrome"
    assert "TLS chrome" in text(page, "#m-status"), text(page, "#m-status")


def test_challenge_response_is_explained_not_just_a_status(page):
    """A 403 from a bot wall must say what it is, so the user does not think
    the replay failed for a normal reason."""
    page.evaluate("""() => {
      const orig = window.api;
      window.api = async (url, opts) => {
        if (url === '/api/repeater/send') {
          return { ok: true, data: {
            status_code: 403, headers: {"cf-mitigated": "challenge"},
            body: "<title>Just a moment...</title>", challenge: true,
            tls_profile: "chrome" } };
        }
        return orig(url, opts);
      };
    }""")
    page.click('.tab[data-tab="live"]')
    page.wait_for_timeout(300)
    page.click("#liveb tr.log-row")
    page.wait_for_timeout(300)
    page.click("#d-open-rep")
    page.wait_for_timeout(700)
    page.click("#m-send")
    page.wait_for_timeout(600)
    out = text(page, "#m-out")
    assert "Bot-management challenge" in out, out[:200]
    assert "Rewrite tab" in out, "no fallback suggested: " + out[:300]
