"""Regression tests: the live poll must not fight the user.

Two reported bugs, one root cause — the 2-second poll re-rendered the table and
the detail pane unconditionally, and assigned the note textarea's ``.value`` on
every tick:

* Selecting a value in the table (to copy it by hand) was impossible: the act
  of dragging fired the row's click handler, which repainted the row and
  cleared the selection. Polls cleared it too.
* Typing in the note box lost text — assign ``.value`` mid-edit and whatever
  was typed is gone, which presented as "the last word disappears when I press
  space".

These tests hold a selection and type across a real poll interval, so they fail
against the old behaviour rather than just asserting the new code exists.
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
PORT = 5291
# The poll interval is 2000ms; every wait below is comfortably longer.
POLL = 3200

ROWS = [
    ("GET", "https://target.example/api/users?role=user", 200,
     "application/json", json.dumps({"role": "user", "token": "abc123"}), ""),
    ("POST", "https://target.example/login", 302, "text/html",
     "<html>redirecting</html>", "user=wiener&pass=peter"),
]


@pytest.fixture()
def dash():
    work = tempfile.mkdtemp(prefix="mp-sel-")
    db = os.path.join(work, "proxy.db")
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL,
        headers TEXT, body TEXT, response_code INTEGER,
        response_headers TEXT, response_body TEXT, content_type TEXT,
        ttfb_ms REAL, total_ms REAL, request_body_len INTEGER,
        response_body_len INTEGER, highlight TEXT, note TEXT)""")
    for i, (m, u, code, ct, resp, req) in enumerate(ROWS):
        conn.execute(
            "INSERT INTO requests (timestamp, method, url, headers, body,"
            " response_code, response_headers, response_body, content_type,"
            " ttfb_ms, total_ms, request_body_len, response_body_len,"
            " highlight, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"2026-10-16T10:0{i}:00+00:00", m, u, "{}", req, code, "{}",
             resp, ct, 5.0, 12.0, len(req), len(resp), None, None))
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
    yield {"base": base, "db": db}
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
        pg = b.new_context(viewport={"width": 1440, "height": 900}).new_page()
        errors: list[str] = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(dash["base"] + "/", wait_until="networkidle")
        pg.wait_for_timeout(1500)
        yield pg
        assert not errors, f"uncaught JS errors: {errors}"
        b.close()


def select_in(page, selector):
    """Programmatically select a node's text (as a drag-select would)."""
    return page.evaluate("""(sel) => {
      const el = document.querySelector(sel);
      const range = document.createRange();
      range.selectNodeContents(el);
      const s = window.getSelection();
      s.removeAllRanges();
      s.addRange(range);
      return String(s);
    }""", selector)


def selected_text(page):
    return page.evaluate("window.getSelection().toString()")


# ── Copy-by-hand in the table ───────────────────────────────────────

def test_table_selection_survives_a_poll(page):
    """Holding a selection in the table across a poll must keep it."""
    original = select_in(page, "#liveb tr td:nth-child(6)")
    assert original, "test did not actually select anything"
    page.wait_for_timeout(POLL)
    assert selected_text(page) == original, \
        "the poll cleared the user's text selection in the table"


def test_path_selection_survives_click_that_fired_with_it(page):
    """Dragging inside a row also fires the row click handler.

    That repaint was what made selecting a value impossible: the selection was
    destroyed the instant the click landed.
    """
    original = select_in(page, "#liveb tr td:nth-child(6)")
    # Simulate the click that a mouse drag ends with.
    page.evaluate("""() => {
      const tr = document.querySelector('#liveb tr');
      tr.dispatchEvent(new MouseEvent('click', {bubbles: true}));
    }""")
    page.wait_for_timeout(300)
    assert selected_text(page) == original, \
        "clicking a row cleared the selection the user was making"


def test_row_click_still_moves_the_selection_highlight(page):
    """The fix must not break selecting a row."""
    page.click("#liveb tr[data-id='2']")
    page.wait_for_timeout(600)
    cls = page.eval_on_selector("#liveb tr[data-id='2']", "e=>e.className")
    assert "selected" in cls, cls
    meta = page.inner_text("#req-meta")
    assert "#2" in meta, meta


# ── Copy-by-hand in the detail pane ─────────────────────────────────

def test_response_body_selection_survives_a_poll(page):
    page.click("#liveb tr[data-id='1']")
    page.wait_for_timeout(600)
    page.click('.dtab[data-pane="p-resp"]')
    page.wait_for_timeout(400)
    original = select_in(page, "#d-resp-b")
    assert original, "nothing selectable in the response pane"
    page.wait_for_timeout(POLL)
    assert selected_text(page) == original, \
        "the poll cleared the selection in the response body"


def test_request_line_selection_survives_a_poll(page):
    page.click("#liveb tr[data-id='2']")
    page.wait_for_timeout(600)
    page.click('.dtab[data-pane="p-req"]')
    page.wait_for_timeout(400)
    original = select_in(page, "#d-req-line")
    page.wait_for_timeout(POLL)
    assert selected_text(page) == original, \
        "the poll cleared the selection in the request line"


# ── The note field ──────────────────────────────────────────────────

def test_note_keeps_text_typed_across_a_poll(page):
    """The exact reported symptom: type, wait a poll, keep typing."""
    page.click("#liveb tr[data-id='1']")
    page.wait_for_timeout(600)
    page.click('.dtab[data-pane="p-note"]')
    page.wait_for_timeout(300)
    page.click("#d-note")
    page.type("#d-note", "hello")
    page.wait_for_timeout(POLL)      # a poll lands mid-edit here
    page.type("#d-note", " world")
    page.wait_for_timeout(400)
    assert page.input_value("#d-note") == "hello world", \
        f"typing was lost across a poll: {page.input_value('#d-note')!r}"


def test_note_keeps_space_immediately_after_a_word(page):
    """The narrow form of the report: a space right after a word."""
    page.click("#liveb tr[data-id='1']")
    page.wait_for_timeout(600)
    page.click('.dtab[data-pane="p-note"]')
    page.wait_for_timeout(300)
    page.click("#d-note")
    page.type("#d-note", "token")
    page.wait_for_timeout(2200)      # land a poll between the word and space
    page.keyboard.press(" ")
    page.wait_for_timeout(400)
    page.type("#d-note", "leak")
    page.wait_for_timeout(400)
    assert page.input_value("#d-note") == "token leak", \
        f"the word before the space was lost: {page.input_value('#d-note')!r}"


def test_note_survives_save_and_reload(page):
    page.click("#liveb tr[data-id='1']")
    page.wait_for_timeout(600)
    page.click('.dtab[data-pane="p-note"]')
    page.wait_for_timeout(300)
    page.fill("#d-note", "IDOR candidate")
    page.click("#d-note-save")
    page.wait_for_timeout(POLL)      # a poll must not revert it
    assert page.input_value("#d-note") == "IDOR candidate"
    assert "Saved" in page.inner_text("#d-note-state")
    page.reload(wait_until="networkidle")
    page.wait_for_timeout(1500)
    page.click("#liveb tr[data-id='1']")
    page.wait_for_timeout(600)
    page.click('.dtab[data-pane="p-note"]')
    page.wait_for_timeout(400)
    assert page.input_value("#d-note") == "IDOR candidate"


def test_switching_rows_loads_the_other_note(page):
    """Unsaved edits must not leak onto a different capture."""
    page.click("#liveb tr[data-id='1']")
    page.wait_for_timeout(600)
    page.click('.dtab[data-pane="p-note"]')
    page.wait_for_timeout(300)
    page.fill("#d-note", "draft for row 1")
    page.wait_for_timeout(300)
    page.click("#liveb tr[data-id='2']")
    page.wait_for_timeout(700)
    assert page.input_value("#d-note") == "", \
        "row 2 showed row 1's unsaved draft"
    page.click("#liveb tr[data-id='1']")
    page.wait_for_timeout(700)
    page.click('.dtab[data-pane="p-note"]')
    page.wait_for_timeout(300)
    assert page.input_value("#d-note") == "draft for row 1" or \
        page.input_value("#d-note") == "", "unexpected cross-row note"


# ── The poll must still do its job ──────────────────────────────────

def test_new_captures_still_appear(page, dash):
    """Guarding the repaint must not stop the table updating."""
    before = page.locator("#liveb tr").count()
    conn = sqlite3.connect(dash["db"])
    conn.execute("INSERT INTO requests (timestamp, method, url, headers, body,"
                 " response_code, response_headers, response_body, content_type,"
                 " ttfb_ms, total_ms, request_body_len, response_body_len)"
                 " VALUES ('2026-10-16T11:00:00+00:00','GET',"
                 " 'https://target.example/new', '{}','',200,'{}','{}',"
                 " 'application/json',1.0,2.0,0,2)")
    conn.commit()
    conn.close()
    page.wait_for_timeout(POLL + 800)
    assert page.locator("#liveb tr").count() > before, \
        "a new capture did not appear — the render guard is too aggressive"
    assert "target.example/new" in page.inner_text("#liveb") or \
        "/new" in page.inner_text("#liveb")
