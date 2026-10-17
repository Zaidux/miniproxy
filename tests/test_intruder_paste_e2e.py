"""Pasting a wordlist into the Intruder, instead of uploading a file.

Wordlists live in awkward places — a notes app, a Slack thread, a Burp export,
a ``curl`` transcript. Making the user save any of that to a file first is pure
friction, so the Intruder takes a paste box: single-list mode gets one next to
the file input, and every pitchfork row gets its own.

Parsing is shared by paste and upload, deliberately. They used to disagree:
the pitchfork upload skipped ``#`` comments and the single-list upload did
not, so the same text produced different wordlists depending on which control
you happened to use.

This file also pins the behaviour the paste box depends on: a single source of
truth for the word list. There used to be two variables — a bare ``words``
written only by the file input, and ``iState.words`` written only by the
bundled cards — with the request counter reading one and "Start attack" reading
the other. The visible symptom was a bundled list counting up correctly and
then refusing to start, and an uploaded file showing no count at all.
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
PORT = 5313

ROWS = [
    ("GET", "https://target.example/login?u=1&p=1", 200,
     "application/json", json.dumps({"ok": False}), ""),
]


@pytest.fixture()
def dash():
    work = tempfile.mkdtemp(prefix="mp-paste-")
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
            (f"2026-10-17T10:0{i}:00+00:00", m, u, "{}", req, code, "{}",
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
        # Open the Intruder tab with the captured request already selected.
        pg.click('.tab[data-tab="intruder"]')
        pg.wait_for_timeout(600)
        pg.click("#isel-btn")
        pg.wait_for_timeout(1000)
        pg.click("#pk-rows tr.log-row")
        pg.click("#pick-use")
        pg.wait_for_timeout(600)
        yield pg
        assert not errors, f"uncaught JS errors: {errors}"
        ctx.close()
        b.close()


def set_words(page, target="iState.words"):
    """The words the Intruder would actually send, read back from its state."""
    return page.evaluate(f"() => {target}")


def parse(page, text):
    """Run text through the shared parser the paste and upload paths both use."""
    return page.evaluate(
        "(t) => parseWordlistText(t)", text)


# ── the single source of truth ──────────────────────────────────────

def test_bundled_card_actually_reaches_the_attack(page):
    """A bundled list must be startable, not just countable.

    Regression: the counter read `iState.words` while "Start attack" read a
    separate bare `words`, so this used to alert "Pick a bundled list or
    upload a wordlist" immediately after the card showed the right count.
    """
    page.click('[data-wl="ids"]')
    page.wait_for_timeout(400)
    assert set_words(page), "clicking a bundled card did not populate the word list"
    assert page.inner_text("#i-total").strip(), "bundled card did not update the counter"

    # Clicking Start must not raise the "pick a wordlist" alert.
    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.click("#istart")
    page.wait_for_timeout(1200)
    assert not [d for d in dialogs if "wordlist" in d.lower()], (
        f"Start attack rejected the bundled list: {dialogs}"
    )


def test_upload_and_bundled_and_paste_share_one_list(page):
    """Whichever control is used last is what the attack sends."""
    page.fill("#ipaste", "alpha\nbravo\ncharlie")
    page.wait_for_timeout(300)
    assert set_words(page) == ["alpha", "bravo", "charlie"]

    page.click('[data-wl="ports"]')
    page.wait_for_timeout(400)
    after_card = set_words(page)
    assert after_card and all(w.isdigit() for w in after_card), (
        f"bundled card did not replace the pasted list: {after_card}"
    )


# ── parsing ─────────────────────────────────────────────────────────

def test_parse_skips_blanks_and_comments(page):
    """A wordlist copied out of a blog post starts with `#`. Sending those as
    payloads is a wasted request at best, so they are dropped — the rule
    `wordlists.load_from_file` documents, which the old pitchfork upload
    already followed and the single-list upload did not."""
    got = parse(page, "# header comment\nalpha\n\n  bravo  \n#skip\n\ncharlie\n")
    assert got == ["alpha", "bravo", "charlie"], got


def test_parse_accepts_comma_separated_paste(page):
    """Pasted lists usually arrive comma-separated, not one-per-line."""
    got = parse(page, "admin, root, guest")
    assert got == ["admin", "root", "guest"], got


def test_parse_caps_at_the_intruder_limit(page):
    """More than the limit must be truncated and reported, never silently
    dropped — otherwise the count on screen lies about the attack size."""
    got = parse(page, "\n".join(str(i) for i in range(1, 1200)))
    assert len(got) == 1000, len(got)


def test_parse_keeps_payloads_with_spaces(page):
    """Splitting on whitespace would destroy payloads like
    `admin' OR '1'='1`, so only newlines and commas separate."""
    got = parse(page, "admin' OR '1'='1\nfoo bar")
    assert got == ["admin' OR '1'='1", "foo bar"], got


# ── single-list paste ───────────────────────────────────────────────

def test_paste_in_single_mode_feeds_the_counter_and_attack(page):
    page.fill("#ipaste", "alpha\nbravo\n#comment\n\ncharlie")
    page.wait_for_timeout(300)
    assert set_words(page) == ["alpha", "bravo", "charlie"]
    # #ifinfo names the source, #i-total sizes the attack.
    assert "3 words (pasted)" in page.inner_text("#ifinfo"), page.inner_text("#ifinfo")
    assert "3 requests" in page.inner_text("#i-total"), page.inner_text("#i-total")


def test_paste_over_cap_warns_rather_than_truncating_silently(page):
    page.fill("#ipaste", "\n".join(str(i) for i in range(1, 1200)))
    page.wait_for_timeout(400)
    info = page.inner_text("#ifinfo")
    assert "1000 words" in info, info
    # And it says what it dropped rather than pretending nothing was lost.
    assert "capped from 1199" in info, info


def test_clearing_the_paste_clears_the_list(page):
    page.fill("#ipaste", "alpha\nbravo")
    page.wait_for_timeout(250)
    page.fill("#ipaste", "")
    page.wait_for_timeout(300)
    assert set_words(page) == [], set_words(page)


def test_pasted_words_survive_a_tab_switch(page):
    """Checking traffic mid-attack is the normal rhythm of using this thing.
    Coming back to the Intruder must not quietly empty the word list."""
    page.fill("#ipaste", "alpha\nbravo\ncharlie")
    page.wait_for_timeout(300)
    page.click('.tab[data-tab="live"]')
    page.wait_for_timeout(500)
    page.click('.tab[data-tab="intruder"]')
    page.wait_for_timeout(500)
    assert set_words(page) == ["alpha", "bravo", "charlie"], set_words(page)
    assert "3 requests" in page.inner_text("#i-total"), page.inner_text("#i-total")


# ── pitchfork paste ─────────────────────────────────────────────────

def go_pitchfork(page):
    page.click("#i-mode-pitch")
    page.wait_for_timeout(300)


def pitch_words(page, name):
    return page.evaluate(f"() => iState.pitch[{name!r}] && iState.pitch[{name!r}].words")


def test_pitchfork_rows_accept_a_paste_each(page):
    page.fill("#iurl", "https://target.example/login?u=§user§&p=§pass§")
    page.wait_for_timeout(400)
    go_pitchfork(page)
    page.wait_for_timeout(400)

    page.click('[data-pfpaste="user"]')
    page.fill('[data-pftextarea="user"]', "admin\nroot")
    page.click('[data-pfuse="user"]')
    page.wait_for_timeout(300)

    page.click('[data-pfpaste="pass"]')
    page.fill('[data-pftextarea="pass"]', "letmein\nwelcome")
    page.click('[data-pfuse="pass"]')
    page.wait_for_timeout(300)

    assert pitch_words(page, "user") == ["admin", "root"]
    assert pitch_words(page, "pass") == ["letmein", "welcome"]
    # 2 × 2
    assert "4" in page.inner_text("#i-total"), page.inner_text("#i-total")


def test_pitchfork_paste_and_bundled_select_do_not_conflict(page):
    """Pasting into one row must not disturb a bundled list chosen in another."""
    page.fill("#iurl", "https://target.example/login?u=§user§&p=§pass§")
    page.wait_for_timeout(400)
    go_pitchfork(page)
    page.wait_for_timeout(400)

    page.select_option('[data-pflist="user"]', "usernames")
    page.wait_for_timeout(400)
    picked = pitch_words(page, "user")
    assert picked and "admin" in picked

    page.click('[data-pfpaste="pass"]')
    page.fill('[data-pftextarea="pass"]', "letmein")
    page.click('[data-pfuse="pass"]')
    page.wait_for_timeout(300)

    assert pitch_words(page, "user") == picked, "pasting pass clobbered user"
    assert pitch_words(page, "pass") == ["letmein"]


def test_pitchfork_paste_survives_a_sibling_row_being_removed(page):
    """Adding and removing a §placeholder§ re-renders every row. A pasted list
    on an untouched row must come back intact rather than being reset by the
    re-render, and a removed row's words must not leak into a new one."""
    page.fill("#iurl", "https://target.example/?a=§alpha§&b=§bravo§")
    page.wait_for_timeout(400)
    go_pitchfork(page)
    page.wait_for_timeout(400)
    page.click('[data-pfpaste="alpha"]')
    page.fill('[data-pftextarea="alpha"]', "one\ntwo")
    page.click('[data-pfuse="alpha"]')
    page.wait_for_timeout(300)
    assert pitch_words(page, "alpha") == ["one", "two"]
    assert pitch_words(page, "bravo") in (None, []), "alpha's paste leaked into bravo"

    page.fill("#iurl", "https://target.example/?a=§alpha§")
    page.wait_for_timeout(600)
    go_pitchfork(page)
    page.wait_for_timeout(600)
    assert pitch_words(page, "alpha") == ["one", "two"], "re-render lost the pasted list"
    assert "bravo" not in page.evaluate("() => Object.keys(iState.pitch)")


def test_pitchfork_cancel_discards_the_text(page):
    page.fill("#iurl", "https://target.example/login?u=§user§&p=§pass§")
    page.wait_for_timeout(400)
    go_pitchfork(page)
    page.wait_for_timeout(400)
    page.click('[data-pfpaste="pass"]')
    page.fill('[data-pftextarea="pass"]', "letmein")
    page.click('[data-pfcancel="pass"]')
    page.wait_for_timeout(300)
    assert pitch_words(page, "pass") in (None, []), pitch_words(page, "pass")


def test_pitchfork_paste_over_cap_reports_what_will_be_sent(page):
    """The old upload handler printed the pre-cap count ("1199 words") while
    storing 1000, so the number on screen lied about the attack."""
    page.fill("#iurl", "https://target.example/login?u=§user§&p=§pass§")
    page.wait_for_timeout(400)
    go_pitchfork(page)
    page.wait_for_timeout(400)
    page.click('[data-pfpaste="pass"]')
    page.fill('[data-pftextarea="pass"]', "\n".join(str(i) for i in range(1, 1200)))
    page.click('[data-pfuse="pass"]')
    page.wait_for_timeout(400)

    assert len(pitch_words(page, "pass")) == 1000, len(pitch_words(page, "pass"))
    info = page.inner_text('[data-pfinfo="pass"]')
    assert "1000 words" in info, info
    assert "1199" in info, info


def test_picking_a_bundled_card_clears_a_pasted_list(page):
    """Two controls holding text, with one of them actually driving the attack,
    is the same shape of lie as the bug this file opened on. The inactive one
    is cleared so what is on screen is what is sent."""
    page.fill("#ipaste", "alpha\nbravo")
    page.wait_for_timeout(300)
    assert page.input_value("#ipaste")

    page.click('[data-wl="ids"]')
    page.wait_for_timeout(500)
    assert page.input_value("#ipaste") == "", (
        "the paste box still held text after a bundled list took over"
    )
    assert page.is_visible('[data-wl="ids"].active'), "bundled card is not highlighted"