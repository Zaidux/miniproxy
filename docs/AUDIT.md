# Code Audit — 2026-09-23

A full read-through of every module in `src/miniproxy/`, focused on: (1) bugs that
could crash the tool, (2) bugs that could silently break capture, and (3) what's
missing before the project is genuinely useful in the field. Fixed findings are
marked ✅ with the module where the fix landed.

---

## 1. Fixed — critical

### ✅ Capture hot path could stall or lock the DB (`addon/db.py`)
`store_request()` called `prune()` on **every captured request**. When the DB grew
past `MINIPROXY_MAX_DB_BYTES`, prune runs `VACUUM` — a seconds-long, full-database
operation — *inside the mitmproxy capture thread*. Under load that stalls every
in-flight request, and concurrent readers (TUI poll, dashboard) could hold the
write lock long enough to trip `database is locked` mid-capture.

**Fix:** `prune_if_needed()` throttles housekeeping to at most once per 60 s with
a lock, and swallows `sqlite3.Error` so a busy reader can never break capture.
Verified: 50 inserts → prune runs once.

### ✅ VACUUM crash when a reader holds the DB (`addon/db.py`)
Even outside the hot path, `prune()` and `clear()` called `PRAGMA
wal_checkpoint(TRUNCATE)` / `VACUUM` unguarded. Any concurrent reader turns that
into an unhandled `sqlite3.Error` — a crash in the proxy addon (killing capture)
or a 500 from the dashboard.

**Fix:** both operations are best-effort behind `try/except sqlite3.Error`.
Row-count bounding (the part that matters) still happens unconditionally.

### ✅ Request bodies uncapped (`addon/db.py`)
Response bodies were capped at 100 KB but request bodies were stored whole. One
multi-megabyte upload (a file POST, a GraphQL mutation blob) ballooned the DB and
accelerated the VACUUM problem above.

**Fix:** request and response bodies are capped at `MAX_BODY_BYTES` (100 KB,
tunable via `MINIPROXY_MAX_BODY_BYTES`) like responses.

### ✅ PID-reuse hazard in process management (`server.py`)
Pid files can outlive their process; the OS then recycles the PID. The pre-audit
code trusted any live PID in the file, so `stop()` could `SIGTERM` an **unrelated
process** and `status()` could report "running" against a stranger.

**Fix:** `_pid_matches()` reads `/proc/<pid>/cmdline` and requires the command
line to actually look like ours (`mitmdump`, or `miniproxy ... dashboard`)
before trusting or killing it. Non-Linux platforms keep the old behavior.

### ✅ `re.sub` interpreted wordlist payloads as group references (`intruder.py`)
A wordlist entry like `\g<0>` or `\1` is a replacement-template token, so
`re.sub(r"§[^§]+§", payload, text)` raised `re.error: invalid group reference`
mid-attack, and `\\` sequences were silently rewritten.

**Fix:** backslashes are escaped before substitution (literal backslashes now
pass through unchanged).

### ✅ CRLF injection via wordlist entries (`intruder.py`)
Intruder substitutes payloads into URLs, headers, and bodies. A payload
containing `\r\n` could break a request out of its header/URL boundaries —
a textbook request-smuggling primitive, and a real hazard when someone runs a
downloaded wordlist.

**Fix:** CR/LF control characters are stripped from payloads before
substitution. (Header *names* containing `:` are still passed through to
`requests` untouched — noted as a hardening TODO in §4.)

### ✅ Export download-filename injection (`app.py`)
`Content-Disposition` values built from capture URLs could contain quotes,
path separators, or control characters.

**Fix:** `_safe_filename()` whitelists `[A-Za-z0-9._-]` with a fallback name.

### ✅ Legacy dead template still shipped (`templates/index.html` at repo root)
The pre-0.4.0 flat-layout dashboard (with its known-broken JS, e.g.
`if(!e||e.errorreturn;`) was still in the tree even though the packaged app
serves `src/miniproxy/templates/index.html`. Removed so nobody edits the wrong
copy or ships the broken one. (Also fixed here: a transient triple-quote
imbalance introduced while adding the export endpoints — caught by py_compile.)

---

## 2. Fixed — availability & workflow gaps

### ✅ No data export (the #1 usability gap)
Captures lived and died inside `~/.miniproxy/proxy.db`. Now:

| Where | What |
|---|---|
| Web → **Export ▾** menu | **HAR 1.2** (imports into Chrome DevTools, Burp, haralyzer), **MiniProxy JSON**, **SQLite snapshot** (consistent copy via `sqlite3.Connection.backup()`, safe while the proxy writes), **selected response body** |
| Web → detail pane | **Save body…** button |
| TUI → `e` key | writes the selected response body to a timestamped file in the cwd |
| Web → **Clear all captures…** | confirm-guarded `POST /api/clear` (bulk-deletes captures + intruder results) |

HAR entries carry timings (`wait` = ttfb_ms, `receive` = total − ttfb), parsed
query strings, and a `comment` on entries whose response body was not captured
(non-API content types stream through uncaptured by design).

### ✅ Error visibility during export
All export endpoints return structured JSON errors (`{"error": ...}`) with
proper status codes instead of stack traces when the DB is missing or corrupt.

---

## 3. Design notes (not bugs)

- **`intercept` config flag is vestigial.** The v4 engine captures unconditionally;
  `set_intercept`/`get_intercept` and the `POST /api/proxy/status` toggle remain
  only for UI compatibility. Removing them entirely is safe post-0.4.x.
- **Body capping is lossy by design.** A 10 MB JSON response is stored as its
  first 100 KB. That's the right default for a security proxy (the DB would
  otherwise be a DoS target), but the UI should *say* so — see §4.
- **WAL mode means `~/.miniproxy/proxy.db-wal` exists while running.** Copy the
  `-wal`/`-shm` files too, or use the dashboard's SQLite snapshot export, if you
  must copy a live DB by hand.
- **CORS is `*`.** Fine for a localhost lab tool; dangerous if you ever bind the
  dashboard to a non-loopback interface (see §4).

---

## 4. Known limitations / next steps

Prioritized by "how much would this hurt in the field". Items 1–4 and 6
from the original audit are **resolved** (see §6); the remaining ones:

1. ~~**No test suite in the repo.**~~ ✅ Resolved — committed pytest suite
   (`tests/`, 62 tests: db layer, API endpoints, exports, token auth,
   background intruder, process manager, headless TUI) plus a GitHub
   Actions matrix CI (Linux/macOS × py3.10/3.12) and a JS syntax check.
2. ~~**Dashboard binds `0.0.0.0`.**~~ ✅ Resolved — binds `127.0.0.1` by
   default; LAN exposure now requires `--dashboard-host 0.0.0.0` and prints
   a warning. `MINIPROXY_DASHBOARD_TOKEN` / `--dashboard-token` gates every
   state-changing endpoint (401 otherwise); CORS only echoes loopback
   origins instead of `*`.
3. ~~**Filtering is client-side.**~~ ✅ Resolved — `get_logs()` accepts
   method/status-class/URL-substring filters applied in SQL; `/api/logs`,
   `/api/logs/count`, and all export endpoints honor them.
4. ~~**No truncation notice.**~~ ✅ Resolved — `request_body_len` /
   `response_body_len` record original sizes at capture time; TUI detail
   panes and the web UI both render "⚠ truncated" with the original size.
5. **Intruder header-name injection.** Payload substitution into header
   *names* is not sanitized beyond CRLF; worth a `requests`-level guard.
6. ~~**Intruder runs are synchronous.**~~ ✅ Resolved — attacks execute in a
   background daemon thread; clients start via `POST /api/intruder/start`
   (202) and poll `GET /api/intruder/status` for progress/results; a
   second start while running returns 409. The web UI polls and renders
   progress live.
7. **No packaging for Windows/macOS in CI.** ✅ Partially resolved — CI now
   runs on ubuntu + macos. Windows (no `/proc`, different signal semantics)
   remains untested.
8. **Static `templates/index.html` ships inline JS/CSS.** Fine for size;
   CI's JS parse check catches the class of quote-count bugs fixed during
   this audit. A ruff lint pass is still worth adding.
9. **Remote browser capture.** ✅ Resolved — the dashboard serves a
   PAC file (`/proxy.pac`), the CA (`/ca.crt`), and a **Connect** wizard
   (`/connect`) that walks through proxy settings, CA install, and device
   pairing (QR) for any OS — including browsers connecting to a proxy
   running on a VPS. `curl -x` and other explicit-proxy integrations keep
   working unchanged. See `docs/connect.md`.

---

## 5. Open-source readiness

| Item | Status |
|---|---|
| License | ✅ MIT (`LICENSE`, `pyproject.toml`, README) |
| PyPI + npm distribution | ✅ `riciplay-miniproxy` on both, npm postinstall bootstrap |
| Docs | ✅ `docs/` — setup, CLI/TUI, web, integrations, troubleshooting |
| README quality | ✅ quick start, terminal-capture guide, structure map |
| Test suite | ✅ `tests/` — 62 pytest tests across db, API, intruder, server, TUI |
| CI | ✅ GitHub Actions — Linux/macOS × py3.10/3.12 + JS syntax check |
| Dashboard security posture | ✅ loopback default, opt-in LAN bind, optional token auth, scoped CORS |
| `CONTRIBUTING.md` | ✅ added — dev setup, test requirements, PR process |
| Security policy (`SECURITY.md`) | ✅ added — private disclosure via GitHub advisories, responsible-use statement, scope, safe harbor |
| Code of Conduct | ✅ added — Contributor Covenant v2.1 |
| Issue templates | ✅ added — bug report + feature request + config linking private security reporting |
| `py.typed` / type annotations | ✅ added — PEP 561 marker shipped in the wheel |
| Changelog | ✅ added — `CHANGELOG.md` (Keep a Changelog format) |
| Example scripts | ✅ added — `examples/` (curl, pip/npm, Python requests, remote VPS) |

**Verdict:** the code is in good shape for open-sourcing *as a clearly-labeled
security-research tool*. The dashboard security posture and the test suite
are no longer blockers; the remaining pre-launch item is a
**`SECURITY.md` + responsible-use statement** — everything else is polish.

## 6. Resolutions (2026-09-23 follow-up)

All four items from the "add what's missing" request landed on top of the
original audit findings:

- **Committed test suite** — `tests/` with pytest (62 tests), run in CI on
  every push/PR. Install with `pip install -e ".[dev]"`, run with `pytest`.
- **Dashboard hardening** — loopback bind by default, explicit
  `--dashboard-host` opt-in for LAN, `--dashboard-token` /
  `MINIPROXY_DASHBOARD_TOKEN` auth on mutating endpoints, loopback-only
  CORS. A warning is printed whenever the dashboard binds a LAN address.
- **Server-side filtering** — SQL-level method/status/URL filters on
  `/api/logs`, a new `/api/logs/count`, and all export endpoints.
- **Truncation notices** — original body sizes persisted
  (`request_body_len`, `response_body_len`) and surfaced in both UIs.
- **Background intruder** — non-blocking attacks with a status/progress
  endpoint (202/409 semantics) and a polling web UI.

---

*Audit scope: every file under `src/miniproxy/` plus the npm launcher
(`bin/`, `scripts/`). Verification: compile pass on all modules, Flask test
client exercising every endpoint (export ×4, clear, logs, meta, repeater
round-trip), Textual Pilot run of the TUI (filters, selection, help, save-body),
and unit checks of the intruder sanitization and prune throttle.*
