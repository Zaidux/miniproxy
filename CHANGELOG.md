# Changelog

All notable changes to MiniProxy are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are
[SemVer](https://semver.org/)-ish (pre-1.0, so breaking changes may land in
minor releases).

Releases are published to [PyPI](https://pypi.org/project/riciplay-miniproxy/)
(`pip install riciplay-miniproxy`) and
[npm](https://www.npmjs.com/package/riciplay-miniproxy)
(`npm install -g riciplay-miniproxy`).

## [Unreleased]

## [0.7.0] — 2026-10-16

Eight features, plus the two interaction bugs they exposed.

### Fixed

- **You can copy values again.** The live poll re-rendered the table and the
  detail panes every 2 seconds, which destroyed any text selection. Worse,
  dragging *inside a row* to select its URL also fires the row's click
  handler, so the selection was cleared the instant it was made — selecting a
  value by hand was impossible. Rendering is now skipped when the output is
  unchanged, and deferred entirely while a selection is held (it flushes as
  soon as you click away).
- **The note field keeps what you type.** The poll assigned the textarea's
  `.value` on every tick, so text entered a second earlier was wiped — which
  read as "the last word disappears when I press space". The field is now left
  alone while it has focus or holds unsaved edits, and shows `unsaved…`
  instead of silently losing work.

### Added

**Compare captures (response diffing)**

- `GET /api/diff/<a>/<b>` and a dashboard modal. The access-control workflow:
  send a request twice with one parameter changed, and read off what actually
  changed instead of eyeballing two hex dumps.
- Three views, chosen automatically for the data present:
  - **JSON** — structural, keyed by dotted path, so `role: 'user' → 'admin'`
    is one line.
  - **Tokens** — word-level, for HTML/text. Punctuation is a token boundary,
    so a *minified* page still localises the change rather than reporting one
    unreadable blob.
  - **Bytes** — character-level with context, for exact offsets.
- Also diffs the URL parameters, path, status and headers — for access-control
  work the changed parameter name is often the whole answer.
- The summary names the change (`role: 'user' → 'admin'`), because "1 field
  differs" is useless mid-test.
- TUI equivalent: press `d` on one capture, move, press `d` again; `m` cycles
  the mode.

**Body search**

- `body` / `exclude_body` / `min_length` filters in SQL, across the listing,
  the count and every export. Searches the request **and** response body —
  where flags, leaked tokens and unexpected parameters actually live.

**Intruder pitchfork**

- `POST /api/intruder/start` with `{"mode": "pitchfork", "lists": {"user":
  [...], "pass": [...]}}`: a different wordlist per `§placeholder§`, run as a
  product. The engine previously put one word into *every* position, so a
  username × password attack was impossible.
- The UI grows one row per placeholder found in the target request, each with
  a list picker or file upload, and shows the combination count before you
  start. Combos are capped at 10,000.

**Bundled wordlists**

- Five curated lists ship in the package — numeric IDs, usernames, common
  passwords, parameter names, ports, paths — so a fresh install can attack
  without hunting for a `.txt` first. `GET /api/wordlists`.

**Repeater tabs + history**

- Multiple persistent tabs (`/api/repeater/tabs`), stored server-side so a
  refresh — or switching from desktop to phone — keeps work in progress.
- Per-tab send history (last 50) with status and size, click to view any past
  response. Edits auto-save as you type.
- **Follow redirects** checkbox: reports the whole redirect chain and the final
  URL. Off by default, because a lab that redirects is usually redirecting to a
  login page and silently following hides the 302 being tested.

**Match & replace**

- Rewrite headers, query parameters or bodies on requests **as they pass
  through the proxy** (`/api/rewrite`), so the target sees the modified values.
  For headers, `exact` matches the name and sets the value; `contains`/`regex`
  match inside the value. Regexes are validated on insert, and CR/LF is
  stripped from replacements (this runs before the request leaves — an
  unescaped newline would be request splitting).
- Dashboard **Rewrite…** modal and a TUI screen (`m`).

**TUI parity**

The terminal UI had none of the 0.6 dashboard work. It now has:
- Host, body, hide-static and highlighted-only filters
- Host / Path / marker columns instead of one wide URL column
- `d` to compare two captures, `n` for noise rules (toggle with Enter), `m` for
  match & replace

### Changed

- Oversized wordlists are refused with a 400 up front instead of being accepted
  and then failing inside the worker (which showed "attack started" before an
  error).
- Intruder payload substitution no longer escapes backslashes: the replacement
  is now a function, so `re.sub` cannot interpret `\g<0>` as a group
  reference. This also stops ordinary payloads like `DOMAIN\user` being
  corrupted.

### Security

- Match-and-replace replacement values have CR/LF stripped, since they are
  applied to the live request.

## [0.6.3] — 2026-10-16

The dashboard becomes something you can actually scan on a phone, and
browser noise stops drowning out the target.

### Added

**Dashboard — closer to Burp, still simpler**

- **Host and Path columns.** The URL is split in the request table so you can
  scan endpoints instead of scrolling past the same host 200 times. The host
  column is dimmed with a leading `www.`/`m.` stripped, the query string is
  shown after a dimmed `?`, and the full URL stays in the row tooltip. The Log
  tab and the request picker use the same split.
- **Size column.** Response size per row (recorded length, falling back to the
  stored body), formatted `B`/`K`/`M`.
- **Resizable, collapsible split.** The divider between the request table and
  the detail pane drags to resize (pointer events, so mouse/touch/pen all
  work) and collapses the detail pane to a full-width table on click. Arrow
  keys resize and Enter/Space toggle when the handle is focused. Width and
  collapsed state persist across refreshes. On narrow screens the panes stack
  and the divider becomes a horizontal affordance.
- **Custom row highlights.** A Burp-style 8-colour palette (red, orange,
  yellow, green, cyan, blue, magenta, pink) plus Clear. A highlighted row gets
  a coloured left bar and a faint tint. Stored on the row, so highlights
  survive refreshes, a different browser, and a proxy restart. Filter to your
  marked rows with the new **Highlighted** chip.
- **Per-row ⋮ menu.** Every row has a touch-sized overflow button — pinned to
  the right edge of the scroll area so it never scrolls out of reach on a
  phone — opening the palette plus Add note / Repeater / To Intruder. There is
  no right-click-only path, because right-click does not exist on Android.
- **Notes.** Free-text notes attached to a capture, edited in a new **Note**
  detail tab. Saving a note never clears the highlight, and vice versa.
- **Pretty / Raw / Hex body views**, on both the request and the response side.
  *Pretty* re-indents JSON; *Raw* escapes control and non-ASCII characters so
  you can see what a decoder or filter did to the bytes; *Hex* is a real dump
  with an offset column, byte columns and ASCII gutter, with all-zero rows
  dimmed. Each side keeps the view you last chose. Binary bodies get a hint
  pointing at Hex.
- **Host focus dropdown**, labelled with each host's capture count, plus a
  summary showing `N shown / M fetched` and naming the noisiest hosts.
- **Hide static chip** — drops images/fonts/css/js/media with one tap.
- **Noise modal** — manage rules, dry-run a scan, and delete captured noise,
  with the same confirmation and backup guarantees as the CLI.

**Noise — three layers**

- **Capture time.** Enabled host rules make matching traffic skip the row
  entirely; it is still proxied, it just never reaches the DB. Rules match on
  host (suffix-aware, `*.example.com` supported) and never on a path segment.
  A bundled list of known telemetry/ad hosts ships **disabled**, so nothing is
  dropped until you opt in.
- **Query time.** `host`, `exclude_host`, `hide_static` and `highlighted_only`
  filters, applied in SQL across the listing, the count and every export. A
  static asset is decided by content type first — a known asset MIME wins, a
  known non-asset MIME wins over a misleading `/api/image.png` filename — and
  only falls back to the URL extension when no type was recorded.
- **Cleanup time.** `scan_noise()` (dry run, never deletes) and
  `clean_noise()`, which writes a timestamped `.noise-backup-<date>.db`
  snapshot via SQLite's backup API first, cascades to `intruder_results`, and
  can protect hosts you name.
- **`miniproxy noise` CLI** — `list` / `enable` / `disable` / `add` / `rm` /
  `scan` / `clean`. `clean` refuses without `--yes` and takes repeatable
  `--keep-host`. Works with no dashboard and no proxy running.

**API**

- `PATCH /api/logs/<id>` — set `highlight` and/or `note` (absent keys
  untouched).
- `GET /api/hosts` — hosts with capture counts, busiest first.
- `GET|POST /api/noise/rules`, `PATCH|DELETE /api/noise/rules/<id>`,
  `GET /api/noise/scan`, `POST /api/noise/clean` (requires `confirm`).

### Changed

- The **Repeater tab now uses the same capture picker modal as the Intruder**,
  instead of a bare `<select>` that ignored the Live tab filters. Both pick
  from the same seeded filters and the modal header shows which editor "Use
  it" will fill, so you can no longer replay or fuzz a request the Live tab is
  hiding. The picker gained its own host filter and shows host/path columns.
- Exports (HAR + JSON) honour the new host / hide-static / highlighted filters,
  so an export matches what the table shows.
- Highlights and notes persist across restarts; the rest of the UI session
  (`localStorage`) additionally now keeps the host filter, the Hide-static and
  Highlighted chips, and the pane width/collapsed state.

### Fixed

- **The noise gate could stop all capture.** The capture-time check read
  `req` one line before `req` was assigned, raising `UnboundLocalError` on
  every single flow. mitmdump reports an addon exception and carries on, so
  the proxy still routed traffic while writing **nothing** to the capture DB
  — silent, and only visible as an empty request table. Fixed, and covered by
  an end-to-end test that runs the real addon under a real mitmdump process and
  asserts traffic actually lands in the DB (plus a check that the addon emits
  no traceback), so a swallowed addon exception fails CI from now on.
- A drag of the splitter handle also fired a click on it, so **every resize
  collapsed the detail pane**. The toggle is now suppressed for a real drag.
- `count_logs()` counted by materialising every matching row into Python
  (`get_logs(limit=10_000_000)`) and taking `len()`. It now runs a real
  `COUNT(*)`, so counting a large capture DB no longer loads hundreds of
  megabytes.
- Listing, counting and exporting now build their `WHERE` clause through one
  shared compiler, so they cannot drift apart.

### Security

- Highlight colors are validated against a fixed palette server-side. The
  value is interpolated into a `style` attribute, so an unvalidated string
  would have been a stored-XSS hole; off-palette values are rejected with a
  400 and never persisted.

## [0.6.1] — 2026-10-15

### Fixed
- **The intercept toggle was a silent no-op.** `set_intercept()` writes the
  `intercept` config key, but the intercept addon read `intercept_enabled` —
  a key nothing in the codebase ever wrote. Interception was therefore
  permanently on regardless of the stored preference. Both sides now use
  `intercept`. The addon defaults the key to `"1"`, so a fresh session (which
  has no row yet) still starts with interception enabled — verified against a
  real fresh DB, and against an existing one.
- `GET/POST /api/proxy/status` returned a hardcoded `"intercept_enabled": true`
  instead of the stored value.

## [0.6.0] — 2026-10-15

Closes the capture DB to the world, and makes one filter definition serve
every view.

### Security
- **The proxy is no longer published to the internet by default.** mitmdump
  was hardcoded to `--set block_global=false` and bound every interface, so
  on a VPS any host that could reach the port could capture *through*
  MiniProxy and land their own traffic in your database. New
  `--proxy-host` flag (default `127.0.0.1`) controls the bind address;
  reach a loopback-bound proxy from another machine with
  `ssh -L <port>:127.0.0.1:<port>`.
  - **Breaking:** a remote browser can no longer connect at the server's
    public IP unless you pass `--proxy-host 0.0.0.0`. Start prints a
    reminder of the `ssh -L` form whenever the proxy is published.
- **`--allow-client <ip>`** (repeatable) restricts the proxy port to specific
  client IPs via mitmproxy's `allow_hosts`. Required when combining
  `--proxy-host 0.0.0.0` with an internet-facing port; `start` warns when a
  published port has no allowlist.
- The startup warning for a LAN-exposed dashboard no longer fires when
  `--dashboard-token` was actually supplied (it previously printed
  "Pass --dashboard-token to require auth" on runs that had just passed it).

### Added
- **Capture-ID filtering, everywhere.** A shared selector accepted by the
  Live tab, the count header, the export menu and the Intruder picker:
  `42`, `1,5,9`, `100-200`, or any comma/space-separated mix. Multiple ids
  are OR-ed; reversed ranges (`200-100`) are normalised; unusable input is
  ignored rather than blanking the table or erroring. Backed by
  `db.parse_id_filter()` (SQL) with a matching client-side implementation
  so the live table stays instant.
- **Intruder request picker.** The Intruder target selector was a bare
  `<select>` that ignored the Live tab filters, so you could fuzz a request
  the live view was hiding. It is now a modal picker seeded from those
  filters and filterable by method, status, URL and ID, with row-click
  selection.
- **Visible "Clear captures" button.** Clearing was implemented and
  reachable but buried in the `Export ▾` dropdown (`display:none` until
  opened), so it read as missing. It now sits in the toolbar as a
  danger-styled button.

### Fixed
- **Repeater/Intruder selectors offered deleted requests.** After
  clearing, `state.logCache` was left populated, so the request dropdowns
  still listed rows that no longer existed and could be replayed. The cache,
  both selectors and the Log table are now refreshed.
- One shared filter reader (`app._log_filters()`) now backs `/api/logs`,
  `/api/logs/count` and every export. `exportFiltersQ()` previously rebuilt
  the query string by hand and would silently drop any newly added filter.
- The live poll now applies filters server-side. With an ID or URL filter
  active, the unfiltered 200-row window could contain none of the wanted
  rows and the table looked empty.
- `__version__` reported `0.4.0` from a 0.5.0 install, so `/api/meta`
  showed a version that did not match the package. All version strings are
  pinned together by `tests/test_version.py`.
- `_same_option()` dropped `action="append"` when copying options to the
  `web` alias, so repeatable flags collapsed to a bare string and would
  have been iterated one character at a time.

## [0.5.0] — 2026-09-25

### Added
- **Remote browser capture** — connect any browser, on any OS/device, from
  anywhere:
  - `GET /proxy.pac` — served proxy auto-config so clients (browsers, OS
    proxy settings, Android Wi-Fi "Proxy Auto-Config") can point themselves
    at MiniProxy with a single URL.
  - `GET /ca.crt` — download mitmproxy's CA certificate directly from the
    dashboard (no shell needed on the device you're connecting).
  - `GET /connect` and a **Connect** tab in the web dashboard — a step-by-step
    wizard (proxy address, PAC URL, CA install per OS, QR code for phones,
    `curl -x` one-liner, per-device pairing), plus a VPS/remote recipe in
    `docs/connect.md`.
  - **Saved device registry** — devices paired on the connect page (or
    dashboard Connect tab) persist in the capture DB: name, IP, browser,
    first/last seen; list/forget from either UI or via
    `GET/POST /api/connect/devices` + `DELETE /api/connect/devices/<id>`.
  - **Android walkthrough** — per-Wi-Fi manual proxy for Chrome/Firefox
    (incl. Firefox `about:config` route that works on mobile data), CA
    install on Android 7+, VPS firewall checklist (`docs/connect.md`).
  - `miniproxy connect` — the same instructions in the terminal, with a
    scannable ANSI QR of the connect page (`--qr yes|no|auto`,
    `--host/--port` overrides).
  - `miniproxy version` subcommand.
  - **Dynamic port selection** — a busy `--port` no longer aborts startup:
    MiniProxy moves up to the next free port and reports the choice (also
    for `--dashboard-port`). `--port auto` / `--dashboard-port auto` always
    pick a free port deterministically.

### Fixed
- **Every `miniproxy` invocation crashed** with
  `argparse.ArgumentError: conflicting subparser: web` on Python 3.12+
  (the `web` subparser was registered twice; found on a real VPS deploy —
  the CLI parser itself had zero test coverage). `build_parser()` is now
  a separate function covered by regression tests that assert every
  subcommand registers exactly once and parses.
- `miniproxy web --port N` passed the port as a *string* (`_same_option`
  dropped `type=` when copying options from `start` to `web`), and the
  copied option silently lost `--port auto` support.
- Docs: PEP 668 (`externally-managed-environment`) install guidance —
  pipx/venv instead of `--break-system-packages`, which downgrades
  shared libraries other tools depend on (`docs/setup.md`,
  `docs/troubleshooting.md`).
  - `w` in the TUI — a connect cheat-sheet overlay (proxy address, PAC,
    CA, curl one-liners).
  - Host detection shared by dashboard/CLI/TUI (`miniproxy.connect`):
    request Host header wins (SSH-tunnel correct), then external interface,
    LAN address, loopback — advertised consistently everywhere.
- **Dashboard persistence across refreshes** — captures are restored from the
  SQLite DB on page load (only **Clear all captures…** removes them), and
  filters, active tab, and the selected request survive a reload via
  `localStorage`; the dashboard token can be stored too.
- Open-source readiness docs: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, GitHub issue templates, this changelog, `py.typed`,
  and `examples/` recipes.

## [0.4.0] — 2026-09-23

The modernized "v4" package — the standalone distillation of the Riciplay CLI
engine.

### Added
- Always-on capture engine (mitmproxy addon): every request/response logged
  with headers, bodies, and status codes; static assets stream through
  without buffering.
- Per-flow timing: `ttfb_ms` and `total_ms` on every capture.
- Scope guard: `--scope '*.target.com'` with skip (default) or
  `--block-out-of-scope` modes.
- Textual TUI (`miniproxy tui`): live feed, master–detail inspection,
  filters, Repeater modal, Intruder results, proxy control (`p`), copy-curl,
  save-body.
- Web dashboard (Flask SPA) mirroring the TUI: Live/Log/Repeater/Intruder
  tabs, truncation notices, token prompt on 401.
- Exports: HAR 1.2, MiniProxy JSON, SQLite snapshot, per-request body
  download, confirm-guarded clear.
- Server-side SQL filters (method / status class / URL substring) on the log
  API and all exports, plus `/api/logs/count`.
- Background Intruder: attacks run in a daemon thread behind
  `POST /api/intruder/start` (202; 409 while running) with
  `GET /api/intruder/status` progress polling.
- Process manager (`server.py`): listener-ready startup waits, pid/port state
  in `~/.miniproxy/`, `miniproxy start` auto-launches the dashboard and
  prints its URL.
- Body-size caps with truncation notices (`MINIPROXY_MAX_BODY_BYTES`,
  default 100 KB, original sizes recorded per capture).
- Committed pytest suite (62 tests) and GitHub Actions CI
  (Linux/macOS × py3.10/3.12 + dashboard JS syntax check).
- npm distribution (`riciplay-miniproxy`) with a postinstall Python
  bootstrap.

### Fixed
- Prune throttled out of the capture hot path (no more per-request `VACUUM`
  stalls / `database is locked`).
- PID-reuse guard: pid files are verified against `/proc/<pid>/cmdline`
  before being trusted or killed.
- Intruder: `re.sub` group-reference crashes and CRLF injection via
  wordlist payloads; export filename injection via capture URLs.
- The old intercept toggle silently produced empty captures on fresh DBs —
  capture is now unconditional.

### Security
- Dashboard binds `127.0.0.1` by default; LAN/internet exposure requires
  explicit `--dashboard-host` (with a printed warning) and supports
  `--dashboard-token` auth on every mutating endpoint.
- CORS restricted to loopback origins (was `*`).

## [0.3.x and earlier]

See the git history (<https://github.com/Zaidux/miniproxy/commits/main>) —
the pre-0.4 releases were the Riciplay-bundled variant without a standalone
changelog.

[Unreleased]: https://github.com/Zaidux/miniproxy/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.7.0
[0.6.3]: https://github.com/Zaidux/miniproxy/releases/tag/v0.6.3
[0.6.1]: https://github.com/Zaidux/miniproxy/releases/tag/v0.6.1
[0.6.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.6.0
[0.5.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.5.0
[0.4.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.4.0
