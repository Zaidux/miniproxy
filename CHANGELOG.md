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

[Unreleased]: https://github.com/Zaidux/miniproxy/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.6.0
[0.5.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.5.0
[0.4.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.4.0
