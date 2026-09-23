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

[Unreleased]: https://github.com/Zaidux/miniproxy/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.4.0
