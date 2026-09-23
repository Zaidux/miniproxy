# MiniProxy

A lightweight HTTP/S interception proxy for security research — the standalone Burp-style toolkit from the [Riciplay](https://github.com/Zaidux/Riciplay) ecosystem. Built on **mitmproxy**, **Flask**, and **SQLite**.

Ships the **v4 capture engine** (the same addon the Riciplay CLI embeds):

- **Always-on capture** — every request/response is logged with full headers, bodies, and status codes. (The old intercept toggle silently produced empty captures on fresh DBs; it's gone.)
- **Static-asset streaming** — JS/CSS/images stream through without buffering, so heavy SPAs don't pay a per-flow decode tax.
- **Timing** — `ttfb_ms` / `total_ms` on every flow. Oracles and timing side-channels need numbers.
- **Scope guard** — `--scope '*.target.com'` keeps out-of-scope traffic out of your capture DB (or 403-blocks it with `--block-out-of-scope`).
- **Repeater** — pick a logged request, edit method/headers/body, resend, inspect.
- **Intruder** — mark parameters with `§param§` placeholders, supply a wordlist, fuzz every position; results highlighted by status code and stored in the DB.
- **TUI** — a full terminal UI (`miniproxy tui`, built with [Textual](https://textual.textualize.io)): live capture feed, master–detail inspection, filters, Repeater, Intruder results, and proxy control — no browser needed.

## Install

```bash
# Python (PyPI)
pip install riciplay-miniproxy

# or Node (npm — installs the Python package on postinstall)
npm install -g riciplay-miniproxy
```

Requires Python 3.10+ and [mitmproxy](https://mitmproxy.org/).

## Quick start

```bash
miniproxy start                          # proxy on :8080 + web UI on :5000 (URL is printed)
miniproxy start --scope '*.target.com'   # capture only in-scope traffic
miniproxy tui                            # terminal UI (live feed, repeater, filters)
miniproxy dashboard                      # web UI in the foreground (Log/Repeater/Intruder)
miniproxy stop                           # stop proxy + dashboard
```

Then point your browser/system at `http://127.0.0.1:8080` (HTTPS interception uses mitmproxy's CA — run `mitmdump` once and install `~/.mitmproxy/mitmproxy-ca-cert.pem` if you haven't). Capture is always on while the proxy runs; the web UI and TUI are just windows onto the same capture DB.

📚 **Full documentation in [`docs/`](docs/index.md)** — [setup](docs/setup.md) · [CLI & TUI](docs/cli-and-tui.md) · [web UI](docs/web-ui.md) · [integrations](docs/integrations.md) · [troubleshooting](docs/troubleshooting.md) · [code audit](docs/AUDIT.md).

```bash
miniproxy log                  # recent captured requests (with timing; reads the DB directly)
miniproxy log --id 5           # full detail for request #5
miniproxy send --url https://example.com/api --method POST \
               --headers '{"Content-Type":"application/json"}' \
               --body '{"key":"value"}'
miniproxy status
miniproxy stop
```

State (pid, port, default capture DB) lives under `~/.miniproxy/`.

## The TUI

`miniproxy tui` opens a two-pane terminal dashboard over the same SQLite capture DB the dashboard uses (it does not need the dashboard — or even the proxy — running):

- **Left** — the live capture table (ID, method, status, latency, URL), polling every 2s (`--refresh` to tune).
- **Right** — tabbed detail panes for the selected request: Request (line, headers, body), Response (headers, body), Intruder results.
- **Filters** — method, status class (2xx/3xx/4xx/5xx/errors/pending), and URL substring, all applied live.
- **Proxy bar** — current proxy state; `p` starts/stops it without leaving the app.
- Selection survives refreshes, `c` copies the request as a ready-to-run curl command, `y` copies the response body.

Keys: `r` Repeater · `i` Intruder · `c` copy curl · `y` copy body · `p` proxy · `R` refresh · `f/t/s` focus URL/method/status filter · `j/k` + `g/G` navigate · `?` help · `q` quit.

## Capturing traffic from the terminal (no browser needed)

You do **not** need a browser in your terminal. A proxy is just a middleman: any HTTP client that points at `127.0.0.1:8080` appears in the capture — browser or not.

```bash
# pane 1
miniproxy start
miniproxy tui

# pane 2 — point any client at the proxy
export https_proxy=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080
curl https://api.github.com/zen        # shows up in the TUI immediately
pip install requests                   # same
HTTPS_PROXY=$https_proxy npm ping      # same
```

Plain HTTP works with zero setup. For **HTTPS**, the client must trust mitmproxy's CA (exactly like a browser would):

```bash
export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem   # python/requests/pip
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem  # node/npm
curl --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com
```

Tools that ignore proxy env vars can usually be pointed explicitly (`curl -x`, `git config http.proxy`, `pip --proxy`). And when *your own browser* is the client, nothing changes: point it at the proxy as usual and keep the TUI open beside it — both views read the same DB in real time.

## The dashboard

`miniproxy dashboard` serves a dark-theme SPA:

- **Proxy** — capture status and scope
- **Log** — live request feed; click any row for full headers/bodies/timing
- **Repeater** — edit and resend any captured request
- **Intruder** — `§param§` placeholders + wordlist fuzzing, results by status code

## Relation to the Riciplay CLI

The Riciplay CLI (`pip install riciplay-cli`) embeds this same engine with agent-first extras: per-session capture DBs, RULES.md-derived scope enforcement, headless replay with response diffing, and bounded payload sweeps driven by the AI agent. Use MiniProxy standalone when you want the manual Burp-like workflow; use Riciplay when you want the agent to drive.

## Project structure

```
src/miniproxy/
├── addon/
│   ├── proxy.py        # mitmproxy addon — v4 capture engine
│   └── db.py           # SQLite handler (timing columns, intruder results, pruning)
├── app.py              # Flask dashboard (API + UI)
├── intruder.py         # §placeholder§ fuzzing engine
├── server.py           # start/stop/status process manager
├── tui.py              # Textual terminal UI (live feed, repeater, filters)
└── __main__.py         # the `miniproxy` entry point (start/stop/status/
                        #   dashboard/tui/send/log — log, send, and the TUI
                        #   work without any dashboard running)
```

## Development

```bash
git clone https://github.com/Zaidux/miniproxy && cd miniproxy
pip install -e ".[dev]"
pytest                     # 62 tests: db, API, exports, intruder, process mgr, TUI
```

CI runs the suite on Linux/macOS (Python 3.10/3.12) for every push and PR,
plus a JS syntax check on the dashboard. The web dashboard binds `127.0.0.1`
by default; LAN exposure is opt-in via `--dashboard-host 0.0.0.0` (pair it
with `--dashboard-token` for auth on state-changing endpoints) — see
[docs/web-ui.md](docs/web-ui.md).

## License

MIT
