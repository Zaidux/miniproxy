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
- **Connect any browser** — the dashboard's **Connect** tab serves a PAC file, the CA cert, and a QR code so your browser (on any OS/device, including over SSH to a VPS) can route itself through MiniProxy.

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
miniproxy start --port auto              # pick any free port (busy ports also move up automatically)
miniproxy start --scope '*.target.com'   # capture only in-scope traffic
miniproxy tui                            # terminal UI (live feed, repeater, filters)
miniproxy dashboard                      # web UI in the foreground (Log/Repeater/Intruder)
miniproxy stop                           # stop proxy + dashboard
```

Then point your browser/system at `http://127.0.0.1:8080` — the dashboard's **Connect** tab (`/connect`) prints the exact settings, a one-click PAC URL, the CA download, and a QR code. HTTPS interception uses mitmproxy's CA — install it from the Connect tab or run `mitmdump` once (`~/.mitmproxy/mitmproxy-ca-cert.pem`). Capture is always on while the proxy runs; the web UI and TUI are just windows onto the same capture DB. Running the proxy on a VPS or another machine? See [docs/connect.md](docs/connect.md).

### Capturing from another machine

Since 0.6.0 the proxy binds `127.0.0.1` only, so it is **not** reachable from
other machines until you say so. Forward the port over SSH instead — the
proxy never needs a public address:

```bash
# on the client (laptop/phone), then point the browser at 127.0.0.1:8080
ssh -N -L 8080:127.0.0.1:8080 user@your-host
```

To publish the proxy on a LAN/VPS interface instead, bind it explicitly and
restrict who may connect:

```bash
miniproxy start --proxy-host 0.0.0.0 --allow-client 203.0.113.7
```

`--allow-client` is repeatable. Without it, a published proxy is an open
relay: anything that can reach the port can capture through it and write to
your database.

📚 **Full documentation in [`docs/`](docs/index.md)** — [setup](docs/setup.md) · [CLI & TUI](docs/cli-and-tui.md) · [web UI](docs/web-ui.md) · [connect browsers & devices](docs/connect.md) · [integrations](docs/integrations.md) · [troubleshooting](docs/troubleshooting.md) · [code audit](docs/AUDIT.md).

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

### Quieting browser noise

```bash
miniproxy noise list                  # rules and their state
miniproxy noise enable                # opt into the bundled telemetry/ad list
miniproxy noise add '*.telemetry.example.com'
miniproxy noise disable youtube.com   # just this one
miniproxy noise rm youtube.com

miniproxy noise scan                  # dry run: what would go, by host
miniproxy noise clean                 # refuses without --yes
miniproxy noise clean --yes --keep-host target.example
```

Enabled rules make matching hosts skip the capture **entirely** — the traffic
is still proxied, it just never reaches the DB. `clean` writes a timestamped
`.noise-backup-<date>.db` snapshot first (via SQLite's backup API) and reports
its path, so a misjudged rule is always recoverable. Works with no dashboard
and no proxy running. Full model: [docs/web-ui.md](docs/web-ui.md#noise--the-browser-noise-problem).

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

- **Live** — capture status, live request feed; click any row for full headers/bodies/timing
- **Log** — the complete request history
- **Repeater** — edit and resend any captured request
- **Intruder** — `§param§` placeholders + wordlist fuzzing, results by status code
- **Connect** — PAC URL, CA download, QR code, and step-by-step settings for connecting any browser/device (including remotely)

### Built for scanning, and for a phone

- **Host + Path columns** — the URL is split so you read endpoints, not the same host 200 times.
- **Resizable / collapsible panes** — drag the divider, click it to hide the detail pane. Remembered across refreshes.
- **Highlight + notes** — an 8-colour Burp-style palette per row (tap the **⋮** button — a real touch target, no right-click needed) and free-text notes. Stored with the capture, so they survive restarts.
- **Pretty / Raw / Hex** — every body, both request and response. JSON re-indented, bytes escaped, or a full hex dump with offsets and an ASCII gutter.
- **Compare captures** — diff two requests the way Burp's Compare does. Added a parameter and want to know what changed? The summary names it: `role: 'user' → 'admin'`.
- **Body search** — full-text over request *and* response bodies, where flags and leaked tokens actually live.
- **Host focus + Hide static** — one tap to narrow to your target, or drop images/fonts/css/js.
- **Noise control** — see below.

### Testing tools

- **Repeater** — persistent tabs with per-tab send history, auto-saving edits, and an optional **follow redirects** so you can see where a 302 lands.
- **Intruder** — `§param§` fuzzing in two modes: one wordlist into every position, or **pitchfork** (a different list per position — usernames × passwords, which is how auth labs are actually solved).
- **Bundled wordlists** — IDs, usernames, passwords, parameter names, ports, paths. No `.txt` hunting on a fresh install.
- **Match & replace** — rewrite headers, query params or bodies on requests as they pass through the proxy.

Captures persist across refreshes and restarts until you click
**Clear all captures…**.

## Browser noise (the thing that ruins a capture)

A browser session drags in telemetry pings, ad beacons, new-tab thumbnails
and fonts. On a real Web Security Academy run: **119 captured rows, 12 on
target**. MiniProxy fights this in three layers, so you can go back to
reading the requests.

1. **Capture time** — enable noise rules and matching hosts never reach the DB
   at all (traffic is still proxied). A bundled list of known telemetry/ad
   hosts ships *disabled*, so nothing is dropped until you opt in.
2. **Query time** — the Host dropdown, the **Hide static** chip, and the
   **Highlighted** chip narrow what's already captured, with a summary showing
   `N shown / M fetched` and naming the noisiest hosts.
3. **Cleanup time** — `noise scan` previews exactly what would be deleted
   (broken down by host) and `noise clean` applies it. Both the CLI and the
   dashboard's **Noise…** button **refuse to delete without confirmation**,
   write a timestamped `.noise-backup-<date>.db` first, and can protect hosts
   you name.

```bash
miniproxy noise list       # rules and their state
miniproxy noise enable     # opt into the bundled telemetry/ad list
miniproxy noise add '*.telemetry.example.com'
miniproxy noise scan       # dry run — never deletes
miniproxy noise clean      # refuses without --yes
```

## Connecting a browser (yours, a phone, or anywhere)

You don't need a browser in your terminal — you need the browser to send its
traffic *through* the proxy:

```bash
miniproxy connect          # prints the exact settings + a scannable QR
```

or open the dashboard's **Connect** tab (`http://127.0.0.1:5000/connect`):
one-click PAC URL, CA download with per-OS steps, `curl -x` one-liners, a
persistent saved-device registry, and a scannable QR code. The TUI shows the same cheat-sheet on `w`. Running MiniProxy
on a VPS and pointing your laptop/phone at it from anywhere?
**[docs/connect.md](docs/connect.md)** covers both the SSH-tunnel and
public-exposure patterns.

## Community & project docs

- [Security policy](SECURITY.md) — report vulnerabilities privately; responsible-use rules
- [Contributing](CONTRIBUTING.md) — dev setup, testing requirements, PR process
- [Code of Conduct](CODE_OF_CONDUCT.md) — Contributor Covenant
- [Changelog](CHANGELOG.md) — every release
- [Examples](examples/) — curl / pip / npm / Python / VPS recipes

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
                        #   dashboard/tui/send/log/noise — log, noise, send,
                        #   and the TUI work without any dashboard running)
```

## Development

```bash
git clone https://github.com/Zaidux/miniproxy && cd miniproxy
pip install -e ".[dev]"
pytest                     # 390+ tests: db, devices, API, exports, intruder,
                          # process mgr, TUI, connect, noise, JS/Python parity,
                          # dashboard XSS, live mitmdump capture, diff,
                          # body search, pitchfork, selection safety
```

CI runs the suite on Linux/macOS (Python 3.10/3.12) for every push and PR,
plus a JS syntax check on the dashboard. The web dashboard binds `127.0.0.1`
by default; LAN exposure is opt-in via `--dashboard-host 0.0.0.0` (pair it
with `--dashboard-token` for auth on state-changing endpoints) — see
[docs/web-ui.md](docs/web-ui.md).

## License

MIT
