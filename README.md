# MiniProxy

A lightweight HTTP/S interception proxy for security research — the standalone Burp-style toolkit from the [Riciplay](https://github.com/Zaidux/Riciplay) ecosystem. Built on **mitmproxy**, **Flask**, and **SQLite**.

Ships the **v4 capture engine** (the same addon the Riciplay CLI embeds):

- **Always-on capture** — every request/response is logged with full headers, bodies, and status codes. (The old intercept toggle silently produced empty captures on fresh DBs; it's gone.)
- **Static-asset streaming** — JS/CSS/images stream through without buffering, so heavy SPAs don't pay a per-flow decode tax.
- **Timing** — `ttfb_ms` / `total_ms` on every flow. Oracles and timing side-channels need numbers.
- **Scope guard** — `--scope '*.target.com'` keeps out-of-scope traffic out of your capture DB (or 403-blocks it with `--block-out-of-scope`).
- **Repeater** — pick a logged request, edit method/headers/body, resend, inspect.
- **Intruder** — mark parameters with `§param§` placeholders, supply a wordlist, fuzz every position; results highlighted by status code and stored in the DB.

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
miniproxy start                          # proxy on :8080
miniproxy start --scope '*.target.com'   # capture only in-scope traffic
miniproxy dashboard                      # web UI on :5000 (Log/Repeater/Intruder)
```

Then point your browser/system at `http://127.0.0.1:8080` (HTTPS interception uses mitmproxy's CA — run `mitmdump` once and install `~/.mitmproxy/mitmproxy-ca-cert.pem` if you haven't).

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
└── __main__.py         # the `miniproxy` entry point (start/stop/status/
                        #   dashboard/send/log — log and send work without
                        #   any dashboard running)
```

## License

MIT
