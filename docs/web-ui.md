# Web UI

The browser dashboard is the TUI in your browser — same data, same layout
ideas, zero terminal required. It reads the same SQLite capture DB, so the
TUI, the CLI, and the web UI always agree.

## Getting the URL

`miniproxy start` launches the dashboard alongside the proxy and prints
the URL:

```
MiniProxy started on :8080 (PID 12345, db=/home/you/.miniproxy/proxy.db)
Web UI: http://127.0.0.1:5000  (mirrors `miniproxy tui`)
```

Other ways:

```bash
miniproxy status            # prints the URL if the dashboard is running
miniproxy web               # (re)start proxy + dashboard, print URL
miniproxy start --dashboard-port 8081   # custom port
```

The dashboard binds `127.0.0.1` only — it is not reachable from other
machines. To open it to your network (e.g. to drive it from a phone, see
[Integrations → mobile devices](integrations.md#mobile-devices)) you must
opt in explicitly, and should set a token:

```bash
miniproxy start --dashboard-host 0.0.0.0 --dashboard-token s3cret
```

With a token set, every state-changing action (proxy toggle, Repeater send,
Intruder attack, clear/export mutations) requires it — the UI will prompt
you once per session. Read-only endpoints (log listing, detail, exports)
remain open. Never expose the dashboard to the internet.

Already running a proxy without the dashboard? Start it alone:

```bash
miniproxy dashboard --port 5000        # foreground
```

## Header bar

- **proxy state** — green dot + port when the capture proxy is running,
  grey otherwise. The **Start/Stop** button next to it toggles the proxy
  process (same as the TUI's `p` or `miniproxy start/stop`).
- **db path** — which capture DB you're looking at (hover for the full path).

## Live tab (mirrors the TUI)

Two panes:

**Left — captured requests.** Columns: ID, method badge, status, ms, URL.
Refreshes every 2s. Filters on top:

| Filter | Matches |
|--------|---------|
| Method | exact (GET, POST…) |
| Status | 2xx / 3xx / 4xx / 5xx / Errors (code 0 = transport error) / Pending (no response yet) |
| URL substring | case-insensitive, anywhere in the URL |

Filters are applied **server-side** (SQL), so huge capture DBs stay fast —
and the same filters carry into exports via the query string. The
**Export ▾** menu offers HAR 1.2, MiniProxy JSON, a SQLite snapshot, the
selected response body, and **Clear all captures…** (confirm-guarded).

Click a row to select it. Selection survives refreshes.

**Right — detail tabs.**

- **Request** — request line + headers, then the body
- **Response** — headers and body; pending rows say so, transport errors
  show the underlying reason. Bodies stored truncated (default cap 100 KB)
  carry a "⚠ truncated" notice with the original size.
- **Intruder** — fuzzing results recorded for this request

Action buttons under the tabs:

- **Repeater** — opens the edit-and-resend modal
- **Copy curl** — a ready-to-run curl command with original headers/body
- **Copy body** — the response body to your clipboard

## Repeater

Two ways in:

1. **Modal** from the Live tab's Repeater button — method/URL on top,
   headers + body on the left, **Send (Ctrl+S)** on the right, and the
   response renders next to it. Esc or the ✕ closes it.
2. **Full tab** (Repeater tab) — pick a logged request from the dropdown,
   edit anything, Send. Same endpoint as the CLI's `miniproxy send`.

Requests are sent by the dashboard process (not through the capture
proxy), with redirects disabled and TLS verification relaxed for lab use —
the same semantics as `miniproxy send`.

## Log tab

The complete request history (no filters): time, method, URL, status.
Click a row to jump to that request selected in the Live tab.

## Intruder tab

1. Pick a logged request — fields prefill.
2. Insert `§param§` placeholders where payloads go, e.g.
   `https://target.com/item?id=§fuzz§` or `{"user":"§user§"}`.
3. Upload a wordlist `.txt` (one entry per line, max 1000).
4. **Start attack** — every payload is substituted into every placeholder
   and sent; results are color-coded by status and stored in the DB.
5. Click a row to see the payload's full response.

Results are also visible in the Live tab's Intruder pane (select the base
request) and from the CLI/TUI.

## Connect tab

The **Connect** tab is the dashboard's wizard for routing *other* browsers
and devices (phone, laptop, anything) through MiniProxy — including from
anywhere over the internet when the proxy runs on a VPS. It shows the
detected proxy address, the one-click **PAC URL**, the CA download with
per-OS install steps, a QR code for phones, and a one-click verify + device
pairing. Full walkthrough: [connect.md](connect.md).

## Session persistence

Captures are stored in SQLite, so a page refresh (or closing and reopening
the dashboard) never loses them — only **Clear all captures…** does. The UI
session also survives refreshes via `localStorage`: active tab, method/status/
URL filters, the selected request, and the dashboard token you typed at the
401 prompt are restored on load. Clearing site data resets all of it.

## Proxy control from the browser

The header **Start/Stop** button calls the same process manager as the
CLI. Starting from the web UI launches mitmdump with your current state
(default DB); stopping it leaves the dashboard itself running so you can
keep browsing captures. Capture is always on while the proxy runs —
there's no "pause" (see the note on the v4 engine in the main README).
