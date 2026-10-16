# Web UI

The browser dashboard is the TUI in your browser — same data, same layout
ideas, zero terminal required. It reads the same SQLite capture DB, so the
TUI, the CLI, and the web UI always agree.

## Getting the URL

`miniproxy start` launches the dashboard alongside the proxy and prints
the URL:

```
MiniProxy started on :8080 (PID 12345, db=/home/you/.miniproxy/proxy.db)
Web UI: http://127.0.0.1:5000   ← paste this into your browser to use MiniProxy (mirrors `miniproxy tui`)
Connect: http://127.0.0.1:5000/connect   — wizard to route any other browser/device through the proxy
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

Two panes with a **draggable divider** between them.

### Left — captured requests

Columns: **ID, method, status, size, host, path**, plus a **⋮** button per
row. Refreshes every 2s.

The URL is split into **host** and **path** deliberately: in a real capture
the host repeats on every row and the path is the only part that identifies
the endpoint. The host column is dimmed and a leading `www.`/`m.` is stripped
so the eye lands on the path; the query string is shown dimmed after `?`.
The full URL is always in the row tooltip.

Filters on top:

| Filter | Matches |
|--------|---------|
| Host | narrows to one host — the dropdown lists every host with its capture count |
| Method | exact (GET, POST…) |
| Status | 2xx / 3xx / 4xx / 5xx / Errors (code 0 = transport error) / Pending (no response yet) |
| URL substring | case-insensitive, anywhere in the URL |
| ID | exact ids and ranges: `42`, `1,5,9`, `100-200` |
| **Hide static** | drops images/fonts/css/js/media captures |
| **Highlighted** | only captures you marked |

Filters are applied **server-side** (SQL), so huge capture DBs stay fast —
and the same filters carry into exports via the query string. The
**Export ▾** menu offers HAR 1.2, MiniProxy JSON, a SQLite snapshot, the
selected response body, and **Clear all captures…** (confirm-guarded).

Click a row to select it. Selection survives refreshes.

### The ⋮ row menu (works on a phone)

Every row ends in a **⋮** button — sized as a real touch target, and
pinned to the right edge of the scroll area so it never scrolls out of
reach on a narrow screen. Tapping it opens a popover with:

- the **8-colour highlight palette** (plus Clear)
- **Add note…** — jumps to the Note tab
- **Repeater** — opens this request in the edit-and-resend modal
- **To Intruder** — loads it into the Intruder with `§param§` markers

There is deliberately **no right-click-only menu**: right-click does not
exist on Android, so the ⋮ is the only entry point.

### Highlighting and notes

Highlights are a Burp-style fixed palette (red, orange, yellow, green, cyan,
blue, magenta, pink). A highlighted row gets a coloured left bar and a faint
tint, and survives restarts — it is stored on the row, not in the browser.

The colour set is fixed and **validated server-side**: a highlight is
interpolated into a `style` attribute, so arbitrary CSS would be a stored-XSS
hole. Off-palette values are rejected with a 400.

Notes are free text attached to a capture, edited in the **Note** tab and
saved with **Save note**. Saving a note never clears the highlight, and vice
versa.

Filter to your marked rows with the **Highlighted** chip.

### Right — detail tabs

- **Request** — request line + headers, then the body
- **Response** — headers and body; pending rows say so, transport errors
  show the underlying reason. Bodies stored truncated (default cap 100 KB)
  carry a "⚠ truncated" notice with the original size.
- **Intruder** — fuzzing results recorded for this request
- **Note** — the capture's note + a full highlight palette

Both body panes have three views:

| View | Shows |
|------|-------|
| **Pretty** | JSON re-indented; anything else as received |
| **Raw** | the bytes with control characters escaped (`\x00`, `\t`, `\x7f`, …) — shows what a decoder did or a filter stripped |
| **Hex** | the classic dump: offset column, byte columns, ASCII gutter. All-zero rows are dimmed. Byte offsets are exact. |

Each side keeps the view you last chose, so you can flip between the request
and response in the same representation. The hint line under the tabs reports
the byte count (and warns when a body is binary and better read in Hex).

Action buttons under the tabs:

- **Repeater** — opens the edit-and-resend modal
- **Copy curl** — a ready-to-run curl command with original headers/body
- **Copy body** — the response body to your clipboard
- **Save body…** — download the stored response body
- **Highlight…** — the same palette as the ⋮ menu
- **Note** — jump to the Note tab
- **To Intruder** — hand this request to the Intruder

### Resizing and hiding the detail pane

The divider between the panes is draggable (mouse, touch, or pen — it uses
pointer events, so it works from a phone). Click it to **collapse** the
detail pane and get a full-width request table; click again to bring the
detail pane back. With the handle focused, **←/→** resize and **Enter/Space**
toggle.

The width and the collapsed state are remembered in `localStorage`, so the
layout you set is the layout you get after a refresh.

On a narrow screen the panes stack vertically and the divider becomes a
horizontal affordance instead.

## Repeater

Two ways in:

1. **Modal** from the Live tab's Repeater button — method/URL on top,
   headers + body on the left, **Send (Ctrl+S)** on the right, and the
   response renders next to it. Esc or the ✕ closes it.
2. **Full tab** (Repeater tab) — **Pick a captured request…** opens the same
   modal the Intruder uses: a filtered, searchable table seeded from the Live
   tab's filters. Edit anything, Send. Same endpoint as the CLI's
   `miniproxy send`.

Both the Repeater and the Intruder pick from the same modal and the same
filters, so you can never end up fuzzing (or replaying) a request the Live
tab is hiding. The modal header shows which editor "Use it" will fill.

Requests are sent by the dashboard process (not through the capture
proxy), with redirects disabled and TLS verification relaxed for lab use —
the same semantics as `miniproxy send`.

## Log tab

The complete request history (respects the Live tab filters): time, method,
host, path, status. Click a row to jump to that request selected in the Live
tab. Highlights are carried over, so you can spot your marked rows in the
history too.

## Noise — the browser-noise problem

A browser session drags in telemetry pings, ad beacons, new-tab thumbnails
and font requests. On a typical Firefox run against the Web Security
Academy, 119 captured rows contained **12** on-target requests — the other
107 were noise. MiniProxy attacks this in three layers.

### 1. Capture-time — rules

Hosts you enable are dropped **before the row is written**, so they never
enter the DB at all. Traffic is still proxied untouched; only the capture is
skipped.

A bundled list of well-known telemetry/ad hosts (Firefox telemetry, Pocket,
DoubleClick, Google Analytics, scorecards…) ships **disabled** — a host list
is a policy decision, not a fact about the target, so nothing is dropped
until you opt in.

Either the **Noise…** button in the dashboard, or the CLI:

```bash
miniproxy noise list                 # rules and their state
miniproxy noise enable               # enable them all (the one-click opt-in)
miniproxy noise add '*.telemetry.example.com'
miniproxy noise disable youtube.com  # just this one
miniproxy noise rm youtube.com
```

Rule matching is host-based and suffix-aware: a bare `example.com` also
covers `a.example.com`, and `*.example.com` works too. A rule never matches
on a path segment — `/ads.example.com/x` on another host is not noise.

### 2. Query-time — filters

For noise already in the DB, without deleting anything:

- **Host** dropdown — one tap to focus your target. Labels carry the capture
  count, so "60 captures" immediately explains where your table went.
- **Hide static** — drops images/fonts/css/js/media.
- The summary on the right of the filter bar shows `N shown / M fetched` and
  names the noisiest hosts.

A static asset is decided by content type first (a known asset MIME wins, a
known non-asset MIME wins over a misleading filename like `/api/image.png`),
falling back to the URL extension only when no type was recorded. The SQL
filter and the in-browser filter are asserted to agree.

### 3. Cleanup-time — delete

```bash
miniproxy noise scan     # dry run: what would go, broken down by host
miniproxy noise clean    # refuses without --yes, and tells you the numbers
miniproxy noise clean --yes --keep-host target.example
```

Or **Noise… → Scan (dry run) → Delete noise captures…** in the dashboard.
Both paths:

- **refuse to delete without explicit confirmation**
- **write a timestamped backup** first (`.noise-backup-<date>.db`, via
  SQLite's backup API so it is never a torn copy), and report its path
- cascade to `intruder_results` for any deleted capture
- honour `--keep-host` for anything you care about

The noise rules themselves stay enabled afterwards, so future traffic to
those hosts is skipped at capture time.

### Endpoint summary

| Endpoint | Purpose |
|----------|---------|
| `GET /api/hosts` | hosts with capture counts (powers the Host dropdown) |
| `GET /api/noise/rules` | list rules + the highlight palette |
| `POST /api/noise/rules` | add a rule, or `{"enable_builtin": true}` to flip them all |
| `PATCH`/`DELETE /api/noise/rules/<id>` | enable/disable or remove one rule |
| `GET /api/noise/scan` | dry run: what would be removed, and why |
| `POST /api/noise/clean` | delete; requires `{"confirm": true}` |
| `PATCH /api/logs/<id>` | set `highlight` and/or `note` |

All of them accept the shared filters (`host`, `exclude_host`,
`hide_static`, `highlighted_only`) alongside method/status/url/id.

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
session also survives refreshes via `localStorage`: active tab, host/method/
status/URL/ID filters, the Hide-static and Highlighted chips, the selected
request, the pane width, whether the detail pane is collapsed, and the
dashboard token you typed at the 401 prompt are restored on load. Clearing
site data resets all of it.

Highlights and notes are **not** in `localStorage` — they are columns on the
capture row, so they survive a browser, a refresh, and a proxy restart.

## Proxy control from the browser

The header **Start/Stop** button calls the same process manager as the
CLI. Starting from the web UI launches mitmdump with your current state
(default DB); stopping it leaves the dashboard itself running so you can
keep browsing captures. Capture is always on while the proxy runs —
there's no "pause" (see the note on the v4 engine in the main README).
