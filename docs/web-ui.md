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

## Tabs

The dashboard is organised as tabs across the top:

| Tab | What it is |
|-----|------------|
| **Live** | the capture feed + detail pane — where you spend most of your time |
| **Log** | the full request history |
| **Repeater** | edit and resend, with tabs and send history |
| **Intruder** | `§param§` fuzzing, single-list or pitchfork |
| **Diff** | compare two captures and read off what changed |
| **Noise** | which hosts are skipped at capture time, and cleanup |
| **Rewrite** | match & replace applied to live traffic |
| **Connect** | route any browser/device through the proxy |

The active tab is remembered across a refresh.

**Diff**, **Noise** and **Rewrite** are also reachable from where you need
them — and those entry points *navigate to the tab* rather than opening an
overlay, so there is only ever one copy of each screen:

- **⋮ → Compare** on any row, or **Compare…** in the detail pane, hands the
  capture to the Diff tab as **A**.
- **Compare…** in the Repeater does the same.
- **Noise…** and **Rewrite…** in the filter bar switch to their tabs.

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

> **Copying text by hand works.** The live poll skips re-rendering when the
> output is unchanged, and defers entirely while you hold a selection — so you
> can drag-select a value and copy it normally. (Dragging inside a row also
> fires that row's click handler, which used to clear the selection the moment
> you made it.)

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
- **Compare…** — diff this capture against another (below)

### Comparing two captures

The access-control workflow. Send the same request twice with one parameter
changed, then ask *what actually changed* instead of reading two hex dumps.
Open it from the **Diff** tab directly, or hand it a capture with **Compare…**
in the detail pane, **Compare…** in the Repeater, or **⋮ → Compare** — those
take you to the tab with A already set.

Pick **A** and **B** (each via the normal capture picker), and the header names
the difference — for example `role: 'user' → 'admin'`. Six views:

| View | Shows |
|------|-------|
| **What changed** | everything that differs, in one table — the default |
| **JSON** | structural, keyed by dotted path (`user.role`) |
| **Tokens** | word-level, for HTML/text; punctuation is a token boundary, so minified pages still localise the change |
| **Bytes** | both bodies side by side, for exact offsets |
| **Params** | query parameters and path |
| **Headers** | header additions, removals and edits |

The mode is chosen automatically for the data present (JSON → tokens → bytes),
and the summary line names the field rather than just counting them.

Two verdicts appear, and they answer different questions:

| Field | Means |
|-------|-------|
| **status** (`same` / `different`) | **status codes only** — did the server return the same code? |
| **identical** | the whole row: status, headers, params, request body and response body |

Two responses can be `status: same` and still `identical: false` — identical
`200`s that differ only in a query parameter, for example. Read `identical`,
not `status`, when asking whether anything changed at all.

### Searching bodies

The **Search bodies…** box filters on the request **and** response body, not
just the URL. That is where flags, leaked tokens and unexpected parameters
live, so it is usually faster than scrolling:

```
Search bodies…   CTF{          → only captures whose body contains it
Search bodies…   pass=admin    → matched inside a request body too
```

It is applied in SQL, so it works across the whole DB rather than the loaded
window, carries into the picker modal and every export, and the same filters
feed the Intruder. `/api/logs?body=…`, `?exclude_body=…` and `?min_length=`
are the API equivalents (`min_length` finds the fat interesting response among
a page of thin ones).

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

### Tabs and history

The Repeater keeps **multiple tabs**, stored on the server rather than in the
browser — so a refresh, or moving from your desktop to your phone mid-test,
does not lose what you were editing. **+ Tab** adds one; the **×** closes it.

Edits **auto-save as you type**, and each tab keeps its **last 50 sends** with
status and size. Click any entry to bring that response back into the viewer —
which is how you compare "before" and "after" without re-sending.

### Follow redirects

Off by default. A lab that returns `302` is usually redirecting to a login
page, and silently following it hides the redirect you are trying to test.
Tick **Follow redirects** to follow the chain and see the final URL and each
hop's status.

### Match & replace

The **Rewrite** tab holds the match-and-replace rules. These apply to
requests **as they pass through the proxy**, before they reach the server — so
the target sees the modified values. Use it to force a header on every request
instead of repeating it by hand in the Repeater forty times.

| Target | Kind | Meaning |
|--------|------|---------|
| Header | **Exact** | matches the header **name**, and sets its value (`X-Forwarded-For: 1`) |
| Header | Contains / Regex | matches inside the header **value** |
| Query / URL | any | rewrites the URL |
| Body | any | rewrites the body |

Regexes are validated when you add them, and CR/LF is stripped from
replacements — these run on the live request, so an unescaped newline there
would be request splitting. Rules are toggled per-row and take effect on new
traffic immediately. `GET/POST /api/rewrite` and
`PATCH/DELETE /api/rewrite/<id>` are the API.

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

Either the **Noise** tab in the dashboard, or the CLI:

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

Or **Noise → Scan (dry run) → Delete noise captures…** in the dashboard.
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
| `GET /api/diff/<a>/<b>` | compare two captures (`?mode=json\|token\|char`) |
| `GET /api/diff/intruder/<a>/<b>` | compare two Intruder results, same engine |
| `GET /api/intruder/status` | the running or most recent attack: progress + results so far |
| `GET /api/intruder/jobs/<id>` | one attack by id, with everything it has produced |
| `POST /api/intruder/cancel` | stop the running attack, keeping collected results |
| `GET /api/repeater/tabs` | repeater tabs (+ `history` per tab) |
| `GET /api/rewrite` | match & replace rules |
| `GET /api/wordlists` | the bundled wordlists |

All of them accept the shared filters (`host`, `exclude_host`,
`hide_static`, `highlighted_only`, `body`, `exclude_body`, `min_length`)
alongside method/status/url/id.

## Intruder tab

1. Pick a logged request — fields prefill.
2. Insert `§param§` placeholders where payloads go, e.g.
   `https://target.com/item?id=§fuzz§` or `{"user":"§user§"}`.
3. Choose a mode:

| Mode | Sends |
|------|-------|
| **Single list** | one wordlist substituted into *every* `§placeholder§` |
| **Pitchfork** | a **different** wordlist per placeholder, combined as a product |

4. **Start attack** — results are color-coded by status and stored in the DB.
5. Click **View** on a row to see the exact request sent and its full response.

**Pitchfork** is the one that solves authentication labs: `§user§` from a
username list crossed with `§pass§` from a password list. The Single list mode
cannot do it — it can only confirm that `admin` pairs with `admin`.

Switch to Pitchfork and the UI grows **one row per placeholder** it finds in
the target request. Each row takes a bundled list, a paste, or your own
upload, and the line above **Start attack** shows the product before you commit
(`2 lists → 30 requests`). Combinations are capped at 10,000; over that, shrink
a list.

### Reading the results

Attacks are sent **sequentially** — one request at a time, each waiting on the
previous response. There is no delay or rate-limit setting, and no concurrency
knob. It is gentler on a rate-limited target than a tool that fires N threads,
but you cannot slow it further; if a lab locks an account, shorten the list.

The toolbar above the results table exists because the task is reading N
responses for the one that behaved differently:

| Control | Effect |
|---------|--------|
| **Sort** | send order, response size (either direction), or status code |
| **Status** | restrict to `2xx` / `3xx` / `4xx` / `5xx` |
| **only size outliers** | keep only rows whose response length differs from the **most common** length |

**Only size outliers** is username enumeration, mechanically: a login form that
replies "Invalid password" for a real user and "Invalid username" for a fake
one gives one response of a different size. The baseline is measured across all
rows *before* filtering, so turning the filter on does not move the baseline.
When every response is the same size it says so explicitly instead of implying
there are no results.

The `#` column is the position in **send order** and does not renumber when you
sort — a number that changes when you reorder is worse than no number.

Tapping a row selects it for comparison: the first tap is **A**, the second
**B**, a third replaces the older pick. With two selected, **Compare A / B**
sends them to the **Diff tab**, using the same engine and views as a capture
comparison.

> Intruder results are stored in `intruder_results`, not in the capture table,
> and the requests are sent **directly from the dashboard rather than through
> the proxy**. Two consequences worth knowing:
> - Intruder and Repeater traffic does **not** appear in the Live or Log tabs.
> - A capture and an Intruder result cannot be compared with each other — the
>   dashboard refuses rather than diffing two unrelated things.
>
> The row ids in the two tables are separate, so the picker (`Pick…`) always
> yields captures and resets the side it fills to "capture".

### Pasting a wordlist

Wordlists live in awkward places — a notes app, a Slack thread, a Burp export,
a `curl` transcript. Making you save any of that to a file first is pure
friction, so both wordlist sources take a **paste**:

- **Single list** — a textarea next to the upload box. Parsed live, so the
  count updates as you type and clearing it clears the list.
- **Pitchfork** — a **Paste** button per row, which unfolds a box under that
  row. Press **Use list** to commit (a half-typed list would otherwise change
  the request product on every keystroke), **Cancel** to discard.

The same text produces the same wordlist whichever way it arrives, which is the
point — upload and paste share one parser:

- Newlines **and commas** separate words, so both `admin⏎root` and
  `admin, root` work.
- **Spaces do not** separate. A payload like `admin' OR '1'='1` stays one
  request instead of being shredded into three.
- Blank lines and lines starting with `#` are dropped. Wordlists copied out of
  blog posts are full of comment headers, and a leading `#` sent as a payload is
  a wasted request.
- Lists are capped at 1,000 words. Over the cap the count says what was
  dropped (`1000 words (pasted, capped from 1199)`) rather than quietly
  truncating — and it is the capped number that appears in the request total.

Only one source is live at a time, and the label next to the count names it.
Choosing a bundled card clears a pasted list, and pasting clears the selected
card, so what is on screen is always what gets sent.

### Bundled wordlists

Five curated lists ship in the package so a fresh install can attack without
hunting for a `.txt` first. Pick one with a click, or paste/upload your own:

| List | For |
|------|-----|
| **Numeric IDs** (1–100) | IDOR / broken access control enumeration |
| **Usernames** | default and lab-common account names |
| **Common passwords** | obvious defaults for auth testing (local lab use) |
| **Parameter names** | hidden-parameter discovery |
| **Ports** | SSRF and redirect validation |
| **Paths** | admin/API endpoint discovery |

`GET /api/wordlists` lists them; `?name=usernames` returns the words. They are
deliberately small and curated — a starting point, not a replacement for
SecLists.

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
