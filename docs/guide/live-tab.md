# The Live tab

The **Live** tab is the main screen: a capture table on one side, the details
of the selected request on the other. Almost every other feature starts here.

The full reference, including the API behind each control, is in
[Web UI](../web-ui.md#live-tab-mirrors-the-tui). This page is the "what do I do
with it" version.

## Read the capture table

**What it's for.** This is the list of requests that have passed through the
proxy, newest first. It is how you find the request you care about.

**How to use it.**

1. Send some traffic through the proxy (see [Getting started](getting-started.md)).
2. Look at the top of the **Captured requests** table. New rows appear within
   about two seconds.
3. Read the columns: **ID**, **Method**, **Status**, **Size**, **Host**,
   **Path**, and a **⋮** button at the end of each row.
4. Click (or tap) a row to select it. The detail pane fills in.
5. Read the count in the card header: `12 captures`, or `3 of 40 shown` when an
   in-page filter is hiding some of the fetched rows.

**Worked example.** On the Web Security Academy login lab, submit the login
form once. In **Live**, find the `POST /login` row. Its status tells you what
the server said (`200` for a rendered page, `302` for a redirect), and its
size tells you whether the response is a full page or a short error.

**What to look for.**

- A new row with the real method, not `CONNECT`.
- A status you can explain: green 2xx, purple 3xx, orange 4xx, red 5xx.
- A **Path** that matches the endpoint you just used.
- The row's tooltip (desktop hover) shows the full URL.

**Common mistakes / notes.**

- **Size is not wire bytes.** It is the recorded response-body length in
  characters, labelled `B`/`K`/`M`. A page full of non-ASCII text is larger on
  the wire than the number suggests. `—` means no body was stored (common for
  images, JS, CSS and other static assets, which are streamed without capture).
- **Pending and errors look different.** A request with no response yet shows
  `…` in Status. A transport failure shows `ERR` (stored as code `0`; the
  reason is in the Response tab as `(transport error: …)`).
- The **Host** column drops a leading `www.`, `m.`, `mobile.` or `amp.`, and
  strips the port. The full host is in the tooltip. The **Path** includes the
  query string, dimmed after `?`.
- **On a phone there is no hover**, so the tooltip is not available. Use the
  request line in the detail pane for the full URL.
- The table polls with the current filters and asks for the newest **200**
  matching rows. The header count is that fetched window, not the database
  total: 5,000 matches still read as `200 captures`. If you are looking for
  older traffic, filter first, use the **Log** tab (500 rows), or export.
- Rows are pruned automatically at the default limits (5,000 rows / 7 days /
  50 MB). Do not treat this as a permanent archive.
- Selecting text with a mouse or finger is safe: the table does not repaint
  while you hold a selection, and it never repaints when nothing changed. You
  can drag-select a value and copy it.

## Narrow the list with filters

**What it's for.** A browser session produces far more requests than the lab
does. Filters cut the table down to the part you are working on. They are
applied in the database, so they also apply to exports and the Log tab, and
they seed the request picker.

**How to use it.**

1. Use the controls above the table, left to right:
   - **All hosts** — focus one host (see below).
   - **Method: All** — exact method (`GET`, `POST`, …).
   - **Status: All** — `2xx`, `3xx`, `4xx`, `5xx`, `Errors` (code `0`,
     transport failure), or `Pending` (no response yet).
   - **Filter by URL substring…** — case-insensitive, anywhere in the full URL.
   - **Search bodies…** — see [Search bodies](#search-bodies).
   - **ID: 42, 1-20, 7** — exact IDs and inclusive ranges, comma- or
     space-separated. Reversed ranges such as `200-100` are accepted.
2. Combine filters freely. They are ANDed.
3. Clear a box or set a dropdown back to `All` to undo that filter.

**Worked example.** You are testing `https://lab.example` but the browser is
also talking to its update server. Set **All hosts** to `lab.example`, set
**Status: All** to `4xx`, and you have a short list of the lab's rejected
requests, such as the failed login you are about to investigate.

**What to look for.** The card header shows `12 captures` when everything
fetched is shown, or `3 of 40 shown` when an in-page filter is hiding some of
the fetched rows. An empty table has two possible messages:

- `Waiting for traffic…` — nothing was fetched. This also happens when the
  server-side filters match nothing, not only when capture is broken.
- `No matching requests — every captured row is filtered out. Turn off a chip
  above.` — rows were fetched but an in-page filter (for example the chips)
  hides them.

Do not read either message as proof that capture stopped. Check the proxy dot
and the filter bar first.

**Common mistakes / notes.**

- The URL box matches the **whole URL**, including the host and query string.
- The ID range is inclusive. `42` matches only capture 42.
- Method, status, URL, ID, host, body search **and both chips** are remembered
  in the browser across refreshes. A host you were focused on is restored too,
  even if it has since dropped out of the picker's top 60. The active tab and
  the selected capture are also restored.
- Clearing a filter does not delete anything.
- **Rewrite…** and **Noise…** in this row are shortcuts to their tabs. They do
  not change the current filter.

## Focus one host

**What it's for.** One target, one click. This is the fastest way to drop
browser noise without deleting it.

**How to use it.**

1. Open the **All hosts** dropdown at the left of the filter bar.
2. Each entry shows the host and its capture count, for example
   `lab.example (27)`.
3. Pick one. The table narrows to that host (the filter is a case-insensitive
   host match; the list contains full hosts, so picking one shows just that
   host).
4. Set it back to **All hosts** to see everything again.

**Worked example.** After ten minutes of browsing, `pocket-image-cdn...`
has 60 captures and your lab has 12. Pick the lab host. You are now looking at
the 12 rows that matter, with no cleanup.

**What to look for.** The count in the header drops, and the busiest-host hint
on the right of the filter bar stops naming the host you selected.

**Common mistakes / notes.**

- The dropdown lists up to the 60 busiest hosts and refreshes about every 15
  seconds. A host with very few captures may not be listed; use the URL filter
  for that.
- The counts describe the recent captures in the database, not the current
  filtered view.
- Focusing a host is a view filter. It does not stop future captures. For that,
  add a [noise rule](noise.md#layer-1-drop-hosts-at-capture-time).

## Hide static assets

**What it's for.** Images, fonts, CSS, JS and media make up most of a modern
page and almost none of a lab's interesting traffic. This chip hides them.

**How to use it.**

1. Tick **Hide static** above the table.
2. Untick it to bring them back.

**Worked example.** A lab page loads 40 JS chunks and four fonts. Tick **Hide
static** and the API calls (`/api/...`, form posts, JSON) are what remain.

**What to look for.** The row count falls, and the remaining rows are document
or API responses rather than `.js`, `.css`, `.png` and `.woff2` requests.

**Common mistakes / notes.**

- **Content type wins over the filename.** An endpoint called
  `/api/image.png` that returns `application/json` is treated as API traffic
  and stays visible. That is deliberate: hiding it on the filename alone could
  hide a bug. Only when no content type was recorded does the extension decide.
- Hiding does not delete. The rows are still in the database and still appear
  in an export unless **Hide static** is ticked when you export.
- Bodies for the usual static content types are not stored at all, so they
  cannot be found with body search and their **Size** is usually `—`.
- Capture-time noise rules do **not** drop static assets. Static filtering is a
  view/cleanup concept.

## Search bodies

**What it's for.** The URL does not contain the flag, the token, or the leaked
value. This box searches the request body **and** the response body, across the
whole database, and it is usually the fastest way to find the one response that
matters.

**How to use it.**

1. Type into **Search bodies…** above the table.
2. Wait a moment; the database is queried after a short debounce.
3. Combine it with **All hosts** and **Hide static** to keep the result short.

**Worked example.** A lab hints that a support page leaks a password reset
token. Type `token` in **Search bodies…**, focus the lab host, and open the
responses that contain it. To find a flag, search for `CTF{`, `flag{`, or the
prefix the lab uses.

**What to look for.** Rows whose request or response body contains the text.
Open the **Response** detail tab and use the **Pretty** view to read it.

**Common mistakes / notes.**

- It matches the **stored** body only. Bodies are capped at 100,000 characters
  by default, so text beyond the cap cannot match.
- Non-API content types are streamed without body capture, so an image or a JS
  bundle will never match even if it contains the string.
- It does not search notes, headers, or the URL. Use **Filter by URL substring…**
  for the URL.
- The search is case-insensitive and literal; it is not a regex.
- The same text carries into the request picker and into exports, which is
  usually what you want and occasionally surprising.

## Show only highlighted captures

**What it's for.** Once you have marked the interesting rows, this hides
everything else.

**How to use it.**

1. Highlight at least one capture (see [Highlight a capture](#highlight-a-capture)).
2. Tick **Highlighted** above the table.
3. Untick it to see everything again.

**Worked example.** You are testing five endpoints and have found three
responses worth a second look. Highlight them in different colours, tick
**Highlighted**, and your working set is the whole table.

**What to look for.** Only rows with a coloured left bar remain, and the count
drops accordingly.

**Common mistakes / notes.**

- A note does **not** count as a highlight. Use a colour.
- Clearing a highlight removes the row from this view immediately.
- **The chip is remembered across a refresh**, like the other filters.

## Resize or hide the detail pane

**What it's for.** Sometimes you want a wide request table; sometimes you want
a wide response body. The divider between the panes controls that.

**How to use it.**

1. Drag the vertical divider left or right to resize.
2. **Click the divider** (without dragging) to collapse the detail pane and
   give the table the full width. Click again to bring it back.
3. With the divider focused, the **←** / **→** keys resize and **Enter** or
   **Space** collapses or expands.
4. The width and collapsed state are remembered after a refresh.

**Worked example.** On a laptop, drag the divider left to give a JSON response
more room while you read a long token. On a phone, tap the divider to hide the
detail pane while you scan the table, then tap it again to inspect a row.

**What to look for.** The detail pane disappears and the table takes the full
width. The divider stays visible as a thin bar so you can bring it back.

**Common mistakes / notes.**

- The drag uses pointer events, so mouse, touch and pen all work.
- If you drag and release, the click that follows does not also collapse the
  pane; that is deliberate.
- On a narrow screen the panes stack vertically and the divider becomes a
  horizontal bar. The detail pane is **below** the table. After tapping a row,
  you may need to scroll down or expand the divider to see it.

## Read a request and a response

**What it's for.** The detail pane shows exactly what was sent and what came
back: the request line, headers, body, response headers, response body, and
timing.

**How to use it.**

1. Select a row in the table.
2. Read the meta line at the top: `#12 · POST · 302 · ttfb 84ms · total 120ms`
   followed by the full URL.
3. Use the four detail tabs: **Request**, **Response**, **Intruder**, **Note**.
4. In **Request**, the top block is the request line and headers; below it is
   the body.
5. In **Response**, the top block is the response headers; below it is the body.
6. Switch the body view with **Pretty**, **Raw**, or **Hex**. The choice is
   remembered separately for request and response.

**Worked example.** A login returns a `302`. Open **Response** and read the
`Location` header. Is it redirecting to `/my-account` (success) or back to
`/login` (failure)? That one header often decides the lab.

**What to look for.**

- **Pretty**: JSON is re-indented. Anything else is shown as received.
- **Raw**: control characters and non-ASCII are escaped (`\n`, `\t`, `\x00`,
  `\u00a7`), so you can see what a decoder did or a filter stripped.
- **Hex**: a classic dump. 16 bytes per row, with a hex offset column and an
  ASCII gutter. All-zero rows are dimmed. Offsets are hexadecimal.
- The hint under the view buttons reports the size, and warns when the body
  looks binary.
- `(pending — response not captured yet)` means the response has not arrived.
  `(transport error: …)` means it never will; the reason is on that line.

**Common mistakes / notes.**

- **Bodies are truncated by default.** The request and response bodies are
  stored up to 100,000 characters. The meta line and the body show
  `⚠ truncated` with the original size when that happened. A diff or a search
  only sees the stored part.
- **Pretty does not syntax-highlight and does not decode anything.** It only
  re-indents valid JSON. If the body is form-encoded, you see it as one line;
  use **Raw** to see the separators.
- **Hex is plain text.** It is selectable and copyable, but it is a rendering,
  not a file download.
- The **Copy** button next to the body view copies the raw body text (not the
  escaped or hex rendering).
- Switching rows keeps the view you chose. If a response looks like a single
  long line, check whether you left **Raw** selected.

## Copy or save what you found

**What it's for.** Get a request out of the dashboard: replay it in a
terminal, keep a response as a file, or paste it into a report.

**How to use it.**

1. Select the capture.
2. Under the detail tabs, click one of:
   - **Copy curl** — a complete `curl` command with the method, URL, original
     headers and body.
   - **Copy body** — the response body to the clipboard.
   - **Save body…** — download the stored response body to a file.
3. For a one-off body download you can also use **Export ▾ → Selected response
   body (#N)**.

**Worked example.** You found an IDOR response and want it as evidence. Click
**Save body…**; the browser downloads the body with an extension chosen from
the content type (`json`, `html`, `txt`, `png`, …). For a reproducible request,
click **Copy curl** and paste it into a terminal.

**What to look for.** A toast at the bottom of the screen (`curl command
copied`, `response body copied`, `Downloading body for #12…`). The downloaded
file opens in the right application.

**Common mistakes / notes.**

- **Copy curl does not add a proxy flag.** The command goes straight to the
  target, which is usually what you want for a reproduction. Add
  `-x http://127.0.0.1:8080` yourself if you want it captured again.
- **Copy body needs a response body.** On a static asset or a pending row it
  says `No response body captured`.
- **Save body… falls back to the request body** when there is no response body.
  It saves whatever is stored; it cannot recover a body that was truncated or
  never captured.
- The filename is derived from the URL; it is not a timestamped archive name.

## Write a note

**What it's for.** A note is a sentence to your future self: why this capture
matters, what you tried, what you expect. It is stored with the capture, not in
the browser.

**How to use it.**

1. Select a capture.
2. Open the **Note** detail tab, or click **Note** in the action row, or choose
   **Add note…** from the **⋮** menu.
3. Type into the box (the placeholder is
   `Why this capture matters — it survives restarts and is searchable.`).
4. Click **Save note**.
5. Watch the small state text next to the button: `unsaved…`, then `Saved ✓`.

**Worked example.** On a lab where `id=2` returns another user's basket, select
that response, open **Note**, and write `IDOR: id=2 returns alice's basket;
compare with id=3`. Later, the row shows a 📝 after its path so you can spot it
in a long table.

**What to look for.** `Saved ✓` and a 📝 marker after the path in the table.
The note survives a refresh, a proxy restart, and a different browser.

**Common mistakes / notes.**

- **Notes are capped at 4,000 characters.** Longer text is silently cut.
- **The body search does not search notes.** The placeholder says
  "searchable", but **Search bodies…** only covers request and response
  bodies. Use the **Highlighted** chip or the 📝 marker to find noted rows.
- A note and a highlight are independent. Saving one never clears the other.
- The background refresh will not overwrite a note you are still typing; it
  waits until the field is not focused or has been saved.

## Highlight a capture

**What it's for.** A Burp-style colour marker on a row, so you can group
findings and filter to them later. It is stored with the capture.

**How to use it.**

1. Open the **⋮** menu on a row, or click **Highlight…** in the detail action
   row, or use the **Highlight** swatches in the **Note** tab.
2. Pick one of the eight colours: red, orange, yellow, green, cyan, blue,
   magenta, pink.
3. Pick **Clear** to remove the highlight.
4. Tick **Highlighted** above the table to see only marked rows.

**Worked example.** Give every response that looks like another user's data a
red highlight, and every "maybe" an orange one. At the end of the session,
tick **Highlighted** and your shortlist is the table.

**What to look for.** A coloured left bar and a faint tint on the row. The
**Highlight…** button changes to **Highlighted ✓** for the selected capture.

**Common mistakes / notes.**

- Colours have no built-in meaning. Decide a convention for the session and
  stick to it.
- The palette is fixed and validated by the server. A colour outside the eight
  is rejected (the API returns an error); the UI only offers the eight.
- Highlights live in the database, so they survive restarts. They are not
  browser local storage.
- The tint is deliberately faint so the path stays readable. If you need a
  stronger signal, use the **Highlighted** filter instead of hunting for a
  colour.

## Use the ⋮ row menu

**What it's for.** One touch target per row that works everywhere, including
Android, where right-click does not exist. It is where a row's actions live.

**How to use it.**

1. Tap **⋮** at the end of the row. The column is pinned to the right edge, so
   it stays visible when the table scrolls sideways on a phone.
2. The popover shows:
   - **Highlight capture** — the eight colours and **Clear**.
   - **Add note…** — selects the row and jumps to the **Note** tab.
   - **Repeater** — opens this request in the Repeater modal.
   - **To Intruder** — loads it into the Intruder tab.
   - **Compare** — opens the Diff tab with this capture as **A**.
3. Tap outside the popover (or press **Esc**) to close it.

**Worked example.** You spot a promising `GET /admin` in the table. Tap **⋮**,
tap **Repeater**, change nothing, and press **Send** to see whether the
response changes on a second request. Then close it, tap **⋮** again, and
**To Intruder** when you are ready to enumerate something.

**What to look for.** The popover appears anchored near the row and stays
inside the screen on a narrow phone. Actions produce a toast or switch tabs.

**Common mistakes / notes.**

- The **⋮** menu is the only context menu. There is no right-click menu on
  desktop either.
- The popover closes on scroll and on resize.
- **To Intruder copies the captured request; it does not add `§` markers.**
  This matters: read
  [Intruder](intruder.md#before-you-start-mark-where-the-payload-goes)
  before you rely on it.
- **Compare** sets only **A**. You still choose **B** in the Diff tab.

## See Intruder results for a capture

**What it's for.** The **Intruder** detail tab shows the fuzzing results that
belong to the selected base request, without leaving the Live tab.

**How to use it.**

1. Select the capture you used as the Intruder target.
2. Open the **Intruder** detail tab.
3. Read one line per result:
   `payload=…  status=…  ttfb=…ms  len=…`.

**Worked example.** You fuzzed `id=§id§` on `GET /account`. Select the original
`/account` capture and open **Intruder** to see the status and length of every
payload at a glance.

**What to look for.** One line per payload, in send order. If nothing appears,
the tab says `(no intruder results for this request)`.

**Common mistakes / notes.**

- This tab only shows results for **this** capture ID. Select the base request,
  not one of the fuzzed responses (those are not in the capture table).
- Results live in their own table. They do not appear in the Live table, the
  Log tab, or exports.
- Clearing captures deletes Intruder results too.
- The `len` value is the response body's character count, not bytes.

## Browse the Log tab

**What it's for.** A compact history view with a larger window than the Live
table. It is the same data, with the same filters.

**How to use it.**

1. Click **Log** in the tab bar.
2. Click **Refresh** if you want the newest rows immediately.
3. Read the rows: ID, time, method, host, path, status.
4. Click a row to open that capture in **Live**, selected.

**Worked example.** You remember a request from earlier but the Live table has
moved on. Open **Log**, set the Live filters to the host you care about first
if the list is long, then click the row. You land back in Live with the detail
pane already filled.

**What to look for.** Up to 500 rows matching the current Live filters, newest
first. A highlighted capture keeps its colour bar here too.

**Common mistakes / notes.**

- **The Log tab uses the Live filters.** If Live is focused on one host, Log is
  too. An "empty" Log is usually a filter, not data loss.
- It loads 500 rows, not the whole database.
- It refreshes when you open it, not on a timer. Click **Refresh** after new
  traffic.
- On a phone the row is wide; the host and path share the URL space, so read
  the two columns together.

## Export or clear captures

**What it's for.** Export gives you a copy of the current view (or the whole
database). Clear resets the lab by deleting all captures.

**How to use it.**

1. Set the filters to exactly the rows you want.
2. Click **Export ▾** in the header.
3. Choose a format:
   - **HAR 1.2 (.har) — DevTools / Burp**: import into browser DevTools,
     Burp, or another tool.
   - **MiniProxy JSON (.json)**: the raw capture rows.
   - **SQLite snapshot (.db)**: a consistent copy of the whole database.
   - **Selected response body**: the body of the selected row (disabled until
     a row is selected).
4. To delete everything, click **Clear captures** and confirm.

**Worked example.** At the end of an IDOR lab, set **Highlighted** so only your
findings are shown, then **Export ▾ → HAR 1.2**. The HAR contains exactly the
marked rows, ready to attach to a report. When you start the next lab, use
**Clear captures** rather than a new install.

**What to look for.** A file download, plus a toast such as
`Exporting HAR…`. The HAR/JSON export respects every current filter, including
the ID filter. The SQLite snapshot is always the whole database.

**Common mistakes / notes.**

- **HAR and JSON exports are capped.** The dashboard asks for the default of
  1,000 rows (the API accepts up to 10,000). If you have more matches, narrow
  the filters and export in slices. The SQLite snapshot is not capped.
- **The SQLite snapshot is the whole database**, not the filtered view. It
  contains every capture, including noise.
- **Clear captures deletes every capture and every Intruder result**, not just
  the filtered rows, and it cannot be undone. It does not delete Repeater tabs
  or their history, Noise or Rewrite rules, or saved devices.
- Exporting does not stop the proxy, and clearing does not stop it either.
- A HAR import shows the bodies that were stored. Truncated bodies stay
  truncated.

Next: [Repeater](repeater.md).
