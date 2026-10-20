# Repeater

Repeater resends a captured request with changes. It is the tool for "what
happens if I change exactly one thing?".

There are two ways in, and they behave differently:

- the **Repeater modal** opened from the Live tab, for a quick edit-and-send;
- the **Repeater tab**, a full editor with multiple tabs and a send history.

The deep reference is in [Web UI → Repeater](../web-ui.md#repeater).

## Before you start: Repeater traffic is not captured

Requests sent by the Repeater are made by the dashboard process, **not through
the capture proxy**. They do not appear in the Live table, the Log tab, or an
export. They are also not affected by [Rewrite](rewrite.md), [Noise](noise.md),
or `--scope`.

This is the single most surprising thing about the Repeater. Keep it in mind:

- To compare two responses in the Diff tab, both requests must be **captures**.
  Send them through the proxy (browser or `curl -x`), not through Repeater.
- Repeater has its own per-tab history, which is where its responses live.

## Open a captured request

**What it's for.** Repeater starts from a request that already exists. Loading
it gives you the real URL, headers and body, including the session cookie the
browser sent.

**How to use it.**

1. In **Live**, click the request you want.
2. Use either:
   - **Repeater** in the detail action row — opens the modal; or
   - the **Repeater** tab → **Pick a captured request…** — opens a picker and
     fills the full editor.
3. In the picker, filter if needed: method, status, **URL contains…**,
   **Any host**, **Body contains…**, **ID: 42, 1-20, 7**.
4. Leave **Use the Live tab filters** ticked to start from the view you were
   just looking at.
5. Click a row, then **Use it**.

**Worked example.** You have just logged in to the lab and the browser is
holding a valid session cookie. Capture the `GET /my-account` request, open it
in Repeater, and the `Cookie:` header comes with it. That is the whole point:
you are editing traffic that was already authenticated.

**What to look for.** The editor fills with the method, URL, headers
(one `Key: Value` per line) and body. The label next to **Pick a captured
request…** changes to `#12 · GET https://…`.

**Common mistakes / notes.**

- The picker is **seeded from the Live filters**. If it opens empty, either the
  Live filters are too narrow or **Use the Live tab filters** should be
  unticked.
- The picker lists up to 300 captures.
- **Use it** is disabled until you click a row. The modal says
  `Selected #12` when you have.
- On a phone, the picker table is wide; the ID and method columns are on the
  left, the path on the right. Tap the row itself, not the empty space below
  the table.

## Edit and send (full tab)

**What it's for.** Change one thing — a parameter, a header, a cookie, the whole
body — and see the response.

**How to use it.**

1. Pick a request (above).
2. Edit **Method**, **URL**, **Headers (one per line: Key: Value)**, and
   **Body**.
3. Click **Send**.
4. Read the **Response** card that appears below: status, headers, body.

**Worked example.** An IDOR lab: capture `GET /account?id=1`, change the URL to
`id=2`, and click **Send**. If the response contains another user's data, you
have the bug.

**What to look for.** A status badge and the response headers/body. The status
is colour-coded the same way as Live (2xx green, 3xx purple, 4xx orange, 5xx
red). `(empty)` means the response body was empty.

**Common mistakes / notes.**

- **Headers are parsed line by line.** A line without a colon is silently
  dropped. A duplicated header name keeps the last value, because the editor
  stores headers as a simple name→value map.
- **There is no cookie jar.** Each **Send** is one independent HTTP request.
  A `Set-Cookie` from a login response is **not** applied to the next send.
  Copy the session cookie from the response into the **Headers** box yourself
  (or start from a captured request that already has it). The Intruder works
  differently: it keeps a session (see [Intruder](intruder.md#read-the-results)).
- Method, URL and body are sent as typed. Changing the URL to another host is
  allowed; Repeater does not enforce scope.
- The request is sent with TLS verification off, so self-signed lab
  certificates work. It times out after 15 seconds.
- The response body shown is text and is capped at 50,000 characters. A binary
  response may not render usefully; use the Live detail pane's **Hex** view for
  a binary body that was captured.
- The status area has no Pretty/Raw/Hex switch. This is a plain
  headers-plus-body view.

## Use tabs and history

**What it's for.** Keep several requests side by side and keep a record of what
you sent. Tabs and history are stored on the server, so a refresh or a switch
from laptop to phone does not lose them.

**How to use it.**

1. Open the **Repeater** tab.
2. Click **+ Tab** to create a tab. The URL field is focused.
3. Click a tab name to switch. Tabs are labelled `Tab 1`, `Tab 2`, and so on
   (or with the URL if one was set at creation through the API).
4. Click the **×** on a tab to close it. Closing deletes that tab's history.
5. Edit as usual. Edits auto-save about half a second after you stop typing.
6. After a send, open **History (newest first)** and click an entry to bring
   that response back into the viewer.

**Worked example.** Use **Tab 1** for "user A's session" and **Tab 2** for
"user B's session", each with its own cookie. Send the same `id=2` request from
both and compare the two histories. Or keep one tab per parameter you are
probing, so you do not lose the original.

**What to look for.** The active tab is highlighted. The history row shows the
status, method and URL, size, and either the time or the error. Clicking a
history row reloads that exact response, even if the request has changed since.

**Common mistakes / notes.**

- If you delete every tab, a fresh `Tab 1` is created immediately. You cannot
  have zero tabs.
- History keeps the **last 50 sends per tab**. It is a comparison aid, not an
  archive.
- The history size is the response body's character count, not bytes.
- Auto-save is debounced. If you type and immediately close the browser, the
  last few hundred milliseconds may not be saved.
- Tabs are not deleted by the Live tab's **Clear captures**. They are separate
  from the capture database's request rows.

## Replaying an upload (multipart bodies)

If the captured request is a file upload — a `POST` whose content type is
`multipart/form-data` — two things must both be right or the server answers
with a missing form field:

1. **Line endings must be CRLF.** The parts of a multipart body are delimited by
   `CRLF--boundary`. A browser textarea silently converts CRLF to LF, which
   breaks that framing. The Repeater now restores CRLF automatically for
   multipart bodies (detected from the content type, or from a body that starts
   with `--`), so nothing to do.
2. **Do not hand-edit `Content-Length`.** A captured length describes the body
   you captured; the moment the body changes — an edited filename, a longer
   payload — the old value is wrong. Too small and the server reads only part of
   the body and stops mid-boundary; too large and it waits for bytes that never
   come. The Repeater and the Intruder now drop it and let the HTTP client
   compute the real length.

**Symptom of both.** The response is a `400` saying something like
`Missing parameter 'csrf'`, even though the `csrf` value is visibly in the body.
It is the *last* part in the body, so it is the first thing lost when the length
is short.

**Checking.** Open **View → Request sent**; the body should end with
`--<boundary>--`. If it ends mid-boundary, the length was short.

## Follow redirects

**What it's for.** By default, Repeater stops at the first response. That is
usually what you want on a lab, because the `302` is the finding. When you need
to see the destination, tick **Follow redirects**.

**How to use it.**

1. Tick **Follow redirects** next to **Send**.
2. Click **Send**.
3. Read the final response in the **Response** card.

**Worked example.** A login returns `302` with a `Location` header. Tick
**Follow redirects**, send again, and read the final page body to see whether
you landed on `/my-account` or back on `/login`.

**What to look for.** The status changes from `302` to whatever the final hop
returned (often `200`), and the body is the destination page.

**Common mistakes / notes.**

- **The dashboard shows the final response, not the redirect chain.** The
  server returns each hop (status, URL, `Location`) in its JSON, but the
  dashboard does not render that list. For the chain, leave the box unticked
  and read the `Location` header, or use `curl -i` with `Copy curl`.
- Following redirects can cross to another host. Repeater does not restrict
  that.
- The Repeater **modal** has no follow-redirects control. Only the full tab
  does.

## Compare with a capture

**What it's for.** The **Compare…** button in the Repeater is a shortcut into
the Diff tab.

**How to use it.**

1. Select a captured row in **Live** first. This is the capture that will
   become **A**.
2. Open the **Repeater** tab and click **Compare…**.
3. The Diff tab opens with **A** set. Choose **B**.

**Worked example.** You have a baseline capture for `id=1` and you are about to
try `id=2` in Repeater. Select the `id=1` capture in Live, click **Compare…**,
then pick another capture as **B**.

**What to look for.** The Diff tab opens with the first capture named next to
**A**.

**Common mistakes / notes.**

- **It does not compare the Repeater's last response.** The button uses the
  capture currently selected in **Live**. If nothing is selected, it says
  `Select a captured row in Live first`.
- Repeater responses are not captures, so they cannot be a Diff side at all.
  To diff two responses, send both through the proxy.

## Use the Repeater modal instead

**What it's for.** A quick send without leaving the Live tab. It is the same
endpoint as the full tab, with fewer controls.

**How to use it.**

1. Select a row and click **Repeater** in the detail action row, or choose
   **Repeater** from the **⋮** menu.
2. Edit method, URL, headers and body in the modal.
3. Click **Send (Ctrl+S)**, or press **Ctrl+S**.
4. Read the response on the right.
5. Press **Esc**, click **Close (Esc)**, or click the dark backdrop to close.

**Worked example.** You are scanning the Live table and spot a request with a
suspicious `role=user` body. Open the modal, change it to `role=admin`, send,
and read the response without losing your place in the table.

**What to look for.** `status 200` (or another code) in the response header
area, then headers and body in the output pane.

**Common mistakes / notes.**

- The modal has **no tabs**, **no history**, and **no follow-redirects**.
- The modal does not auto-save. Closing it discards your edits; the original
  capture is unchanged.
- On a phone, the modal fills most of the screen and its two columns stay side
  by side, so it can feel cramped. Use the full tab, or rotate the phone.
- **Ctrl+S** is a keyboard shortcut. On a phone, tap the **Send (Ctrl+S)**
  button.
- Like the full tab, the modal sends directly and the exchange is not captured.

Next: [Intruder](intruder.md).
