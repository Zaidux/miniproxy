# Intruder

Intruder sends the same request many times, substituting a word from a list
each time. It is for repetitive, boring work: trying every username, every
password, every numeric ID, or every parameter name.

There are two modes:

- **Single list** — one wordlist, and each word is substituted into every
  `§placeholder§`.
- **Pitchfork** — a different wordlist per placeholder, combined as a product
  (usernames × passwords).

The reference material is in [Web UI → Intruder](../web-ui.md#intruder-tab).

## Before you start: mark where the payload goes

Read this before your first attack, or you will send the same request 500
times and wonder why nothing changed.

**The attack runs against what is in the Intruder tab's text boxes.** When you
click **Start attack** the dashboard sends the Method / URL / Headers / Body
exactly as you typed them, and the server substitutes each word into the
`§placeholder§` markers it finds there.

This was not always true. The server used to ignore the boxes and reload the
*stored capture* instead, which quietly discarded every edit you made — the
count would look perfect and every single request would be identical. If you
are following older advice that says you must build the request with `curl`,
you do not need to any more: type the markers in the tab.

### Adding markers

Put `§name§` wherever a payload should go. The name is yours — `user`, `pass`,
`id`, anything — and it is what the Pitchfork rows will be named.

In the **URL**:

```
https://target.com/login?username=§user§&password=§pass§
```

In the **Body** (if the login is a form POST):

```
username=§user§&password=§pass§
```

In a **Header**, if that is where the value lives:

```
Authorization: Bearer §token§
```

`§` is just a marker character this tool looks for. There is nothing to enable
and nothing to escape.

**On a phone, use `{{name}}` instead.** The two are interchangeable everywhere —
`?user={{user}}&pass={{pass}}` behaves exactly like the `§` form. Braces are
easy to type on any keyboard; `§` is not, and cannot be typed into a browser
address bar at all. The Intruder rewrites them to the canonical form before
anything else reads the request.

**You must still pick a captured request first.** The boxes start out filled
from a capture, and the attack is stored against that request's ID — so pick a
request, then edit the boxes freely.

**If you forget a marker**, **Start attack** stops and tells you, rather than
firing a wordlist of identical requests. The server enforces this too, so a
stale browser tab cannot slip one through.

### Checking it worked

Look at the **URL** column of the first two results, or press **View** on a
result and read **Request sent**. If the payload appears where the marker was,
substitution is happening.

**If every request was identical, the results table says so** — it puts a line
under the toolbar reading *"All N requests were identical — no payload was
substituted, so the wordlist was ignored."* The whole request is compared (URL,
body and headers), so a login whose marker is in the body is not flagged
wrongly. A table full of identical rows is otherwise easy to mistake for a
finished attack.

### Common mistakes / notes

- **Reload the dashboard after an upgrade.** A tab opened before the upgrade
  keeps running the old page, and older builds discarded the Intruder boxes
  entirely — the attack would target the stored capture and quietly send the
  same request N times. If results look identical or your edits seem ignored,
  reload before assuming the tool is broken.
- The **To Intruder** button (detail pane and **⋮** menu) copies a capture
  into the boxes so you can edit from there. It does not add markers for you.
- The same marker name can appear more than once and is substituted in every
  spot — `§user§` in both the URL and a header is fine.
- In **Single list** mode one wordlist is substituted into *every* marker, so
  `§user§` and `§pass§` both get the same word. Use **Pitchfork** if the two
  positions need different lists.
- A browser percent-encodes `§` in a URL (`%C2%A7`), so typing it into the
  address bar of a real browser does not produce a marker. Type it in the
  Intruder boxes instead — they are not a browser address bar.

## Pick the target request

**What it's for.** Choose which captured request the attack will be built from.

**How to use it.**

1. Open the **Intruder** tab.
2. Under **1 · Target**, click **Pick a captured request…**.
3. Filter the picker if needed (the same filters as Live, seeded from Live).
4. Click a row, then **Use it**.
5. Check the **Request (use §param§ in fields)** boxes: the method, URL,
   headers and body are filled from the capture. Put your `§markers§` in
   them — these boxes are what the attack actually sends.

**Worked example.** For an IDOR enumeration, capture `GET /account?id=1` while
logged in, then pick it here. The URL should look like
`https://lab.example/account?id=1`. To fuzz it you need the capture to contain
`id=§id§`; create that capture with `curl` as described above.

**What to look for.** The label next to the button shows
`#12 · GET https://…`, and the fields match the request you intended.

**Common mistakes / notes.**

- Only captures can be targets. Repeater responses are not captures.
- The picker respects the Live filters. If it opens empty, untick **Use the
  Live tab filters** or widen the Live filters.
- The **Method** dropdown lists GET/POST/PUT/DELETE/PATCH only. The stored
  request's method is what is actually sent.
- Results are attached to this capture ID. Delete the capture (or let pruning
  remove it) and its Intruder results go with it.

## Single list mode

**What it's for.** One list of words, one request per word, each word placed
into every `§placeholder§`. This is the mode for "try these 100 IDs" or "try
these 40 parameter names".

**How to use it.**

1. Select a target (above).
2. Click **Single list**. The hint reads
   `One wordlist, substituted into every §placeholder§.`
3. Supply the list in one of three ways:
   - **Paste** into the box under
     `Wordlist — paste, upload .txt, or pick a bundled list below`.
     It is parsed as you type; no confirm button.
   - **Upload** a `.txt` with **or upload a .txt**.
   - Click one of the bundled cards.
4. Read the count next to the words, for example `100 words (Numeric IDs)`.
5. Read the line above the button: `100 requests queued`.
6. Click **Start attack**.

**Worked example.** IDOR enumeration. Create a capture containing
`?id=§id§`, choose the **Numeric IDs** card (1–100), and start. One hundred
requests go out, each with a different `id`.

**What to look for.** `N requests queued` equals the number of words. A status
code and a size for each result, and at least one row whose status or size does
not match the rest. That outlier is the account you are not supposed to see.

**Common mistakes / notes.**

- **Spaces inside a word are kept.** `admin' OR '1'='1` stays one payload
  instead of being split into three.
- **Newlines and commas separate words.** Both `admin` + Enter + `root` and
  `admin, root` work. A comma **inside** a structured payload is part of the
  payload, though: `{"user":"admin","pass":"x"}` stays one word, because
  splitting it would send two malformed requests.
- Lines starting with `#` are ignored, and blank lines are dropped. This is
  deliberate: wordlists copied from blog posts are full of comment headers.
- **The list is capped at 1,000 words.** Over the cap, the label says
  `1000 words (pasted, capped from 1199)` and it is the capped number that is
  sent.
- **The count label names the source that is actually live**, so trust it over
  the boxes. Choosing a bundled card clears the paste box, and pasting clears the
  file input. But an upload does not clear the paste box, and a bundled card
  does not clear the file box, so you can see a stale filename or text that is
  not what will run. The label (`100 words (Numeric IDs)`, `3 words (pasted)`,
  `12 words (my-list.txt)`) is the truth.
- A bundled list is a starting point, not a replacement for SecLists. The six
  lists are deliberately small.

### Bundled wordlists

| Card | Words | Use it for |
|------|-------|------------|
| **Numeric IDs** | 1–100 | IDOR / broken access control enumeration |
| **Common usernames** | 31 | auth labs: default and lab-common names |
| **Common passwords** | 26 | obvious defaults for auth labs |
| **Parameter names** | 40 | hidden-parameter discovery |
| **Common ports** | 30 | SSRF and redirect validation |
| **Common paths** | 39 | admin/API endpoint discovery |

## Pitchfork mode

**What it's for.** A different list per placeholder, combined as a product.
This is the mode that solves authentication labs: one list of usernames crossed
with one list of passwords.

**How to use it.**

1. Make sure the target request contains at least two named markers, for
   example `username=§user§&password=§pass§`.
2. Click **Pitchfork**. The hint reads
   `A different wordlist per placeholder — e.g. usernames × passwords.`
3. The tab grows **one row per placeholder** it finds in the URL, body and
   headers. Rows are alphabetical. If you add or remove a marker afterwards the
   rows update on their own — the empty state's *"add some and they appear
   here"* is literal, not an instruction to toggle the mode. There is no need
   to leave Pitchfork and come back.
4. For each row, choose a source:
   - pick a bundled list from `— choose a bundled list —`;
   - upload a `.txt`;
   - or click **Paste**, type into the box that unfolds, then click
     **Use list** (or **Cancel** to discard).
5. Read each row's count, for example `31 words (Common usernames)`.
6. Read the product line:
   `2 list(s) → 806 requests` and, under it,
   `Lists combine as a product: 31 × 26 = 806 requests.`
7. Click **Start attack**.

On a phone, each row's controls stack: the marker, its word count and **Paste**
stay on the first line, and the list picker and file box move below.

**Worked example.** Password guessing on a lab login. The captured body is
`username=§user§&password=§pass§`. Pick **Common usernames** for `§user§` and
**Common passwords** for `§pass§`. 31 × 26 = 806 requests. The result you want
is the one whose status or body size differs: usually a `302` to
`/my-account` while the failures return `200` with the login page.

**What to look for.**

- One row per marker, with the word count you chose.
- The product line equals the multiplication, and matches the pending count in
  the Results header.
- The **Payload** column labels each result like `user=alice | pass=secret`,
  so you can identify the winning pair without opening anything.

**Common mistakes / notes.**

- **Markers without a list are replaced with an empty string**, not left as
  literal text. If you configure `§user§` but leave `§pass§` at `0 words`, the
  request goes out with `password=` and no value. Configure every marker you
  care about.
- The rows are derived from the markers in the URL, body and headers (not the
  method). These are the boxes the attack sends, so editing them changes the
  attack; see [mark where the payload goes](#before-you-start-mark-where-the-payload-goes).
- **The combined limit is 10,000 requests.** The line above **Start attack**
  warns when you are over; the server refuses with
  `pitchfork would send N requests (max 10000) — shrink a list`.
- Each list from the UI is capped at 1,000 words by the shared parser.
- The paste box in a row starts with that row's current words, so pasting over
  a bundled list starts from what is there. **Use list** commits; **Cancel**
  discards and empties the box.
- Re-rendering the rows (for example after editing a marker) keeps the lists
  you already chose for markers that still exist, and drops the ones that do
  not.
- Pitchfork is not "cluster bomb". It does not try every combination of every
  list in a different order; it is the Cartesian product of the lists you
  provide, and the payload label names each position.

## Start, watch, and wait

**What it's for.** Run the attack and know when it is safe to read the results.

**How to use it.**

1. Click **Start attack**.
2. The button changes to **Running…** and is disabled.
3. Watch the **Results** card header: it shows `0 / N requests` while the attack
   runs, then `N requests` when the table appears. It is not a smooth
   per-request progress bar (see the note below).
4. When the run finishes, the full table appears and the button returns to
   **Start attack**.

**Worked example.** A 100-ID enumeration on a lab takes a few seconds. An
806-request pitchfork against a slow lab can take minutes, because requests are
sent one at a time.

**What to look for.** The button returns to **Start attack** and the results
table is populated. If the attack failed, an alert names the error
(`Attack failed: …`).

**Common mistakes / notes.**

- **Only one attack can run at a time.** Starting a second one while the first
  is running is refused (`an attack is already running`).
- **Progress is coarse.** The counter can sit at `0 / N` for the whole run and
  then the header switches to `N requests` when the table appears. The server
  reports progress when the run finishes, not per request. A still counter does
  not mean a hung attack. Give it time.
- **Results are not streamed.** The table is rendered when the attack
  completes, not per response.
- **Requests are sequential with no delay or rate-limit control.** There is no
  "threads" or "throttle" setting. This is fine for a lab and unsuitable for
  anything you do not own or have permission to test.
- Each request has a 10-second timeout. A timeout is recorded as status `0`.
- If you close the dashboard tab, the attack continues in the dashboard
  process. If the process exits mid-attack, the run is lost.

## Leaving an attack running

**What it's for.** Big sweeps take minutes. You should not have to sit and watch
a progress bar with the screen awake.

**How to use it.**

1. Start the attack as usual.
2. Read the line under **Start attack**: it names the job and its progress, and
   says the run is safe to leave.
3. Close the tab, lock the phone, or wander off. The attack is a server-side
   job, not something the page drives.
4. Come back — reload the dashboard and open **Intruder**. It reattaches to the
   job, shows the results collected so far, and keeps updating.
5. **Stop attack** (next to Start while a run is active) cancels it but keeps
   everything already collected.

**What survives what.**

| Event | What happens |
|-------|--------------|
| You close the browser or leave the page | The attack keeps running |
| You reload the dashboard | It reattaches, with progress and results so far |
| The dashboard process restarts | It resumes from the last flushed batch, not from the beginning |
| The machine reboots | Same: the queue is in the database, so it resumes when the dashboard starts |

Results are written to the database every ten requests, so progress is real and
a crash costs at most that much. A run is refused only if another one is
already going — one at a time, deliberately, so two attacks cannot interleave
their results.

**Note.** An attack targets one host. Leaving it running is fine, but keep an
eye on rate limits and lockouts: there is no throttle, and resuming does not
slow it down either.

## Read the results

**What it's for.** Find the one response that behaved differently. That is the
whole skill behind enumeration.

**How to use it.**

1. Read the **Results** table:
   - **#** — the position in send order. It does not renumber when you sort.
   - **Payload** — the word sent, or `name=value | name=value` for Pitchfork.
   - **Status** — colour-coded HTTP status.
   - **URL** — the URL as actually sent, with the payload substituted.
   - **Size** — response body length in characters.
2. Click **View** on a row to open a read-only **Response** window with
   **Request sent** (method, URL, body) and **Response body**.
3. Step to the next or previous result with **Next ›** / **‹ Prev**, or the
   ← / → arrow keys, instead of closing and reopening. The header shows where
   you are (`3 / 101`) alongside the payload, status and size.
4. Close it with **Close (Esc)** or **Esc**.

**Next/Prev follow what is on screen**, including your sort and filters. With
**only size outliers** ticked, stepping visits just the outliers, so you are
not paging through the hundreds of responses you already ruled out.

On a phone the two panes stack (request above, response below) and the
response takes most of the height — side by side at 412px leaves too little
width to read an HTML body. Both panes are selectable, so you can copy a value
out.

On a phone, the **Payload** and **URL** columns truncate. Open **View** to read
the full request and response instead of trying to scroll the table sideways.

### The toolbar above the table

Scrolling hundreds of rows looking for the odd one is not practical, so there
are three controls. They change what you see; they never change what was sent.

| Control | What it does |
|---------|--------------|
| **Sort** | `sent order`, `size, biggest first`, `size, smallest first`, or `status code` |
| **Status** | keep only `2xx`, `3xx`, `4xx` or `5xx` |
| **only size outliers** | keep only rows whose size differs from the most common size |

**only size outliers** is the one to reach for first. Turn it on and the table
collapses to the responses that are *not* like the others. A line under the
controls tells you what the common size was and how many rows differ, so you
can tell "nothing stands out" (every response was identical) from "there are
three outliers".

The most common size is measured across **all** the results before any filter
is applied, so switching the **Status** filter on and off will not move it
underneath you.

**Worked example.** Username enumeration. Every fake username returns `200`
with the same 58-character body; the real one returns `302` with a 26-character
body. Paste the list, start the attack, tick **only size outliers**, and the
table shows exactly one row. That is your username. Tick **Status → 3xx** as
well to confirm it is the redirect.

### Comparing two results

Once you have a suspicious pair — say the real username against a fake one —
you can see exactly what differs, instead of holding two **View** windows in
your head.

1. Tap the first row. It gets an **A** badge.
2. Tap the second row. It gets a **B** badge.
3. **Compare A / B** lights up. Press it.

You land on the **Diff** tab with both responses loaded and the same six views
you get for captures: **What changed**, **JSON**, **Tokens**, **Bytes**,
**Params** and **Headers**. The summary line names the difference:

```
status 302 → 200 · 1 param(s): username · JSON error: 'Invalid password' → 'Invalid username' · 1 header(s) differ
```

A third tap replaces the older of the two picks, so a mis-tap costs you one
selection, not the whole thing.

**What to look for.**

- A status that differs from the majority.
- A size that differs from the majority. Even a 10-character difference can be
  the "invalid username" versus "wrong password" distinction.
- A URL that does not contain the payload where you expected it. That means the
  marker was missing from the request.
- Pitchfork labels that show the exact pair that succeeded.
- In the diff, the **error** field changing is almost always the finding.

**Two different verdicts in the Diff tab.** `status` (`same` / `different`) is
about **status codes only**. `identical` is about the whole response — status,
headers, query parameters and body. Two `200`s that differ only by one query
parameter are `status: same` and `identical: false`. Trust `identical` when
you are asking "did anything change at all".

**Common mistakes / notes.**

- **Two results cannot be compared with a capture.** Results and captures are
  different kinds of row with separate IDs, so mixing them is refused rather
  than producing a meaningless diff. The **Pick…** buttons only ever give you
  captures.
- **Size counts characters, not bytes.** A response full of non-ASCII text is
  bigger on the wire than the number suggests. Use it for comparison, not as a
  transfer measurement.
- **The results are not captures.** They live in a separate table and do not
  appear in Live, the Log tab, or a HAR export. The selected base capture's
  **Intruder** detail tab shows a one-line-per-result summary.
- Results are stored in the database when the attack finishes. They are deleted
  when you **Clear captures**, when the base capture is pruned, and by a
  [Noise cleanup](noise.md#layer-3-clean-up-with-a-dry-run-and-a-backup) that
  removes the base.
- **Redirects are not followed.** A successful lab login usually shows `302`,
  and that is the signal. If you need the destination body, take the winning
  payload to [Repeater](repeater.md) and use **Follow redirects**.
- **Cookies persist across the attack.** Intruder uses one HTTP session for its
  lifetime, so a `Set-Cookie` returned for one payload is sent with later
  requests, and it survives between attacks until the dashboard process
  restarts. That is convenient when a payload logs you in, but it also means
  one attack can contaminate the next. Restart the dashboard if you need a
  clean session. (You still cannot give each payload a different starting
  session; the captured `Cookie` header is what the attack begins with.)
- **Rewrite, Noise and scope do not apply.** Intruder sends directly, not
  through the proxy. Do not expect a header rewrite or a noise rule to change
  an attack.
- Payloads have carriage returns and newlines stripped before substitution, so
  a wordlist entry cannot split the request. Spaces and backslashes are kept.
- Deleting results is irreversible. Write the winning payload in a [note](live-tab.md#write-a-note)
  before you clear the lab.

Next: [Diff](diff.md).
