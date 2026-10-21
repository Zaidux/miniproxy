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

## [0.9.6] — 2026-10-21

### Added

- **Replay through a real browser.** A new `browser` mode in the Repeater's
  TLS picker executes the request inside an actual browser page, so TLS,
  HTTP/2, cookies, User-Agent and any JavaScript challenge state are native.
  This is the only replay mode that works when the gate is IP reputation plus a
  managed challenge rather than the handshake — measured on the case that
  prompted it, where a matched fingerprint (`firefox154`) and even real Chrome
  from the same address were both challenged.

  - Attaches to a system Chrome/Chromium (or `MINIPROXY_BROWSER_PATH`), or to a
    browser you already have open via `MINIPROXY_BROWSER_CDP` — including
    Android Chrome over USB, which gives the request that device's IP and
    solved challenge.
  - Persistent profile at `~/.miniproxy/browser-profile`, so a challenge solved
    once stays solved. `MINIPROXY_BROWSER_HEADLESS=0` runs headed.
  - Requests are executed with the page's own `fetch`, so a page's forbidden
    headers (`Host`, `Cookie`, `User-Agent`, `Content-Length`, `Sec-*`, …) are
    supplied by the browser. The response lists what was dropped rather than
    pretending the replay was byte-faithful.
  - Playwright's "HeadlessChrome" User-Agent is rewritten, since that string is
    itself a detection signal.
  - Independent of `curl_cffi`: a machine with a browser but no TLS extra can
    still use this mode.

## [0.9.5] — 2026-10-21

### Added

- **Browser-TLS replay in the Repeater.** A **TLS fingerprint** picker replays a
  request with a real browser's TLS and HTTP/2 handshake (`chrome`,
  `firefox147`, `safari184`, `chrome131_android`, …), which is the only way
  through bot management that binds a clearance cookie to the client handshake.
  Verified with a peer that reports fingerprints: plain `requests` sends
  `ja4 …h1…` with its own hashes, while each profile produces its own distinct
  JA3/JA4/HTTP-2 hashes.

  This was prompted by a real block: a captured iFood request returned `200` in
  the browser and `403` from the Repeater with **byte-identical headers, the
  same cookie and the same body** — the response being Cloudflare's
  *Just a moment…* page. Copying headers cannot fix that.

  - The response now carries `challenge: true` when a bot wall answers (header,
    page title, or a bare 403), so the dashboard explains what happened and
    points at the Rewrite fallback instead of showing an unexplained status.
  - Unknown profiles are rejected with the valid list rather than silently
    falling back to a fingerprint you did not choose.
  - Optional dependency: `pip install "riciplay-miniproxy[tls]"`. Without it the
    picker states the install command and plain replay continues to work.

  **Limit, stated plainly:** a profile only helps when it matches the browser
  that obtained the clearance. A challenge solved in Firefox on Android cannot
  be replayed by any shipped profile (they are desktop versions). For those
  targets, use Rewrite with the real browser — the browser keeps its handshake
  and the proxy edits the request in flight.

## [0.9.4] — 2026-10-20

### Fixed

- **The CRLF repair was browser-only.** Restoring multipart framing in the
  Repeater modal fixed the dashboard but left every other path broken: a
  direct `POST /api/repeater/send` (a supported way to replay a request) and
  the Intruder both still sent LF-only bodies, so the server could not find the
  closing boundary and reported the last form field as missing. Normalisation
  now happens server-side, in the one place every path passes through.

  Verified against the live service: a stored LF body of 325 bytes now arrives
  as 335 bytes with `CRLF--boundary` framing and is accepted, where it was
  rejected before.

## [0.9.3] — 2026-10-20

### Fixed

- **Replaying an uploaded file failed with "Missing parameter 'csrf'".** Two
  separate defects, both in the send path:
  - A captured `Content-Length` was forwarded verbatim. It describes the
    captured body, so any edit made it wrong; too small and the server reads
    only part of the body and stops **mid-boundary**, too large and it waits.
    The Repeater and the Intruder now drop `Content-Length` /
    `Transfer-Encoding` and let the HTTP client compute them.
  - A browser `<textarea>` normalises CRLF to LF, and multipart parts are
    delimited by `CRLF--boundary`, so loading a captured upload and pressing
    Send broke the framing. CRLF is now restored for multipart bodies
    (detected from the content type, or from a body starting with `--`).

  Because `csrf` is the *last* part of the body, it is what a short read loses
  first — which is why the error named that field. Reproduced against a server
  that validates the closing boundary: `400 Missing parameter 'csrf'` before,
  `200 uploaded` after, with all 470 bytes delivered.

## [0.9.2] — 2026-10-19

### Added

- **A `{{…}}` button beside URL and Body** turns the selected text into a
  marker. Select the `1` in `192.168.0.1`, tap it, and the field becomes
  `192.168.0.{{i}}`; with only a cursor placed it inserts a marker there. This
  closes the phone gap: `§` cannot be typed on a mobile keyboard, so marking a
  value was previously impossible without a hardware keyboard.
- A **marker counter** beside **Start attack** (`0 markers`, `1 marker (i)`).

### Fixed

- **"No param markers" blocked the attack with a modal.** The check was
  correct — a request with no marker cannot substitute anything — but the
  modal did not say *which* field was unmarked, could not be read while fixing
  it, and left no way to add a marker without typing `§`. The warning is now an
  inline line, **Start attack** is disabled while it applies, and the `{{…}}`
  button makes fixing it one tap. The server-side guard is unchanged, so a
  stale tab still cannot send a wordlist of identical requests.

## [0.9.1] — 2026-10-19

## [0.9.1] — 2026-10-19

### Added

- **Numeric ranges as a payload source.** A paste-box line that is only a
  number range expands the way Burp's "Numbers" payload type does:
  `1-255`, `1-255:2` (step), `255-1` (descending), `001-010` (zero-padded).
  Only a whole-line range expands, so payloads that merely contain a hyphen
  (`1-2-3`, `a-b`) stay literal. This is what an SSRF address sweep needs —
  `stockApi=http://192.168.0.{{i}}:8080/admin` with `1-255` — and it works in
  Single list and Pitchfork, in a durable job, with the outlier filter. Before
  this there was no way to express a range at all: the bundled ID list stopped
  at 100 and the only alternative was pasting 255 lines by hand.
- Documented the full SSRF workflow, including the trap that produced a
  9,898-request run with zero findings: the `stockApi` parameter is in the
  **body**, so markers must go in the Body box, not the URL query.

## [0.9.0] — 2026-10-18

### Added

- **Attacks keep running when you leave, and resume after a restart.** The work
  queue (base request + every payload combination) is now persisted with the
  job, and results are written every ten requests instead of only at the end.
  - Closing the tab or the browser no longer matters: the run is a server-side
    job, not something the page drives.
  - Reloading the dashboard **reattaches** to the running job — progress and
    the results collected so far come back from the database.
  - A dashboard restart, or a reboot, **resumes** from the last flushed batch
    rather than losing the attack or starting over.
  - **Stop attack** cancels a run but keeps everything already collected.
  - New endpoints: `GET /api/intruder/status` (now DB-backed),
    `GET /api/intruder/jobs/<id>`, `POST /api/intruder/cancel`.
- **`{{name}}` works as a marker alias for `§name§`**, everywhere: the editor,
  the guard that refuses marker-less attacks, pitchfork row detection, the API
  and stored captures. `§` cannot be typed on a phone keyboard (or into a
  browser address bar), which made the documented syntax effectively
  unusable on mobile — this was the real reason attacks kept failing with "no
  markers".

### Fixed

- **The dashboard template is served through Jinja, so a literal `{{name}}` in
  it was parsed as a Jinja expression** and the whole page returned 500. The
  template contains no Jinja directives, so it is now wrapped in a raw block —
  which also means any future use of Jinja in it needs that block removed.

## [0.8.4] — 2026-10-18

### Fixed

- **Host filtering matched nothing for any URL with a non-default port.**
  `host_of()` strips the port but the SQL host slice keeps it, so the exact
  comparison introduced in 0.8.3 made `host=127.0.0.1` fail on
  `http://127.0.0.1:5347/login` — every capture on a port became unfilterable,
  as did `exclude_host`. The match now covers the host, the host with a port, a
  subdomain, and a subdomain with a port. Caught by smoking the installed
  wheel, not by the suite: no existing test used a URL with a port.

## [0.8.3] — 2026-10-18

### Fixed

- **A wordlist could run with no payload substituted at all.** 101 requests
  were sent to a single URL, every one identical, and the results table
  presented it as a finished attack. The marker check existed only in the
  browser, so a page loaded before an upgrade — which sends only a request ID —
  fell back to the stored capture and bypassed it entirely. The server now
  refuses a request with no `§markers§` (URL, body, header names or values),
  where a stale page cannot skip it.
- **The results table now calls out an identical-URL run.** A line under the
  toolbar reads *"All N requests sent the same URL — no payload was substituted,
  so the wordlist was ignored."* A table of identical rows is otherwise very
  easy to read as a successful attack.
- **Pitchfork's empty state promised rows that never appeared.** It said "add
  some … and they appear here", but rows were only rebuilt on a mode switch, so
  adding a marker did nothing and the mode looked broken. Editing the request
  now refreshes them, debounced, and only when the *set* of marker names
  changes — so an unrelated edit cannot close an open paste box or discard a
  half-typed list. **To Intruder** refreshes them too.
- **The results viewer could not show a full body on a phone.** Two panes side
  by side at 412px left roughly 180px each, which is unreadable for HTML. They
  now stack with the response taking most of the height. Added **‹ Prev** /
  **Next ›** and the ← / → keys to step through results without closing the
  modal; navigation follows the current sort and filters, so with **only size
  outliers** ticked it visits just the outliers.

### Fixed — pre-release audit

Two read-only audits of the Intruder and of every other surface found the
following. Each is fixed with a regression test in
`tests/test_audit_regressions.py` unless noted.

**Data loss**

- **`prune()` could delete every capture in the database.** The size-cap loop
  deleted 100 rows per pass and re-tested `page_count`, but only `VACUUM`
  shrinks `page_count` — so when `VACUUM` was blocked (a concurrent reader, a
  busy disk) the condition never became false and the loop emptied the table
  silently. Measured before the fix: 249 of 249 rows in one call. It now stops
  when a pass reclaims nothing, and one call may not remove more than a quarter
  of the table (minimum 100 rows).
- **Noise cleanup deleted even when its safety backup failed.** `_backup_db()`
  returns `""` on failure and the caller ignored it, while the UI and CLI both
  promise a timestamped backup first. A failed backup now raises and nothing is
  deleted; the API answers 409 and the CLI prints the reason.
- **Switching rows discarded an unsaved note.** The poll was careful never to
  overwrite the note field, and then a row click overwrote it anyway. The
  previous row's note is now saved before the switch.
- **`_harden_perms()` chmod'd the database's parent directory, not just
  `~/.miniproxy`.** With `--db /tmp/lab.db` it made `/tmp` 0700. Only a
  directory literally named `.miniproxy` is tightened now.

**Security**

- **A foreign site could wipe your captures.** `POST /api/clear` needs no body
  and no token by default, so any page could submit a form to it. Mutating
  requests with a foreign `Origin` (or `Sec-Fetch-Site: cross-site`) are now
  refused with 403; requests with no Origin (curl, CLI) are unaffected.
- **The CORS origin check was a prefix match**, so `http://127.0.0.1.evil.com`
  was echoed back and could read captures. Origins are now compared exactly
  (scheme+host+port) against the request's own host.
- **`esc()` escaped `& < >` but not quotes**, while marker names, URLs and
  paths are interpolated into HTML attributes. A captured request containing a
  header like `§" onmouseover="…§` executed script in a dashboard that holds
  captured credentials. Quotes are escaped now.
- **`--allow-client` was still documented as a client allowlist** in
  `server.start()`'s docstring, though it is mitmproxy's destination
  `allow_hosts`. Corrected.

**Wrong results**

- **Diff reported "identical" when B was a superset of A.** The token diff was
  one-directional, so a response containing everything A had *plus* an admin
  section came back identical — the exact access-control question answered
  backwards. The diff is symmetric now and the summary names tokens "only in
  B".
- **Diff could compare a capture against a stale Intruder result id.** A B-side
  chosen from the Intruder results survived into a capture comparison, silently
  diffing the wrong row (or 404ing). B is only carried over within the same
  source.
- **`Hide static` dropped every capture with an unrecorded content type.** The
  SQL twin was not parenthesised, so `"NOT " + expr` parsed as
  `(NOT mimes) OR ext`, and `NULL` content types made the expression `NULL`,
  which `WHERE` treats as false. Extension-only rows (pending flows, 304s) were
  also never matched. It is parenthesised and `COALESCE`d, and it now agrees
  with the Python classifier for URLs with query strings like `app.js?v=1`.
- **Host filtering matched substrings, so `example.com` also returned
  `notexample.com` and `example.com.evil`** — the wrong target's traffic. A
  hostname-looking value now matches the host and its subdomains on label
  boundaries; a bare fragment (`mozilla`) keeps substring behaviour.
- **The noise dry-run ignored `--keep-host`**, so it over-reported what Delete
  would remove. Scan and clean now share the keep list.
- **The CLI lost the dashboard URL crash path**: a dashboard start failure
  raised `KeyError: 'url'` after a success message. It now prints the failure.
- **`with_dashboard=False` did not suppress the dashboard** (`dashboard`
  defaults True, and the check was `dashboard or with_dashboard`), so the
  header's Start button could spawn a second dashboard.
- **`miniproxy web --scope a b` was rejected** because the alias did not copy
  `nargs` from `start`.
- **A failed start could leave an orphan proxy with no PID file.** The state
  files were written last and assumed their directory existed, and the
  readiness probe always checked `127.0.0.1` even for a non-loopback
  `--proxy-host` — so a non-loopback bind waited 8s, failed, and left mitmdump
  running where `status` and `stop` could not see it. The directory is created,
  the probe uses the bind address, and a failed start now stops the child.

**TUI**

- The table declared seven columns and filled five: the full URL sat in
  **Host**, **Path** was always blank, and the highlight marker never showed.
- The Rewrite view was always blank — it wrote into a `RichLog` that was never
  mounted, so `.lines` was empty.
- The proxy toggle started a proxy on the default DB instead of the TUI's
  `--db`, so captures never appeared. It also no longer spawns a dashboard.
- Host, body and the two chip filters did nothing until new traffic arrived:
  they had no handlers, and the poll's change signature is computed over
  unfiltered rows.
- The noise list cursor jumped to a different rule after toggling (the list is
  ordered enabled-first); it is preserved by rule id. `a` is labelled
  "Bundled on/off", which is what it always did.
- `Set-Cookie` and other duplicate headers are joined by mitmproxy into one
  header; this is unchanged and now documented as a known limitation.

## [0.8.2] — 2026-10-17

### Added

- **The Intruder results table can be sorted, filtered, and diffed.** Finding
  the one response out of hundreds that behaved differently *is* the skill
  behind username enumeration, and the table previously offered neither
  ordering nor comparison — you got an unordered list and an `alert()`.
  - **Sort** by response size (either direction) or status code.
  - **Filter** by status class (`2xx` / `3xx` / `4xx` / `5xx`).
  - **Only size outliers** narrows the table to rows whose response length
    differs from the *most common* length. The baseline is measured across
    all rows before filtering, so switching the filter on never moves the
    baseline out from under you. When every response is the same size it says
    so rather than implying there are no results.
  - The `#` column keeps its original send order after sorting, so a number
    that changes when you reorder is never shown.
  - **Compare A / B**: select any two rows and diff them against each other in
    the Diff tab. This needed plumbing — Intruder results live in
    `intruder_results`, a separate table with a separate id space from
    captures, and the results returned to the client carried no `id` at all.
    `store_intruder_results` now stamps each result with its new row id.

### Fixed

- **The Intruder attacked the stored capture and ignored everything you typed.**
  The dashboard sent only a request ID, and the server reloaded that capture
  from the database and substituted into *it*. Every edit in the Intruder tab
  was silently discarded — you could not retarget the URL, fix a header, or
  introduce a `§placeholder§` from the UI at all, and there was no other way
  to add one. (Older guides work around this by building the request with
  `curl` through the proxy.) The tab now sends the Method / URL / Headers /
  Body exactly as shown, and the server uses them when supplied, falling back
  to the stored capture for older clients. **Start attack** also now refuses a
  request with no `§markers§` instead of firing a wordlist of identical
  requests.
- **`Hide static` and `Highlighted` never came back after a reload.** The two
  chips saved to `mp.filter.static` / `mp.filter.highlighted` (built by
  string-stripping the element id) but were restored from
  `mp.filter-highlighted` — a different key — and `static` was never read at
  all. Both now restore from the keys they actually write.
- **`--allow-client` does not do what it says, and the README recommended it as
  a security control.** Despite the name it is passed to mitmproxy's
  `allow_hosts`, which filters **destination** hosts — not who may connect to
  the proxy port. So it does not close an open relay, which is exactly what
  the flag's help text and the README claimed it did. mitmproxy has no
  client-IP allowlist in its option layer, so the help, the runtime warning
  and the README now say so and point at a firewall or an SSH tunnel instead
  of implying the flag is a lock.
- **Two tooltips promised more than the code did.** `To Intruder` said it
  loaded the request "with §param§ markers" (it adds none), and the Repeater's
  `Compare…` said it compared the tab's last response (it uses the capture
  selected in Live). Both now describe what they actually do.
- **The Diff tab's "A body" / "B body" panes were permanently empty.**
  `runDiff` read `data.body_a` / `data.body_b`, which the diff payload has
  never contained, so both panes rendered `(empty)` for every comparison.
  They are now fetched from the `/bodies` endpoint, which existed but was
  never called.
- **A capture and an Intruder result could be diffed as if they were
  comparable.** They are different kinds of row in different id spaces, so
  mixing them is now refused with an explanation rather than silently
  producing a meaningless diff. Sources also travel with the ids when A and B
  are swapped.
- **Result rows opened an `alert()`**, which is blocking, unscrollable, and
  unreadable for a multi-KB body. Replaced with a View modal showing the exact
  request sent alongside the response.
- Results that failed to persist have no row id, and therefore nothing to
  diff. The results table now says so and disables **Compare** instead of
  offering a button that quietly does nothing.

### Docs

- **New beginner guide** in [`docs/guide/`](docs/guide/README.md) — what each
  feature is for and how to use it, in plain language, with worked examples
  from the PortSwigger labs.
- The guide also documents several behaviours the existing reference docs
  glossed over or got wrong: results are not captures and never appear in
  Live/Log or a HAR export; Intruder and Repeater send directly rather than
  through the proxy, so Rewrite/Noise/scope do not apply to them; the Live tab
  shows only the newest 200 rows and its counter counts that window; exports
  cap at 1,000 rows; Notes are not searchable; an unconfigured pitchfork
  placeholder is substituted with an empty string, not left as literal text;
  and cookie state persists across attacks until the dashboard restarts.

## [0.8.1] — 2026-10-17

### Added

- **Paste a wordlist into the Intruder — no file needed.** Wordlists live in
  awkward places (a notes app, a Slack thread, a Burp export, a `curl`
  transcript), and making you save any of that to disk first is pure friction.
  - **Single list** gets a paste box beside the upload input. It parses live,
    so the count updates as you type and clearing the box clears the list.
  - **Pitchfork** gets a **Paste** button per row, unfolding a box under that
    row. **Use list** commits it, **Cancel** discards it — committing
    explicitly because a half-typed list would otherwise change the request
    product on every keystroke.
- **One shared parser for paste and upload.** The two disagreed: the pitchfork
  upload skipped `#` comments and the single-list upload did not, so identical
  text produced a different wordlist depending on which control you used. Both
  now take the same rules:
  - Newlines **and commas** separate words — pasted lists rarely arrive
    one-per-line.
  - **Spaces do not** separate. `admin' OR '1'='1` stays one request instead of
    being shredded into three.
  - Blank lines and `#` comment lines are dropped, the rule
    `wordlists.load_from_file` has always documented (though nothing currently
    calls it — the parsing now lives in the dashboard).
  - Capped at 1,000, and over the cap the count reports what was dropped
    (`1000 words (pasted, capped from 1199)`) rather than truncating quietly.

### Fixed

- **A bundled wordlist counted up and then refused to start.** The word list was
  held in two variables: a bare `words` written only by the file input, and
  `iState.words` written only by the bundled cards. The request counter read
  the second and **Start attack** read the first — so clicking a bundled card
  showed a correct count and then alerted *"Pick a bundled list or upload a
  wordlist"*, while an uploaded file showed no count at all. There is now a
  single source of truth with one setter, and it names the active source
  (`3 words (pasted)`).
- **The pitchfork upload handler lied about list size.** It printed the
  pre-cap count — *"1199 words"* — while storing the capped 1000. The count on
  screen no longer describes the attack it is about to run.
- **Inactive wordlist sources are cleared instead of lingering.** Choosing a
  bundled card clears the paste box, and pasting clears the selected card. A
  control still showing text while a different list is what actually gets sent
  is the same shape of lie as the two-variable bug above.

## [0.8.0] — 2026-10-16

Diff, Noise and Rewrite are top-level tabs.

### Changed

- **The three former modals are now tabs.** `Diff`, `Noise` and `Rewrite` sit
  in the top tab bar next to Live/Log/Repeater/Intruder/Connect, so they are
  directly reachable instead of hiding behind a button. Each gets the full
  page width and scrolls internally rather than pushing the page into a
  double scrollbar.
- Every existing entry point now navigates to the tab rather than opening an
  overlay — one implementation of each screen, no second copy to drift:
  - **⋮ → Compare** (new) and the detail pane's **Compare…** hand the capture
    to the Diff tab as **A**, leaving you to pick B there.
  - The Repeater's **Compare…** does the same.
  - The filter bar's **Noise…** and **Rewrite…** switch to their tabs and load
    the current state on entry.
- The Diff tab's own **Pick…** buttons open the shared capture picker with the
  header reading `→ Capture A` / `→ Capture B`, so it is clear which side you
  are filling.
- The tab bar wraps, which it needs to: eight entries overflow a 412px phone
  viewport otherwise. The active tab is still restored on reload.

### Fixed

- The Diff tab's **Pick…** buttons passed the short target `a`/`b` to the
  picker, which only recognises `diff-a`/`diff-b` — so they fell through to
  the Intruder and filled the wrong editor.

## [0.7.0] — 2026-10-16

Eight features, plus the two interaction bugs they exposed.

### Fixed

- **You can copy values again.** The live poll re-rendered the table and the
  detail panes every 2 seconds, which destroyed any text selection. Worse,
  dragging *inside a row* to select its URL also fires the row's click
  handler, so the selection was cleared the instant it was made — selecting a
  value by hand was impossible. Rendering is now skipped when the output is
  unchanged, and deferred entirely while a selection is held (it flushes as
  soon as you click away).
- **The note field keeps what you type.** The poll assigned the textarea's
  `.value` on every tick, so text entered a second earlier was wiped — which
  read as "the last word disappears when I press space". The field is now left
  alone while it has focus or holds unsaved edits, and shows `unsaved…`
  instead of silently losing work.

### Added

**Compare captures (response diffing)**

- `GET /api/diff/<a>/<b>` and a dashboard modal. The access-control workflow:
  send a request twice with one parameter changed, and read off what actually
  changed instead of eyeballing two hex dumps.
- Three views, chosen automatically for the data present:
  - **JSON** — structural, keyed by dotted path, so `role: 'user' → 'admin'`
    is one line.
  - **Tokens** — word-level, for HTML/text. Punctuation is a token boundary,
    so a *minified* page still localises the change rather than reporting one
    unreadable blob.
  - **Bytes** — character-level with context, for exact offsets.
- Also diffs the URL parameters, path, status and headers — for access-control
  work the changed parameter name is often the whole answer.
- The summary names the change (`role: 'user' → 'admin'`), because "1 field
  differs" is useless mid-test.
- TUI equivalent: press `d` on one capture, move, press `d` again; `m` cycles
  the mode.

**Body search**

- `body` / `exclude_body` / `min_length` filters in SQL, across the listing,
  the count and every export. Searches the request **and** response body —
  where flags, leaked tokens and unexpected parameters actually live.

**Intruder pitchfork**

- `POST /api/intruder/start` with `{"mode": "pitchfork", "lists": {"user":
  [...], "pass": [...]}}`: a different wordlist per `§placeholder§`, run as a
  product. The engine previously put one word into *every* position, so a
  username × password attack was impossible.
- The UI grows one row per placeholder found in the target request, each with
  a list picker or file upload, and shows the combination count before you
  start. Combos are capped at 10,000.

**Bundled wordlists**

- Five curated lists ship in the package — numeric IDs, usernames, common
  passwords, parameter names, ports, paths — so a fresh install can attack
  without hunting for a `.txt` first. `GET /api/wordlists`.

**Repeater tabs + history**

- Multiple persistent tabs (`/api/repeater/tabs`), stored server-side so a
  refresh — or switching from desktop to phone — keeps work in progress.
- Per-tab send history (last 50) with status and size, click to view any past
  response. Edits auto-save as you type.
- **Follow redirects** checkbox: reports the whole redirect chain and the final
  URL. Off by default, because a lab that redirects is usually redirecting to a
  login page and silently following hides the 302 being tested.

**Match & replace**

- Rewrite headers, query parameters or bodies on requests **as they pass
  through the proxy** (`/api/rewrite`), so the target sees the modified values.
  For headers, `exact` matches the name and sets the value; `contains`/`regex`
  match inside the value. Regexes are validated on insert, and CR/LF is
  stripped from replacements (this runs before the request leaves — an
  unescaped newline would be request splitting).
- Dashboard **Rewrite…** modal and a TUI screen (`m`).

**TUI parity**

The terminal UI had none of the 0.6 dashboard work. It now has:
- Host, body, hide-static and highlighted-only filters
- Host / Path / marker columns instead of one wide URL column
- `d` to compare two captures, `n` for noise rules (toggle with Enter), `m` for
  match & replace

### Changed

- Oversized wordlists are refused with a 400 up front instead of being accepted
  and then failing inside the worker (which showed "attack started" before an
  error).
- Intruder payload substitution no longer escapes backslashes: the replacement
  is now a function, so `re.sub` cannot interpret `\g<0>` as a group
  reference. This also stops ordinary payloads like `DOMAIN\user` being
  corrupted.

### Security

- Match-and-replace replacement values have CR/LF stripped, since they are
  applied to the live request.

## [0.6.3] — 2026-10-16

The dashboard becomes something you can actually scan on a phone, and
browser noise stops drowning out the target.

### Added

**Dashboard — closer to Burp, still simpler**

- **Host and Path columns.** The URL is split in the request table so you can
  scan endpoints instead of scrolling past the same host 200 times. The host
  column is dimmed with a leading `www.`/`m.` stripped, the query string is
  shown after a dimmed `?`, and the full URL stays in the row tooltip. The Log
  tab and the request picker use the same split.
- **Size column.** Response size per row (recorded length, falling back to the
  stored body), formatted `B`/`K`/`M`.
- **Resizable, collapsible split.** The divider between the request table and
  the detail pane drags to resize (pointer events, so mouse/touch/pen all
  work) and collapses the detail pane to a full-width table on click. Arrow
  keys resize and Enter/Space toggle when the handle is focused. Width and
  collapsed state persist across refreshes. On narrow screens the panes stack
  and the divider becomes a horizontal affordance.
- **Custom row highlights.** A Burp-style 8-colour palette (red, orange,
  yellow, green, cyan, blue, magenta, pink) plus Clear. A highlighted row gets
  a coloured left bar and a faint tint. Stored on the row, so highlights
  survive refreshes, a different browser, and a proxy restart. Filter to your
  marked rows with the new **Highlighted** chip.
- **Per-row ⋮ menu.** Every row has a touch-sized overflow button — pinned to
  the right edge of the scroll area so it never scrolls out of reach on a
  phone — opening the palette plus Add note / Repeater / To Intruder. There is
  no right-click-only path, because right-click does not exist on Android.
- **Notes.** Free-text notes attached to a capture, edited in a new **Note**
  detail tab. Saving a note never clears the highlight, and vice versa.
- **Pretty / Raw / Hex body views**, on both the request and the response side.
  *Pretty* re-indents JSON; *Raw* escapes control and non-ASCII characters so
  you can see what a decoder or filter did to the bytes; *Hex* is a real dump
  with an offset column, byte columns and ASCII gutter, with all-zero rows
  dimmed. Each side keeps the view you last chose. Binary bodies get a hint
  pointing at Hex.
- **Host focus dropdown**, labelled with each host's capture count, plus a
  summary showing `N shown / M fetched` and naming the noisiest hosts.
- **Hide static chip** — drops images/fonts/css/js/media with one tap.
- **Noise modal** — manage rules, dry-run a scan, and delete captured noise,
  with the same confirmation and backup guarantees as the CLI.

**Noise — three layers**

- **Capture time.** Enabled host rules make matching traffic skip the row
  entirely; it is still proxied, it just never reaches the DB. Rules match on
  host (suffix-aware, `*.example.com` supported) and never on a path segment.
  A bundled list of known telemetry/ad hosts ships **disabled**, so nothing is
  dropped until you opt in.
- **Query time.** `host`, `exclude_host`, `hide_static` and `highlighted_only`
  filters, applied in SQL across the listing, the count and every export. A
  static asset is decided by content type first — a known asset MIME wins, a
  known non-asset MIME wins over a misleading `/api/image.png` filename — and
  only falls back to the URL extension when no type was recorded.
- **Cleanup time.** `scan_noise()` (dry run, never deletes) and
  `clean_noise()`, which writes a timestamped `.noise-backup-<date>.db`
  snapshot via SQLite's backup API first, cascades to `intruder_results`, and
  can protect hosts you name.
- **`miniproxy noise` CLI** — `list` / `enable` / `disable` / `add` / `rm` /
  `scan` / `clean`. `clean` refuses without `--yes` and takes repeatable
  `--keep-host`. Works with no dashboard and no proxy running.

**API**

- `PATCH /api/logs/<id>` — set `highlight` and/or `note` (absent keys
  untouched).
- `GET /api/hosts` — hosts with capture counts, busiest first.
- `GET|POST /api/noise/rules`, `PATCH|DELETE /api/noise/rules/<id>`,
  `GET /api/noise/scan`, `POST /api/noise/clean` (requires `confirm`).

### Changed

- The **Repeater tab now uses the same capture picker modal as the Intruder**,
  instead of a bare `<select>` that ignored the Live tab filters. Both pick
  from the same seeded filters and the modal header shows which editor "Use
  it" will fill, so you can no longer replay or fuzz a request the Live tab is
  hiding. The picker gained its own host filter and shows host/path columns.
- Exports (HAR + JSON) honour the new host / hide-static / highlighted filters,
  so an export matches what the table shows.
- Highlights and notes persist across restarts; the rest of the UI session
  (`localStorage`) additionally now keeps the host filter, the Hide-static and
  Highlighted chips, and the pane width/collapsed state.

### Fixed

- **The noise gate could stop all capture.** The capture-time check read
  `req` one line before `req` was assigned, raising `UnboundLocalError` on
  every single flow. mitmdump reports an addon exception and carries on, so
  the proxy still routed traffic while writing **nothing** to the capture DB
  — silent, and only visible as an empty request table. Fixed, and covered by
  an end-to-end test that runs the real addon under a real mitmdump process and
  asserts traffic actually lands in the DB (plus a check that the addon emits
  no traceback), so a swallowed addon exception fails CI from now on.
- A drag of the splitter handle also fired a click on it, so **every resize
  collapsed the detail pane**. The toggle is now suppressed for a real drag.
- `count_logs()` counted by materialising every matching row into Python
  (`get_logs(limit=10_000_000)`) and taking `len()`. It now runs a real
  `COUNT(*)`, so counting a large capture DB no longer loads hundreds of
  megabytes.
- Listing, counting and exporting now build their `WHERE` clause through one
  shared compiler, so they cannot drift apart.

### Security

- Highlight colors are validated against a fixed palette server-side. The
  value is interpolated into a `style` attribute, so an unvalidated string
  would have been a stored-XSS hole; off-palette values are rejected with a
  400 and never persisted.

## [0.6.1] — 2026-10-15

### Fixed
- **The intercept toggle was a silent no-op.** `set_intercept()` writes the
  `intercept` config key, but the intercept addon read `intercept_enabled` —
  a key nothing in the codebase ever wrote. Interception was therefore
  permanently on regardless of the stored preference. Both sides now use
  `intercept`. The addon defaults the key to `"1"`, so a fresh session (which
  has no row yet) still starts with interception enabled — verified against a
  real fresh DB, and against an existing one.
- `GET/POST /api/proxy/status` returned a hardcoded `"intercept_enabled": true`
  instead of the stored value.

## [0.6.0] — 2026-10-15

Closes the capture DB to the world, and makes one filter definition serve
every view.

### Security
- **The proxy is no longer published to the internet by default.** mitmdump
  was hardcoded to `--set block_global=false` and bound every interface, so
  on a VPS any host that could reach the port could capture *through*
  MiniProxy and land their own traffic in your database. New
  `--proxy-host` flag (default `127.0.0.1`) controls the bind address;
  reach a loopback-bound proxy from another machine with
  `ssh -L <port>:127.0.0.1:<port>`.
  - **Breaking:** a remote browser can no longer connect at the server's
    public IP unless you pass `--proxy-host 0.0.0.0`. Start prints a
    reminder of the `ssh -L` form whenever the proxy is published.
- **`--allow-client <ip>`** (repeatable) restricts the proxy port to specific
  client IPs via mitmproxy's `allow_hosts`. Required when combining
  `--proxy-host 0.0.0.0` with an internet-facing port; `start` warns when a
  published port has no allowlist.
- The startup warning for a LAN-exposed dashboard no longer fires when
  `--dashboard-token` was actually supplied (it previously printed
  "Pass --dashboard-token to require auth" on runs that had just passed it).

### Added
- **Capture-ID filtering, everywhere.** A shared selector accepted by the
  Live tab, the count header, the export menu and the Intruder picker:
  `42`, `1,5,9`, `100-200`, or any comma/space-separated mix. Multiple ids
  are OR-ed; reversed ranges (`200-100`) are normalised; unusable input is
  ignored rather than blanking the table or erroring. Backed by
  `db.parse_id_filter()` (SQL) with a matching client-side implementation
  so the live table stays instant.
- **Intruder request picker.** The Intruder target selector was a bare
  `<select>` that ignored the Live tab filters, so you could fuzz a request
  the live view was hiding. It is now a modal picker seeded from those
  filters and filterable by method, status, URL and ID, with row-click
  selection.
- **Visible "Clear captures" button.** Clearing was implemented and
  reachable but buried in the `Export ▾` dropdown (`display:none` until
  opened), so it read as missing. It now sits in the toolbar as a
  danger-styled button.

### Fixed
- **Repeater/Intruder selectors offered deleted requests.** After
  clearing, `state.logCache` was left populated, so the request dropdowns
  still listed rows that no longer existed and could be replayed. The cache,
  both selectors and the Log table are now refreshed.
- One shared filter reader (`app._log_filters()`) now backs `/api/logs`,
  `/api/logs/count` and every export. `exportFiltersQ()` previously rebuilt
  the query string by hand and would silently drop any newly added filter.
- The live poll now applies filters server-side. With an ID or URL filter
  active, the unfiltered 200-row window could contain none of the wanted
  rows and the table looked empty.
- `__version__` reported `0.4.0` from a 0.5.0 install, so `/api/meta`
  showed a version that did not match the package. All version strings are
  pinned together by `tests/test_version.py`.
- `_same_option()` dropped `action="append"` when copying options to the
  `web` alias, so repeatable flags collapsed to a bare string and would
  have been iterated one character at a time.

## [0.5.0] — 2026-09-25

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

[Unreleased]: https://github.com/Zaidux/miniproxy/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.8.0
[0.7.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.7.0
[0.6.3]: https://github.com/Zaidux/miniproxy/releases/tag/v0.6.3
[0.6.1]: https://github.com/Zaidux/miniproxy/releases/tag/v0.6.1
[0.6.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.6.0
[0.5.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.5.0
[0.4.0]: https://github.com/Zaidux/miniproxy/releases/tag/v0.4.0
