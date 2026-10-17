# Common workflows

These are end-to-end recipes that combine the tabs. They assume you have
already done [Getting started](getting-started.md) and that the lab is one you
are authorised to test.

Every workflow below starts from a captured request. That is the MiniProxy
model: capture first, then replay, fuzz, or compare.

## Username enumeration

**Goal:** find which usernames exist, using the difference between "no such
user" and "wrong password".

**Steps.**

1. Submit the login form once with a made-up username. Find the `POST /login`
   in **Live** and confirm it is there.
2. Select that capture and click **To Intruder**. The Intruder tab's boxes fill
   from it. Edit them: put `§user§` where the username goes in **Body** (or
   **URL** for a GET login), and keep the session `Cookie` in **Headers**.
   These boxes are what the attack sends, so nothing else is needed.
3. Choose **Single list** and paste the candidate list the lab gives you, or
   click a bundled list to start. Up to 1,000 words.
4. Click **Start attack** and wait for the count to settle.
5. Tick **only size outliers** above the results table. The table collapses to
   the responses that are not like the rest. Read the line under the controls:
   it tells you the common size and how many rows differ.
6. Narrow further with **Status** if useful — `3xx` catches the lab that
   redirects on success.
7. Tap the surviving row and its most boring-looking neighbour, then press
   **Compare A / B**. The Diff tab names the difference outright:

   ```
   status 302 → 200 · 1 param(s): username · JSON error: 'Invalid password' → 'Invalid username'
   ```

**What to look for.** A small group of rows whose response is a different
length or status from the majority. A valid username might return
`Incorrect password` while invalid ones return `Invalid username`. The body
difference is the signal, not the status code.

**Common mistakes / notes.**

- If every result is identical, there was no marker in the request. Open
  **View** on the first result and read **Request sent**. **Start attack**
  refuses to run a marker-less request, so if the attack ran at all, a marker
  was present.
- The bundled username list is a starting point. For a real lab, paste the
  candidate list the lab gives you.
- Size is character count. Use it to find outliers, not to measure bytes.
- If the filter leaves nothing, every response was the same size — the
  difference is in the body, not the length. Use **Compare A / B** on any two
  rows and read the **What changed** view.
- Intruder does not follow redirects. If the lab answers `302`, that is
  visible and useful.
- Some labs deliberately return the same length and status for valid and
  invalid users, and differ only in timing or in a header. Those need a
  different approach; the size filter will honestly report that nothing stands
  out rather than inventing an answer.

## Password guessing

**Goal:** find the password for a confirmed username.

**Steps.**

1. Capture the login once in the browser, select it in **Live**, and click
   **To Intruder**. In the Intruder tab, put two markers in the **Body**:

   ```
   username=§user§&password=§pass§
   ```

   (For a GET login, put them in **URL** instead. Keep the session `Cookie` in
   **Headers**.) These boxes are what the attack sends, so there is no need to
   rebuild the request anywhere else.

2. Click **Pitchfork**. A row appears for each marker.
3. For `§user§`, press **Paste** and paste the confirmed username — or a short
   list if you have not confirmed one yet.
4. For `§pass§`, press **Paste** and paste the password list. A caret in the
   list shows the word count before you commit it.
5. Check the product line. With one username and the bundled 26-password list
   it reads `1 list(s) → 26 requests`; with two names it is `52`.
6. Click **Start attack** and wait. Requests are sent one at a time, so this
   takes noticeably longer than the enumeration did.
7. Read the results: tick **Status → 3xx** to pull out the redirects, or tick
   **only size outliers** for labs that stay at `200` and differ only in body.
8. Tap the winning row and any failing row, then **Compare A / B** to see the
   difference stated outright.

**What to look for.** A `302` where the failures are `200`, or a response body
that says "welcome" instead of "invalid". The **Payload** column labels the
pair (`user=alice | pass=secret`), so you can read the winner directly.

**Common mistakes / notes.**

- **The 10,000-combination cap.** 31 usernames × 1,000 passwords is 31,000 and
  will be refused. Use one username and a long password list, or trim both.
- The bundled password list is 26 obvious defaults. It will not contain a real
  lab password. Paste the lab's list or a wordlist you are allowed to use.
- To see response **headers** (such as `Set-Cookie`), the results table is not
  enough. Open the base capture in [Repeater](repeater.md), put the winning
  pair in the body, send, and read the headers there.
- There is no rate-limit control. Do not run this against a system you do not
  own or have permission to test.

## IDOR and access-control checks

**Goal:** prove that changing an identifier returns another user's data.

**Steps (quick check).**

1. Browse to your own object, for example `/account?id=1`, with the proxy on.
2. In **Live**, select the request and click **Repeater**.
3. Change `id=1` to `id=2` and click **Send**.
4. Compare the response body with the original.

**Steps (evidence you can diff).**

1. Browse to `id=1` and `id=2` in two browser tabs, both through the proxy.
2. In **Live**, select the `id=1` capture and click **Compare…**.
3. In **Diff**, pick the `id=2` capture as **B**.
4. Read **What changed**; open **JSON** if both bodies are JSON, or **Tokens**
   for HTML.
5. Highlight the divergent capture and write a **Note**.

**What to look for.** A different username, email, balance, or order list in
the other object. A `200` for both is normal; the content is the finding. A
`403` for `id=2` and `200` for `id=1` means the access control is working.

**Common mistakes / notes.**

- **Repeater responses are not captures**, so a Repeater exchange cannot be a
  Diff side. Use the browser (or `curl -x`) for both objects if you want to
  diff them.
- The Diff compares **response** headers only. A `Set-Cookie` difference is
  visible; a request-header difference is not.
- If the body is HTML and only the text differs, use the **Tokens** pane. The
  **What changed** pane covers status, URL, response headers and JSON, not
  HTML text.
- Changing the path (`/account/1` → `/account/2`) shows as a **path** change,
  not a parameter change.

## Hidden-parameter discovery

**Goal:** find a parameter the application accepts but does not advertise
(`admin=1`, `debug=true`, `role=user`).

**Steps.**

1. Find the request in **Live**, select it, and click **To Intruder**. In the
   Intruder tab, put `§param§` where a parameter *name* would go.

   For a GET, in **URL**:

   ```
   https://TARGET/api/user?§param§=1
   ```

   For a form POST, in **Body**:

   ```
   §param§=1
   ```

   Keep the session `Cookie` in **Headers** so the requests are authenticated.

2. Choose **Single list** and click the **Parameter names** card (40 names).
3. Click **Start attack**.
4. Tick **only size outliers** above the results. A parameter the app accepts
   usually shifts the response length or status; one it ignores returns the
   baseline exactly and disappears from the filtered view.
5. Press **Compare A / B** on an interesting row and a boring one to see what
   actually changed.
6. Take any interesting parameter to **Repeater** and try meaningful values
   (`admin=1`, `debug=true`), because `=1` may not be the value that triggers
   the behaviour.

**What to look for.** One response that is longer, shorter, a different
status, or contains a new field. A parameter that is silently ignored usually
returns the baseline response exactly.

**Common mistakes / notes.**

- Put the marker in the Intruder tab's URL or Body box. **Start attack** uses
  what is in those boxes, not the stored capture.
- A marker in a query string needs the parameter name position:
  `?§param§=1`, not `?x=§param§` (the latter fuzzes values, which is a
  different job).
- Parameter names are case-sensitive on many frameworks. The bundled list is
  lowercase.
- The request body must be the content type the server expects. `curl --data`
  sends form encoding; add `-H 'Content-Type: application/json'` for a JSON
  API, where `{"§param§":1}` substitutes into a valid JSON key. A form body is
  simpler if you are unsure.

## Find the leaked value or flag

**Goal:** locate a token, a password, or a flag somewhere in a large capture
set.

**Steps.**

1. In **Live**, tick **Hide static** and focus the target host.
2. Type a fragment into **Search bodies…**: `flag`, `CTF{`, `token`, `secret`,
   or a value you saw in the page.
3. Open the matching rows and use **Pretty** or **Raw** in **Response**.
4. Highlight the finding, add a **Note**, and export the marked set:
   **Highlighted** → **Export ▾ → HAR 1.2**.

**What to look for.** A row whose response contains the value, often a JSON
field or an HTML comment. **Raw** is useful when the value is hidden by
escaped characters.

**Common mistakes / notes.**

- Body search covers the stored request and response bodies only. It does not
  search headers, notes, or the URL.
- Bodies are capped at 100,000 characters, and static assets have no body at
  all. A flag inside a JS bundle will not be found this way; use the browser's
  view-source or `curl` for that.
- The HAR/JSON export is capped at 1,000 rows by default. Narrow the filters
  first.

## Test a redirect or an open redirect

**Goal:** see where a `302` really goes, and whether you can control the
destination.

**Steps.**

1. Capture the request that returns the redirect.
2. In **Repeater**, leave **Follow redirects** off for the first send and read
   the `Location` header in the response.
3. Change the redirect parameter (`next=`, `url=`, `return=`) and send again.
4. Tick **Follow redirects** to confirm the final destination.

**What to look for.** A `Location` that points at a host you supplied, or at
`//evil.example`. The first response's headers are the evidence; the followed
response shows the impact.

**Common mistakes / notes.**

- Repeater shows only the **final** response when following; the chain is not
  rendered in the dashboard. Read the first hop's `Location` before following.
- Repeater does not use the proxy, so this test is not captured. If you need a
  record, `curl -i -x http://127.0.0.1:8080` the same request.
- A redirect to a login page is not an open redirect. Check the host, not just
  the path.

## Keep a lab session tidy

**Goal:** spend your time on the target, not on browser noise.

**Steps.**

1. Start the lab with its own database and a scope:
   `miniproxy start --db ~/labs/lab1.db --scope '*.target.example'`.
2. In **Noise**, click **Enable bundled list** to stop common telemetry at
   capture time.
3. In **Live**, focus the target with **All hosts** and tick **Hide static**.
4. When the table gets crowded with old noise, run **Scan (dry run)** and read
   the per-host preview before **Delete N noise captures…**.
5. Highlight findings as you go and write short notes.
6. At the end, filter to **Highlighted** and export a HAR.
7. Start the next lab with a fresh database, or **Clear captures** (which also
   deletes Intruder results).

**What to look for.** A Live table with a handful of target rows, a Noise
preview that names only hosts you do not care about, and a short highlighted
list at the end.

**Common mistakes / notes.**

- **Cleanup always counts static assets as noise.** Read the preview before
  deleting.
- Noise rules affect only new traffic. Old rows need a cleanup.
- Captures are pruned automatically at 5,000 rows / 7 days / 50 MB by default.
  Export anything you need to keep.
- **Clear captures** is irreversible and ignores the current filters. It also
  deletes Intruder results, but not Repeater tabs or rules.

## A note on authorization

Everything here is for systems you own or are explicitly allowed to test: the
Web Security Academy labs, a bug-bounty program's in-scope hosts, or your own
applications. Intruder has no rate limiting, and Repeater/Intruder send
directly rather than through the proxy, so `--scope` and noise rules do not
protect a target from them. Keep the scope decision in your head, not only in
the tool.

Back to the [guide index](README.md). The words used above are defined in the
[Glossary](glossary.md).
