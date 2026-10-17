# Diff

Diff compares two captures and tells you what changed. It is built for the
access-control workflow: send the same request twice with one thing different,
then stop eyeballing two pages and read the difference.

The reference version is in [Web UI → Comparing two
captures](../web-ui.md#comparing-two-captures).

## Start from two captures

This page covers comparing two rows from the capture table. A response you got
from the Repeater is not a capture, so it is not part of this workflow.

To compare "user A" with "user B", get both exchanges into the capture
database: browse them, or send them with `curl -x http://127.0.0.1:8080`.
Then select one and compare it with the other.

The same capture cannot be both sides. The UI refuses to run in that case, and
the API returns `pick two different captures to compare`.

**Two Intruder results can also be compared with each other**, using the same
views, from the Intruder results table: tap two rows and press **Compare A / B**.
That is the quickest way to read a username-enumeration finding. See
[Intruder → Comparing two results](intruder.md#comparing-two-results). A capture
and an Intruder result still cannot be mixed — they are different kinds of row.

## Open a comparison

**What it's for.** Set **A** and **B** and get a result.

**How to use it.**

1. Open the **Diff** tab, or hand it a capture from somewhere else:
   - **Compare…** in the Live detail pane (sets **A** to the selected capture);
   - **Compare** in the **⋮** row menu (sets **A**);
   - **Compare…** in the Repeater tab (sets **A** to the capture selected in
     Live; see the note below).
2. Click **Pick…** next to **A** and choose a capture.
3. Click **Pick…** next to **B** and choose another.
4. Wait for the result. It runs automatically once both sides are set.
5. Use **⇄ Swap** to exchange A and B. "Only in A" becomes "only in B", so the
   direction matters.
6. Read the summary in the **Compare captures** header, then the tabs below.

**Worked example.** While logged in as user A, open `/account?id=1` and
`/account?id=2` in the browser (both through the proxy). Select capture #20
(id=1), click **Compare…**, and pick #21 as **B**.

**What to look for.** The summary names the difference, for example
`status 200 → 403`, `1 param(s): id`, `JSON role: 'user' → 'admin'`, or
`3 token(s) differ: alice, balance, 1200`. If nothing differs, it says
`identical`.

**Common mistakes / notes.**

- **The picker only lists captures**, and it is seeded from the Live filters.
  If **B** is missing, widen the filters or untick **Use the Live tab filters**
  in the picker.
- **Repeater's Compare… is not a comparison of its last response.** It uses the
  capture currently selected in Live as **A**. If nothing is selected it says
  `Select a captured row in Live first`.
- **Compare… can carry over the previous B.** If you have already compared two
  captures, handing in a new **A** can immediately run against the old **B**.
  Check both labels before reading the result.
- Pending captures have no status and an empty body. Comparing one is usually
  noise; wait for the response.
- Bodies are stored truncated at 100,000 characters by default. The diff only
  sees the stored part.

## Read "What changed"

**What it's for.** One table with everything that differs, in the order you
would look for it. This is the default pane and usually the answer.

**How to use it.**

1. Stay on **What changed**.
2. Read the **What** column, then the **A** and **B** columns.
3. The section labels are literal:
   - `status` — the HTTP status changed.
   - `path` — the URL path changed.
   - `param`, `param +`, `param -` — a query parameter changed, was added, or
     was removed.
   - `header`, `header +`, `header -` — a **response** header changed, was
     added, or was removed.
   - `json`, `json +`, `json -` — a JSON field changed, was added, or was
     removed. **Only shown when the chosen mode is JSON.**

**Worked example.** A role-escalation lab returns
`{"user":"alice","role":"user"}` for one request and
`{"user":"alice","role":"admin"}` for another. The table shows
`json · role` with `user` in A and `admin` in B.

**What to look for.** A row whose A and B values are meaningfully different.
`param +` / `header +` are often the finding: something appears only when you
change the parameter.

**Common mistakes / notes.**

- **When the body mode is Tokens or Bytes, this table does not include body
  differences.** It covers status, URL params, response headers, and JSON
  fields (JSON mode only). If only the HTML body differs, this pane can say
  `Identical.` while the header summary says tokens differ. Check the
  **Tokens** or **Bytes** pane before concluding nothing changed.
- `header` means **response** headers. Request headers are not compared.
- `param` means the **URL query string**. Parameters in a request body are not
  compared.
- The table has no expandable groups; a long diff is one long table.

## JSON mode

**What it's for.** Structural comparison of two JSON responses, keyed by dotted
path. It answers "which field changed?" without making you read either body.

**How to use it.**

1. Compare two captures whose response bodies both parse as JSON.
2. Open the **JSON** tab.
3. Read the table: `What` is the dotted path (for example `user.role` or
   `items.0.price`), `A` is the left value, `B` the right.

**Worked example.** An API returns an `is_admin` boolean. Capture the response
before and after changing your role, diff them, and the JSON tab shows
`is_admin` with `false → true` and nothing else changed.

**What to look for.** Paths with a real value change. Arrays are flattened by
index (`items.0.name`), so a shifted array shows as many changed paths.

**Common mistakes / notes.**

- This pane only works when **both** bodies parse as JSON. If either one is
  HTML, it says `Neither body is JSON — try Tokens or Bytes.`
- The comparison mode is chosen automatically: JSON if both bodies parse,
  Tokens whenever either body has content, and Bytes only when both bodies are
  empty. **The dashboard does not let you force a mode.** The tabs are views of
  the chosen result, not mode switches. If you need a token-level view of two
  JSON bodies, the API accepts `?mode=token`, but the dashboard will not ask
  for it.
- A body that is not valid JSON falls back to Tokens, and the JSON pane then
  says neither body is JSON.
- Large JSON bodies are truncated by the capture cap, which can make the body
  invalid and drop the comparison to Tokens.

## Tokens mode

**What it's for.** Word-level comparison for HTML and text. It finds the words
that are present on one side and not the other, even in minified markup.

**How to use it.**

1. Compare two captures whose bodies are not both JSON (typically HTML).
2. Open the **Tokens** tab.
3. Read the words. Normal text is in both; **orange** words appear only in
   **A**.

**Worked example.** A login failure page says `Invalid username or password`.
A valid username with a wrong password says `Incorrect password`. Diff the two
responses: the Tokens pane marks `Invalid`, `username`, and `or` as only in A.

**What to look for.** A small cluster of orange words that differs between the
two responses. That cluster is the message that distinguishes the cases, which
is exactly what username enumeration depends on.

**Common mistakes / notes.**

- **It is one-directional.** It lists the tokens of **A** that are missing from
  **B**. A word that appears only in **B** is not shown at all. Swap A and B to
  see the other direction.
- Punctuation and markup characters are token boundaries (`<>()[]{}"',;=&|`),
  so minified HTML still localises the change instead of reporting one blob.
- The comparison is a set membership test, not a positional diff: it tells you
  a word is new, not where it moved.
- Up to 4,000 tokens of A are compared; the pane renders at most 3,000 of them.
  A very large body is silently clipped.
- This pane is only populated when the chosen mode is Tokens. In JSON mode it
  says `No token view — use Bytes.`

## Bytes mode

**What it's for.** The two response bodies side by side, in full, so you can
read the exact text or look for an offset yourself.

**How to use it.**

1. Open the **Bytes** tab.
2. Read the two boxes: **A body** and **B body**.
3. Scroll each box independently.

**Worked example.** You know a token differs somewhere but the Tokens pane is
too coarse. Open **Bytes**, put the two bodies side by side on a laptop, and
read the differing region. On a phone the boxes stack, so scroll one at a time.

**What to look for.** The exact differing substring. The server *can* return a
character-level result with a byte offset ("bodies differ at byte N"), but the
dashboard always asks for the automatic mode, so you will normally get the
JSON or token summary instead. This pane does not depend on that result.

**Common mistakes / notes.**

- **Despite the name, this pane is a plain side-by-side viewer.** It does not
  highlight changed bytes or align the two bodies. You find the difference by
  reading.
- A "byte offset" in a summary is a character index, not a jump target, and it
  is not marked in these boxes.
- On a narrow screen the two boxes stack vertically.
- Truncated bodies are shown truncated.

## Params mode

**What it's for.** Compare the URL: the query parameters and the path. This
often names the exact thing you flipped without making you read either URL.

**How to use it.**

1. Open the **Params** tab.
2. Read the summary line: `Same path: /account` or
   `Path changed: /account → /admin`.
3. Read the table: the parameter name, its A value, and its B value. An added
   parameter shows `—` in A; a removed one shows `—` in B.

**Worked example.** You changed `?id=1&debug=0` to `?id=2&debug=1`. The Params
pane shows both `id` (`1 → 2`) and `debug` (`0 → 1`), and tells you the path
did not change.

**What to look for.** The parameter you intended to change, and any parameter
that appeared or disappeared unexpectedly. An added `admin=1` is a finding.

**Common mistakes / notes.**

- It reads the URL only. A form-encoded or JSON **request body** is not a
  parameter here.
- Repeated parameter names collapse to one value (the last one), because the
  URL is parsed into a name→value map.
- `/account/1` and `/account/2` are a **path** change, not a parameter change.
  Different paths through the same route show up as `Path changed`.
- The path line is informative even when no parameters differ.

## Headers mode

**What it's for.** Compare **response** headers: additions, removals, and value
changes.

**How to use it.**

1. Open the **Headers** tab.
2. Read the table: header name, A value, B value. An added header shows `—` in
   A; a removed one shows `—` in B.
3. For the `header +` / `header -` labels, use the **What changed** pane; this
   pane shows only names and values.

**Worked example.** Two requests return the same page, but one sets a
different `Set-Cookie` or adds `X-Cache: HIT`. The Headers pane names it.

**What to look for.** A `Set-Cookie` that only appears for the privileged
request, a `Location` that differs, a content type that changes from HTML to
JSON, or a cache header that explains why two "different" responses are
identical.

**Common mistakes / notes.**

- **These are response headers.** Request headers (including your cookies) are
  not compared here, even though changing one is often what caused the
  difference.
- Header names are compared case-insensitively, as HTTP requires.
- Header order is not compared.
- A missing header and a header with an empty value are different things: the
  former is `header +`, the latter is `header` with an empty string.

## The summary line, and what "identical" means

**What it's for.** A one-line verdict at the top of the tab, so you can decide
whether to dig in.

**How to use it.** Read the coloured line next to **Compare captures**. Green
means identical; orange means something differs. It names up to a few concrete
differences rather than only counting them.

**Worked example.** `1 param(s): id · JSON role: 'user' → 'admin'` tells you
the request differed by `id` and the response role changed. You do not need to
open a pane to know where to look.

**What to look for.** The field names, not just the counts. A count alone ("1
field differs") is not a finding.

**Common mistakes / notes.**

- The server's "identical" verdict also includes the **request bodies**. There
  is no pane that shows request-body differences, so a comparison can be
  reported as not identical while every visible pane looks the same. If that
  happens, the two requests were sent with different bodies.
- "Identical" means status, response headers, URL params, response body, and
  request body all match. It does not mean the two requests were the same
  request; only that nothing captured differs.
- Two captures with the same body but different response **times** are
  identical for this purpose. Timing is not diffed.
- The mode is chosen server-side (JSON → Tokens → Bytes). The visible tabs do
  not change it.

Next: [Noise control](noise.md).
