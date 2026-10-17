# Rewrite

Rewrite changes requests **while they are in flight**, before they reach the
target. The upstream server sees the modified request. It is for the values you
would otherwise retype in Repeater forty times: a role, a version header, a
redirect target.

The reference is in [Web UI → Match & replace](../web-ui.md#match--replace).

## What it can and cannot touch

It can rewrite, on requests that pass through the proxy:

- a **header value** (with Exact on a header, the whole value of an existing
  header);
- the **URL** (path, query string, or even the host, because it works on the
  URL string);
- the **body** (text bodies).

It cannot rewrite:

- responses;
- requests sent by the Repeater or the Intruder (they do not go through the
  proxy);
- request bodies that cannot be round-tripped as text (the proxy leaves those
  alone rather than corrupting them).

## Add a rule

**What it's for.** Teach the proxy a match-and-replace pair. Every matching
request is changed from then on.

**How to use it.**

1. Open the **Rewrite** tab (or click **Rewrite…** in the Live filter bar).
2. Choose a **Target**: **Header**, **Query / URL**, or **Body**.
3. Choose a **Kind**: **Exact**, **Contains**, or **Regex**.
4. Type the **match** (the placeholder says `match (name or substring)`).
5. Type the **replace with** value.
6. Click **Add**.
7. Check the rule appears in the list with `N of M active` in the header.

On a phone, the Target and Kind selects and the match/replace fields wrap onto
separate lines. The order is still target, kind, match, replace, **Add**.

**Worked example.** A lab hides an admin panel behind a `role=user` body
parameter. Target **Body**, Kind **Contains**, match `role=user`, replace
`role=admin`. Click **Add**, then reload the page through the proxy. The
captured request now carries `role=admin`, and the server treats you as an
admin.

**What to look for.** The new rule is listed and enabled, the count increases,
and the next proxied request shows the replacement in **Live** (the captured
request is the rewritten one, not the original). A toast says
`Rule active on new traffic`.

**Common mistakes / notes.**

- **Rules take effect immediately for new traffic.** There is no staging or
  preview. A broad rule can break every site you browse while it is enabled.
- **Only requests through the proxy are affected.** Testing a rule by resending
  the request in Repeater proves nothing, because Repeater bypasses the proxy.
- Rules are applied in the order they were created (oldest first). Two rules
  that match the same text can interact; the first one changes what the second
  sees.
- The match is a literal string for **Exact** and **Contains**. It is
  case-sensitive, except for the header **name** in the Exact header case.

## Header rules

**What it's for.** Change a header on every request. The three kinds mean
different things here, and this is the part people get wrong.

**How to use it.**

1. Target **Header**.
2. Kind **Exact**: the **match** is the header **name**, and **replace with**
   is its new, complete value.
3. Kind **Contains** or **Regex**: the **match** is applied inside every header
   **value**.
4. Add the rule and send a request through the proxy.

**Worked example.** A lab only renders the mobile site for a mobile user agent.
Target **Header**, Kind **Exact**, match `User-Agent`, replace with a mobile
UA string. The browser's next request goes out with that value.

**What to look for.** Open the request in **Live** and read the headers. The
value is the one you set. If the site's response changes, the server honoured
it.

**Common mistakes / notes.**

- **No header rule can add a header; they only change headers that are already
  there.** The code walks the existing headers and changes their values. Exact
  matches the **name**; Contains and Regex match inside the **value**. A rule
  for `X-Forwarded-For: 127.0.0.1` does nothing if the browser never sent
  `X-Forwarded-For` in the first place. Browsers usually do not. To add a
  missing header, use Repeater (once) or a tool that can inject it.
- Exact matches the header **name** case-insensitively. The header keeps its
  original spelling; only the value changes.
- Contains replaces **every occurrence** of the substring inside each matching
  header value. It does not replace the whole value.
- Regex uses Python's `re` syntax on each header value. A replacement can use
  groups (`\1`, `\g<name>`). An invalid regex is rejected when you add the
  rule, so you find out immediately.

## Query / URL rules

**What it's for.** Rewrite the URL string: a parameter value, a path segment,
or a version prefix.

**How to use it.**

1. Target **Query / URL**.
2. Kind **Contains**: match a literal substring of the whole URL.
3. Kind **Regex**: match with a Python regex over the whole URL.
4. Add, then send traffic through the proxy.

**Worked example.** An API moved from `/api/v1/` to `/api/v2/`. Target
**Query / URL**, Kind **Contains**, match `/api/v1/`, replace `/api/v2/`. Every
proxied request goes to the new prefix.

Or, for an IDOR check you want to automate: match `id=1` and replace `id=2`.
Every request that contains it is changed before it leaves the proxy.

**What to look for.** The **Path** column and the request line in **Live** show
the rewritten URL. The target responds as if it received the new URL.

**Common mistakes / notes.**

- **It is a raw string replacement over the entire URL**, not a parsed
  parameter editor. `id=1` also matches `userid=1`, and it can rewrite the
  host if that substring appears there. Be specific.
- **Exact and Contains do the same thing for this target.** The special
  name-matching behaviour only exists for headers.
- A rule matching a common substring can hit every request in the session. Use
  a full path (`/account?id=`) rather than `id=`.
- Percent-encoding is whatever the browser sent. `§` and spaces are usually
  encoded before the proxy sees them, so match the encoded form when in doubt.
- Regex replacements are applied with `re.sub`, so `\1` and friends work, and a
  pattern that matches an empty string can insert text everywhere.

## Body rules

**What it's for.** Change the request body: a form field, a JSON value, a
serialized object.

**How to use it.**

1. Target **Body**.
2. Kind **Contains** for a literal substring, **Regex** for a pattern.
3. Add the rule and send a request through the proxy.

**Worked example.** A JSON API takes `{"role":"user"}`. Target **Body**, Kind
**Contains**, match `"role":"user"`, replace `"role":"admin"`. Make sure the
match includes the quotes and colon exactly as they appear in the body (no
spaces, in this example). Then trigger the request in the browser.

**What to look for.** The **Request** detail tab in **Live** shows the modified
body. The server's response reflects the new value.

**Common mistakes / notes.**

- The match is literal for Contains. A body with different whitespace will not
  match. Use a regex if the formatting varies.
- **Text only.** If the body cannot be set back as text (binary upload), the
  proxy keeps the original rather than corrupting it, and the rule silently
  does not apply.
- Form bodies are one line: `role=user&name=x`. Match the `&` boundaries or use
  a regex, so `role=user` does not also match `role=user_admin`.
- **The capture can show a stale `Content-Length`.** mitmproxy recalculates
  the real header when the body is changed, so the request that reaches the
  server is correct. But the dashboard stores the header map it copied before
  the rewrite, so the **Request** detail tab can show the old length next to
  the new body. Trust the body, not that number.
- Like all rules, this one applies to every proxied request with that text,
  including requests to other hosts in the same browsing session.

## Manage the rules

**What it's for.** Turn rules off when you are done, and remove the ones you no
longer need. An enabled rule is invisible in the target but active on every
request.

**How to use it.**

1. Open the **Rewrite** tab.
2. Untick a rule's checkbox to disable it (`Rule disabled`), tick it to enable
   it (`Rule active`).
3. Click **Remove** to delete it permanently.
4. Read the header count: `N of M active`.

**Worked example.** You forced an admin role for one lab step. Untick the rule
before you go back to browsing, or every subsequent request will carry the
rewritten value and other labs will behave strangely.

**What to look for.** The count drops, and new requests in **Live** show the
original values again. Requests already captured keep the rewritten values;
disabling a rule does not retroactively change stored rows.

**Common mistakes / notes.**

- **A rule is active on all proxied traffic, not just the current tab or host.**
  There is no per-site scoping and no "only this request" mode.
- Disabling does not undo a capture. The stored request is what was sent at the
  time.
- Removing a rule is immediate and cannot be undone from the UI. Recreate it if
  needed.
- The rules are stored in the database, so they survive a dashboard restart.
  They are per database, not per browser.
- There is no import/export for rules. If a rule set is valuable, keep the text
  in your lab notes.

Next: [Connect](connect.md).
