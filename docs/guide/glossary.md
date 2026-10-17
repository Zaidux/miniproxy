# Glossary

The words this guide uses, in the sense it uses them. Links point to the page
that explains the thing in context.

**Access control.** The rules that decide who may read or change what. "Broken
access control" means those rules can be bypassed, for example by changing an
ID.

**Body.** The part of a request or response after the headers. Form fields,
JSON, HTML and files live here. In the dashboard, the **Body** block under the
request line and under the response headers.

**CA (certificate authority).** The certificate that lets a client trust
MiniProxy's HTTPS interception. If the client does not trust it, HTTPS bodies
stay encrypted. See [Getting started](getting-started.md#4-trust-the-ca-so-https-bodies-are-readable).

**Capture.** One request/response pair recorded by the proxy, with an **ID**,
method, URL, headers, bodies, status, and timing. "Capture" and "row" mean the
same thing in this guide.

**CONNECT.** The HTTP method a client uses to ask a proxy for an HTTPS tunnel.
A `CONNECT` row in the capture table means the body was not decrypted, usually
because the CA is not trusted.

**Cookie / session cookie.** A value the server sets to recognise you on later
requests. Repeater has no cookie jar, so a captured `Cookie` header is what
keeps you logged in when you resend.

**CTF.** Capture the flag: a practice challenge where a hidden string is the
goal. Lab vocabulary, not a MiniProxy feature.

**Diff.** The comparison of two captures, or of two Intruder results. See
[Diff](diff.md).

**Dry run.** A preview that does not change anything. **Scan (dry run)** in the
Noise tab counts what a cleanup would delete.

**Fuzz / fuzzing.** Sending many variations of a request automatically and
looking for the one that behaves differently. The Intruder does this.

**HAR.** HTTP Archive, a JSON file format for captured traffic. Importable into
browser DevTools, Burp and other tools. **Export ▾ → HAR 1.2**.

**Header.** A `Name: Value` line in a request or response. Headers carry
cookies, content types, redirect targets (`Location`), caching rules, and more.

**Hidden parameter.** A parameter the application accepts but does not show in
its forms or links, such as `admin=1` or `debug=true`. See [Common
workflows](workflows.md#hidden-parameter-discovery).

**Highlight.** A colour marker on a capture row, stored in the database. Used
to group findings and filter with the **Highlighted** chip. See [The Live
tab](live-tab.md#highlight-a-capture).

**Host.** The server part of a URL (`lab.example`), without the path. The Live
table has a **Host** column and a host dropdown.

**IDOR (Insecure Direct Object Reference).** A broken-access-control bug where
changing an identifier (an order number, a user ID) gives you someone else's
object. The classic MiniProxy workflow is Repeater or Diff on `id=1` vs `id=2`.
See [Common workflows](workflows.md#idor-and-access-control-checks).

**In scope / out of scope.** Whether a host is part of the program you are
allowed to test. `--scope` limits what MiniProxy captures; it does not limit
what Repeater or Intruder will send.

**Intruder.** The fuzzing tab: `§placeholder§` markers plus a wordlist. See
[Intruder](intruder.md).

**Lab.** A deliberately vulnerable practice application, such as a PortSwigger
Web Security Academy exercise. Use MiniProxy only on labs and authorised
targets.

**Marker.** The `§name§` text the Intruder replaces. Same as
`§placeholder§`.

**Noise.** Traffic that is not the target: telemetry, ads, fonts, images, JS
bundles. See [Noise control](noise.md).

**Note.** Free text attached to a capture, saved in the database (up to 4,000
characters). A noted row shows 📝 after its path.

**Outlier.** A result whose response size differs from the most common size
among all the results. **only size outliers** in the Intruder results table
keeps exactly these, which is how a single valid username is picked out of
several hundred replies. Finding the outlier is the point of enumeration.

**PAC (proxy auto-config).** A small script, served at `/proxy.pac`, that tells
a browser or OS to send traffic through MiniProxy. See
[Connect](connect.md#use-the-pac-url).

**Path.** The part of a URL after the host, before the query string
(`/account`). The Live table shows it as its own column.

**Payload.** One word from a wordlist after it is substituted into the request.
The results table has a **Payload** column.

**Pitchfork.** Intruder mode with a different wordlist per placeholder,
combined as a product (usernames × passwords). See
[Intruder](intruder.md#pitchfork-mode).

**Placeholder (`§name§`).** The marker in a request where a payload goes. The
Intruder finds anything between two `§` characters. The name is a label, not a
variable you declare.

**Pretty / Raw / Hex.** The three body views in the Live detail pane. Pretty
re-indents JSON; Raw escapes control characters; Hex is a byte dump with
offsets. See [The Live tab](live-tab.md#read-a-request-and-a-response).

**Prune.** Automatic housekeeping that deletes the oldest captures when the
database hits its limits (5,000 rows / 7 days / 50 MB by default). It runs
without asking and takes Intruder results with it.

**Proxy.** The middleman that receives a client's requests and forwards them.
"Interception proxy" and "MITM proxy" mean the same thing here. MiniProxy is
the proxy plus a capture database and a dashboard.

**Query string.** The `?name=value&name=value` part of a URL. The Live table
shows it dimmed after the path. The Diff **Params** pane compares it.

**Repeater.** The edit-and-resend tool, in a modal and a full tab. See
[Repeater](repeater.md).

**Request / response.** What the client sends and what the server sends back.
A capture stores both.

**Rewrite.** Match-and-replace applied to requests in flight, before the
target sees them. See [Rewrite](rewrite.md).

**Scope.** The list of hosts you are allowed to (and want to) capture. See
`--scope` in [Getting started](getting-started.md#6-keep-a-lab-separate-recommended).

**Single list.** Intruder mode with one wordlist, substituted into every
placeholder. See [Intruder](intruder.md#single-list-mode).

**Static asset.** Images, fonts, CSS, JavaScript, audio and video. Their
bodies are not captured, and **Hide static** / cleanup can drop them from view.

**Status code / status class.** The three-digit HTTP result (`200`, `302`,
`404`, `500`). The class is the first digit: 2xx success, 3xx redirect, 4xx
client error, 5xx server error. MiniProxy also uses `0` for a transport error
and "pending" for no response yet.

**Token (dashboard).** The password for state-changing dashboard actions, set
with `--dashboard-token` / `MINIPROXY_DASHBOARD_TOKEN`. Not to be confused with
a session token or a CSRF token in a lab.

**Truncation.** MiniProxy stores at most 100,000 characters of a body. A
truncated body shows `⚠ truncated` and the original size. Search and diff only
see the stored part.

**TTFB / total.** Time to first byte and total request time, in milliseconds,
shown in the detail meta line. Useful for timing side-channels and for spotting
a slow endpoint.

**Wordlist.** The list of words or payloads the Intruder tries. Newline- or
comma-separated, `#` comments ignored, spaces kept, capped at 1,000 words per
list from the UI.

Back to the [guide index](README.md).
