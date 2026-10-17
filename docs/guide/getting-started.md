# Getting started

MiniProxy is an HTTP/HTTPS proxy with a web dashboard. You point a browser (or
`curl`, or your phone) at the proxy. Every request that client sends passes
through MiniProxy and is recorded in a local database. The dashboard is a
window onto that database: you read requests, search them, replay them, fuzz
them, and mark the interesting ones.

The same database is shared by the dashboard, the TUI, and the CLI. They do
not each have their own copy.

## 1. Install

Python 3.10 or newer is required, plus `mitmproxy` (which provides the
`mitmdump` binary).

```bash
pipx install riciplay-miniproxy
# or, if you manage your own virtualenv:
pip install riciplay-miniproxy
# or, via npm (it installs the Python package):
npm install -g riciplay-miniproxy
```

`pipx` is the safest choice on Debian 12+/Ubuntu 23.04+, where a plain
`pip install` refuses to touch the system Python. The full set of install
options, including the "externally-managed-environment" error, is in
[Setup](../setup.md).

Check that both halves exist:

```bash
miniproxy --help
mitmdump --version
```

**Common mistakes / notes.**

- If `miniproxy start` fails saying `mitmdump` was not found, install
  `mitmproxy` in the same environment (`pipx inject riciplay-miniproxy
  mitmproxy`, or `pip install mitmproxy` inside the venv).
- The npm package is only a launcher. The real code is the Python package.

## 2. Start the proxy and the dashboard

```bash
miniproxy start
```

You should see something like:

```
MiniProxy started on :8080 (PID 12345, db=/home/you/.miniproxy/proxy.db)
Web UI: http://127.0.0.1:5000   ← paste this into your browser to use MiniProxy
Connect: http://127.0.0.1:5000/connect   — wizard to route any other device
```

Two processes are now running:

- the **proxy** on port `8080` — clients send their traffic here;
- the **dashboard** on port `5000` — you read the captures here.

Capture is always on while the proxy runs. There is no "pause capture" button;
the dashboard does not decide what is captured. (It can send its own Repeater
and Intruder requests, but those bypass the proxy and are not captured.)

Open the printed Web UI URL. The header bar tells you what you are looking at:

- the dot and the text next to **MiniProxy**: green with `proxy running :8080`
  when the proxy is up, grey with `proxy stopped` when it is not;
- the **Start** / **Stop** button next to it;
- the database path, dimmed on the right of the proxy state (hover it for the
  full path).

**Common mistakes / notes.**

- **The header Start/Stop button uses defaults.** It starts the proxy on
  `127.0.0.1` at the default port (`8080`, or the next free one) with the
  default database and no scope or bind flags. If you started the proxy with
  custom flags (a different port, a lab database, `--proxy-host 0.0.0.0`,
  `--scope`), stop and start it with `miniproxy stop` / `miniproxy start …` in a
  terminal instead. Restarting from the header silently drops those flags.
- Stopping from the header stops the proxy but leaves the dashboard open, so
  you can keep reading captures.
- `miniproxy stop` stops both.

## 3. Point a client at the proxy

**What it's for.** Make the browser (or tool) send its traffic to MiniProxy
instead of straight to the site.

**How to use it.**

1. Start MiniProxy (above).
2. Set an **HTTP proxy** to `127.0.0.1` port `8080` in the client.
   - Firefox: Settings → Network Settings → Manual proxy configuration.
   - Chrome/Edge: use the OS proxy settings, or the **PAC URL** from the
     dashboard's **Connect** tab.
   - `curl`: add `-x http://127.0.0.1:8080` to the command.
3. If the client is a **phone or another machine**, see the mobile note below.
4. Browse to your lab.

**Worked example.** Prove the loop with `curl` before touching a browser:

```bash
curl -x http://127.0.0.1:8080 https://api.github.com/zen
```

**What to look for.** Within about two seconds a new row appears at the top of
the **Live** tab with status `200`, the host `api.github.com`, and the path
`/zen`. If it does, the proxy and the capture database are wired correctly.

**Common mistakes / notes.**

- **The proxy is not on your phone just because the dashboard is.** Since
  0.6.0 the proxy binds `127.0.0.1` only. To let a phone on the same Wi-Fi use
  it, start MiniProxy so the proxy listens on the LAN **and** fence it off:

  ```bash
  miniproxy start --proxy-host 0.0.0.0 \
                  --dashboard-host 0.0.0.0 --dashboard-token <random-string>
  ```

  Then restrict port `8080` at the host firewall to the phone's address, and
  remove the rule when you are done. A proxy bound to `0.0.0.0` is reachable by
  anything that can reach that port: it is an open relay, and anyone who can
  use it can write to your capture database. The safer pattern is an SSH
  tunnel, which exposes nothing:
  `ssh -N -L 8080:127.0.0.1:8080 user@host`. Full per-platform steps:
  [Connect](../connect.md).

  Do **not** use `--allow-client` as a client allowlist. It is passed to
  mitmproxy's `allow_hosts` option, which filters **destination** hosts, not
  the addresses of clients that may connect. A phone's IP in that list does not
  fence the proxy off and can stop it working at all. Use a firewall, or a
  tunnel.
- **Android keeps proxy settings per Wi-Fi network.** Mobile data cannot be
  pointed at an HTTP proxy without a VPN app.
- **The PAC file deliberately sends localhost direct.** That is why opening the
  dashboard itself does not loop through the proxy.
- **If the dashboard needs a token**, it asks once when you do something that
  changes state (start the proxy, send a request). Read-only pages and exports
  stay open. The token is kept in the browser's local storage for that session.

## 4. Trust the CA so HTTPS bodies are readable

**What it's for.** HTTPS is encrypted end to end. MiniProxy can only show you
the request and response bodies if the client trusts MiniProxy's own
certificate authority (CA).

**How to use it.**

1. Open the **Connect** tab.
2. Under **3 · Trust the CA (HTTPS bodies)**, click **Download CA**.
3. Install and trust that certificate on the device whose traffic you are
   capturing. On Android: Settings → Security → Encryption & credentials →
   Install a certificate → CA certificate. On Firefox: Settings → Privacy &
   Security → Certificates → View Certificates → Import.
4. Restart the browser if it does not pick the CA up immediately.

**Worked example.** Open any HTTPS lab page. In **Live**, select the request
and open the **Response** detail tab. The body should be readable HTML. With
the CA downloaded but not trusted, you usually see only a `CONNECT` row, or a
TLS error.

**What to look for.** The **Response** tab shows headers and a body, not
`(pending)` and not a transport error. The request's method is the real method
(`GET`, `POST`), not `CONNECT`.

**Common mistakes / notes.**

- Without the CA, HTTPS still routes and is still captured at the connection
  level (method, host, status, timing), but the bodies are encrypted and
  unreadable.
- On Android 7+, most **apps** ignore user-installed CAs. Browsers honour them.
  This workflow is for browser traffic, not arbitrary apps.
- If the Connect tab says no CA was generated yet, run `mitmdump` once on the
  proxy host (Ctrl+C after a second) and reload the page.

## 5. Confirm capture, then get to work

**What it's for.** Know that what you see is what the target received, before
you spend an hour on a lab.

**How to use it.**

1. Open the **Connect** tab.
2. Click **Send one proxied test request**.
3. Read the result next to the button.
4. Switch to **Live** and find the test request.

**Worked example.** The button sends a request to
`https://api.github.com/zen` from the machine running the dashboard. It is a
quick end-to-end check of "proxy running, database writable, dashboard
reading the right database".

**What to look for.** The line says `✔ captured — HTTP 200 (N B)`, and a row
appears in **Live**. If it says `✘`, the proxy is not running on that host, or
the machine cannot reach the internet through it.

**Common mistakes / notes.**

- This button proves the **proxy host** works. It does not prove your phone is
  configured. For the phone, browse a site and check **Live**.
- The dashboard shows a database path in the header. If you have more than one
  database (for example `--db /tmp/lab.db`), make sure the proxy was started
  with the same one. Rows "missing" are very often two different databases.
- **Captures are pruned automatically.** The defaults are 5,000 rows, 7 days,
  or 50 MB, whichever limit is hit first. Housekeeping deletes the oldest
  captures and their Intruder results without a prompt. If a lab relies on
  old traffic, export it (see [The Live tab](live-tab.md#export-or-clear-captures)).
  The limits are environment variables: `MINIPROXY_MAX_ROWS`,
  `MINIPROXY_MAX_AGE_DAYS`, `MINIPROXY_MAX_DB_BYTES`.
- If nothing appears at all, the maintainer
  [Troubleshooting](../troubleshooting.md) page covers the usual causes: a
  stopped proxy, the wrong port, a PAC that points at an unreachable address,
  and `mitmdump` missing.

## 6. Keep a lab separate (recommended)

Use one database per lab, and scope the capture to the target:

```bash
miniproxy start --db ~/labs/idor.db --scope '*.target.example'
```

`--scope` means only hosts matching that pattern are captured. Out-of-scope
traffic still flows, but it never reaches your database. That keeps a whole
browser session from burying the target. Add `--block-out-of-scope` if you
want out-of-scope requests to get a 403 instead of being passed through.

With the dashboard open, `--scope` is not a dashboard control; it is a start
flag. Restart the proxy with the flag, and use
[Noise](noise.md) for the junk that is already in the database.

Next: [The Live tab](live-tab.md).
