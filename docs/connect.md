# Connect browsers & devices

MiniProxy is an HTTP proxy. **Any HTTP client pointed at it is captured** —
the browser on this machine, the browser on your phone, a laptop on the other
side of the internet, or `curl -x` in a script. This page walks through every
way to get traffic into the capture DB.

> You do **not** need a browser in your terminal, and the terminal is not
> "tunneled into" a browser. A proxy is a middleman: clients send their
> requests *to* MiniProxy, MiniProxy forwards them, and both legs are logged.
> The three entry points for connecting a client are:
>
> - the **Connect tab** in the web dashboard (`/connect`) — the full wizard
> - `miniproxy connect` — the same instructions in your terminal, with a QR
> - the **`w`** key in the TUI — a cheat-sheet overlay

## Start the proxy first

```bash
miniproxy start
# MiniProxy started on :8080 (PID 12345, db=/home/you/.miniproxy/proxy.db)
# Web UI: http://127.0.0.1:5000   ← paste this into your browser to use MiniProxy (mirrors `miniproxy tui`)
# Connect: http://127.0.0.1:5000/connect   — wizard to route any other browser/device through the proxy
```

The proxy listens on **all interfaces** (`:8080`), so other devices can reach
it at your machine's IP. The *dashboard* stays on `127.0.0.1:5000` unless you
explicitly expose it (see [Exposing the dashboard](#exposing-the-dashboard)).

## The Connect tab (dashboard wizard)

Open `http://127.0.0.1:5000/connect` (or click the **Connect** tab). It shows:

1. **Proxy address** — auto-detected from how you opened the page. If you
   reached the dashboard through an SSH tunnel or port-forward, the advertised
   address is already correct. Override it inline if the detection guesses
   wrong.
2. **Point the browser here** — a one-click **PAC URL**, manual host/port
   settings, and copy-paste `curl -x` / env-var one-liners.
3. **Trust the CA** — download `mitmproxy`'s CA straight from the dashboard
   (`/ca.crt`) with per-OS install steps, plus a **QR code** of the connect
   page for phones.
4. **Verify & pair** — one button sends a proxied test request so you can see
   capture working end-to-end; then name the device to mark it "paired".

Everything the wizard shows is also available as JSON at `/api/connect/info`.

## `miniproxy connect` (terminal)

```bash
miniproxy connect
```

prints the same instructions — proxy address, PAC URL, CA download, curl
one-liners — and, on an interactive terminal, a **scannable ANSI QR code** of
the dashboard's `/connect` page so a phone can jump straight to the wizard.

```bash
miniproxy connect --host 203.0.113.7 --port 8080   # override the advertised address
miniproxy connect --qr yes                         # force the QR (even when piped)
miniproxy connect --qr no                          # never print the QR
```

## Method 1 — PAC URL (easiest, one click)

A PAC (proxy auto-config) file tells a browser or OS *everything* to proxy
with one URL. MiniProxy serves it at `/proxy.pac`:

1. Copy the PAC URL from the Connect tab (e.g.
   `http://192.168.1.10:5000/proxy.pac`).
2. Paste it into the "automatic proxy configuration" setting:

   | Where | Path |
   |---|---|
   | Chrome / Edge | Settings → System → Open proxy settings → **Use setup script** |
   | Firefox | Settings → Network Settings → **Automatic proxy configuration URL** |
   | macOS | System Settings → Network → Wi-Fi → Proxies → **Automatic Proxy Configuration** |
   | Windows | Settings → Network & Internet → Proxy → **Use setup script** |
   | Android | Wi-Fi long-press → Modify → Advanced → Proxy: **PAC auto-config** |
   | iOS | Settings → Wi-Fi → (i) → Configure Proxy → **Automatic** |

3. Browse. Every request appears in the dashboard/TUI within a second.

Localhost traffic bypasses the proxy (the PAC returns `DIRECT` for it), so
opening the dashboard itself never loops.

## Method 2 — Manual proxy settings

Set an **HTTP proxy** to `<host>:8080` in the browser or OS network settings.
Same result as the PAC, just typed by hand. Chrome can also be launched with
the proxy baked in:

```bash
google-chrome --proxy-server=http://192.168.1.10:8080
```

## Method 3 — Terminal tools (curl -x and friends)

```bash
# one-off
curl -x http://192.168.1.10:8080 https://example.com

# everything in a shell
export http_proxy=http://192.168.1.10:8080 https_proxy=http://192.168.1.10:8080
curl https://api.github.com/zen && pip install requests   # both captured
```

More per-tool recipes (git, npm, Docker, Python `requests`) live in
[integrations.md](integrations.md).

## Method 4 — Phones & tablets (QR code)

1. Open the Connect tab (or run `miniproxy connect` in a terminal).
2. Scan the QR with the phone camera — it opens `/connect` on the phone.
3. Follow the on-page steps: tap the PAC URL or download the CA, set the
   proxy, browse.

## Connecting an Android browser (Chrome or Firefox) — incl. from a VPS

Android has no global proxy setting; the proxy is configured **per Wi-Fi
network** (mobile data cannot be pointed at a proxy without a VPN app).
Both Chrome and Firefox for Android follow that network proxy. Full
end-to-end walkthrough for the "MiniProxy runs on my VPS" case:

### 0 · On the VPS — start MiniProxy and open the firewall

```bash
miniproxy start --dashboard-host 0.0.0.0 --dashboard-token <random-string>
```

Then open **both** ports in the VPS provider's firewall/security group (not
just the OS one — this is the single most common reason a phone can't
connect):

- **8080/tcp** — the proxy itself (this is what your browser talks to)
- **5000/tcp** — the dashboard, so the phone can open `/connect`, download
  the CA, and pair (firewall it off again after setup if you prefer; only
  the proxy port is needed day-to-day)

Verify from the phone's browser first: `http://<vps-ip>:5000/connect` must
load. If it doesn't, it's the firewall — fix that before touching proxy
settings. From here on, the wizard on the phone shows the right addresses.

### 1 · Save the device

On the phone, open the connect page and tap **Save device** with a name like
`pixel-chrome`. It lands in the device registry (name, IP, browser, last
seen) and stays there across restarts — see [Saved
devices](#saved-devices).

### 2 · Point the Android browser at the proxy

**Chrome (and every browser that follows the system proxy):**

1. Settings → Network & Internet → (or long-press your Wi-Fi name →
   **Modify**) → **Advanced**.
2. **Proxy** → **Manual**.
3. Host: `<vps-ip>` · Port: `8080` · Bypass for: leave empty.
4. Save. Chrome now routes through MiniProxy (no restart needed).

> Some Android builds hide the per-network proxy behind "Modify network →
> Advanced"; Samsung calls it "Advanced → Proxy settings". If your keyboard
> is open when saving, the Save button can hide behind it — press Back
> first.

**Firefox for Android:** it follows the same system/Wi-Fi proxy by default,
but you can also force it in-app:

1. Open Firefox → type `about:config` in the address bar (Debug menu on
   older versions: Settings → scroll to the bottom).
2. Search for `proxy`.
3. Set **`network.proxy.type`** → `1` (manual).
4. Set `network.proxy.http` → `<vps-ip>`, `network.proxy.http_port` →
   `8080` (integer), and the same for `network.proxy.ssl` /
   `network.proxy.ssl_port` — Firefox uses the *ssl* entries for HTTPS
   sites.
5. Restart Firefox.

> The in-app route also covers **Firefox over mobile data**, where the
> Wi-Fi proxy panel can't help. (It may require Firefox's beta/nightly
> builds on some versions; the Wi-Fi proxy route works for every browser.)

**PAC instead of manual:** Wi-Fi proxy settings also accept
"Proxy Auto-Config" on most builds — paste the PAC URL from the connect
page there.

### 3 · Trust the CA on Android (HTTPS bodies)

1. Download: connect page → **Download CA** (or `http://<vps-ip>:5000/ca.crt`).
2. Settings → Security → **More security settings** → **Encryption &
   credentials** → **Install a certificate** → **CA certificate**
   (wording varies by vendor: "Install from storage" on older builds).
3. Android warns that your traffic can be monitored — that's exactly the
   point of an interception proxy; proceed only on a device you own.
4. Restart the browser. Chrome honors user CAs immediately; Firefox asks
   once whether to trust certificates from your installed CA — say yes.

Without this step HTTPS still flows and is captured (method, URL, status,
timing) but bodies stay encrypted. Note that on Android **7+** most *apps*
ignore user-installed CAs — **browsers honor them**, which is why this
workflow targets Chrome/Firefox browsing rather than arbitrary apps.

### 4 · Verify

Browse any site on the phone, then check the dashboard's **Live** tab (or
`miniproxy log` on the VPS). The connect page's **Send one proxied test
request** button also proves the path works. When you're done on public
networks, remove the Wi-Fi proxy (set it back to "None") — Android keeps
proxy settings per network, and a dead proxy makes every browser look
offline.

### Phone on mobile data, or no firewall access?

- **Mobile data** can't use a Wi-Fi proxy. Options: tether the phone to a
  network whose gateway is the proxy, use Firefox's in-app proxy (above),
  or run a VPN app (e.g. an app that proxies via an HTTP proxy over VPN).
- **Can't open ports?** Use the SSH-tunnel pattern from
  [Pattern A](#pattern-a--ssh-tunnel-recommended-nothing-is-exposed) —
  run the tunnel on a laptop or an Android SSH client and point the Wi-Fi
  proxy at `127.0.0.1` on that device.
## HTTPS bodies: trust the CA

Without the CA, HTTPS traffic still **routes and is captured** (method, URL,
status, timing) but the encrypted request/response *bodies* can't be decoded.
To see bodies:

1. Download the CA: Connect tab → **Download CA**, or `GET /ca.crt` — or use
   the file already on the proxy host at `~/.mitmproxy/mitmproxy-ca-cert.pem`
   (generated the first time `mitmdump` runs; set `MINIPROXY_CA_CERT` to
   point somewhere else).
2. Install and trust it on the *device you're connecting*:

   | OS | Steps |
   |---|---|
   | macOS | Open the `.pem` → Keychain Access → System → **Always Trust** (SSL) |
   | Windows | Double-click → Install Certificate → Local Machine → **Trusted Root Certification Authorities** |
   | Linux (Firefox) | Settings → Privacy & Security → Certificates → **Import** |
   | Linux (system) | `sudo cp miniproxy-ca-cert.pem /usr/local/share/ca-certificates/miniproxy.crt && sudo update-ca-certificates` |
   | Android | Settings → Security → **Install from storage** (user credential; Android 7+ apps may ignore user CAs — the browser honors them) |
   | iOS | Download → Settings → Profile Downloaded → Install → enable in **About → Certificate Trust Settings** |

Browsers usually pick the CA up immediately; Firefox may need a restart.

## Capturing a browser that is *not* on your network (VPS / remote)

Two supported patterns — both keep capture working from anywhere:

### Pattern A — SSH tunnel (recommended; nothing is exposed)

On the VPS:

```bash
miniproxy start --dashboard-host 127.0.0.1
```

On your laptop, forward both ports:

```bash
ssh -N -L 5000:127.0.0.1:5000 -L 8080:127.0.0.1:8080 user@your-vps
```

Now open `http://127.0.0.1:5000/connect` locally. Because you reached the
dashboard via the tunnel, the wizard advertises `127.0.0.1:8080` — which is
exactly right through the tunnel. Point your browser at the proxy and traffic
flows through the tunnel into the VPS capture DB. `examples/remote-vps.sh`
(default mode) automates the VPS side.

### Pattern B — public exposure (explicit opt-in)

Pointing a browser that lives on *another* network directly at the VPS:

```bash
# on the VPS — proxy on all interfaces, dashboard open with a token
miniproxy start --dashboard-host 0.0.0.0 --dashboard-token <random> 
```

Open the **printed** `http://<vps-ip>:<dashboard-port>/connect` from anywhere;
`0.0.0.0` is a bind address, not a browser destination, so MiniProxy replaces
it with the detected VPS/LAN address in the startup URL. The wizard detects
the public IP and prints matching proxy/PAC/CA URLs. ⚠️ **This exposes the
dashboard to the internet.** Keep the token, firewall the port if you can,
and `miniproxy stop` when done. Prefer Pattern A unless you specifically need
direct reachability (e.g. a phone without an SSH client).

For *HTTPS* you additionally need the CA (above). Without it, remote HTTPS
still shows up with method/URL/status — only bodies stay opaque.

## Saved devices

Every device you **Save** on the connect page (or in the dashboard's Connect
tab) is stored in the capture DB's `devices` table — name, IP, browser user
agent, first/last seen — and survives restarts. Pairing the same name from
the same IP again just refreshes its last-seen time. Manage the registry
from either UI:

- **Connect page** (`/connect`, step 4) — save, list, forget one, forget all
- **Dashboard Connect tab** — the same list with inline Forget buttons
- API: `GET/POST /api/connect/devices`, `DELETE /api/connect/devices/<id>`

This is an inventory aid, not an access-control list: any client that can
reach the proxy can use it. The registry only remembers what paired.

## Exposing the dashboard

The dashboard is the read/write window (Repeater, Intruder, clear) and binds
`127.0.0.1` by default. To reach it from another device:

```bash
miniproxy start --dashboard-host 0.0.0.0 --dashboard-token s3cret
```

- reads (log list, detail, exports, `/proxy.pac`, `/ca.crt`, `/connect`) stay open;
- every state-changing call (Repeater, Intruder, clear, proxy toggle, pairing)
  requires the token — the UI prompts once and remembers it for the session.

Never expose the dashboard to the public internet without a token and a
firewall rule; captures contain cookies, tokens, and session data.

## Verifying capture works

1. Connect tab → **Send one proxied test request** → expect a green
   "✔ captured" with an HTTP status.
2. Or from any terminal:
   `curl -x http://<proxy>:8080 https://example.com` then `miniproxy log`.
3. The request appears in the dashboard's **Live** tab and the TUI within a
   second. Captures persist across page refreshes, dashboard restarts, and
   proxy restarts until you click **Clear all captures…**.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Browser can't reach any site after setting the proxy | Proxy stopped, wrong host/port, or a firewall between you and it. Check `miniproxy status`; test with `curl -x http://<host>:8080 http://example.com`. |
| PAC URL does nothing | The URL must be reachable *from the client*. From the client, `curl http://<dash-host>:5000/proxy.pac` should print the script. |
| HTTPS sites show but bodies are `(empty)` / undecodable | Trust the CA on the client (see above); HSTS-pinned apps may still refuse — test in a normal browser tab. |
| Certificate errors after installing the CA | The client may cache the old failure — restart the browser; on iOS also enable full trust in Certificate Trust Settings. |
| Traffic from *this* machine doesn't appear | The proxy env vars/PAC may bypass localhost by design — that's intended so the dashboard doesn't capture itself. |
| Remote device can't reach the proxy | The proxy binds all interfaces, but cloud VPSes need the ports opened in the *cloud firewall/security group*, not just the OS one. |
| Everything captured except one app | Some apps pin certificates or ignore system proxies. Route them via an explicit proxy setting if available, or capture at the OS level. |
| Android: browser says offline after leaving the VPS | The Wi-Fi still has the proxy configured. Set it back to **None** (or the phone keeps trying a dead proxy). |
| Android: proxy option missing on mobile data | Android only supports proxies on Wi-Fi networks; use Firefox's in-app proxy or a VPN-based route on mobile data. |

## Quick reference

| Endpoint | Purpose |
|---|---|
| `/connect` | Full connect wizard (any browser) |
| `/api/connect/info` | Machine-readable connect info |
| `/api/connect/devices` | Saved-device registry (GET list / POST save) |
| `/proxy.pac` | PAC file for automatic proxy configuration |
| `/ca.crt` | mitmproxy CA download |
| `/connect/qr.svg` | QR code of the connect page |

⚠️ Intercept only traffic to systems you own or are authorized to test —
see [SECURITY.md](../SECURITY.md).
