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
# Web UI: http://127.0.0.1:5000  (mirrors `miniproxy tui`)
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

Open `http://<vps-ip>:5000/connect` from anywhere; the wizard detects the
public IP and prints matching proxy/PAC/CA URLs. ⚠️ **This exposes the
dashboard to the internet.** Keep the token, firewall the port if you can,
and `miniproxy stop` when done. Prefer Pattern A unless you specifically need
direct reachability (e.g. a phone without an SSH client).

For *HTTPS* you additionally need the CA (above). Without it, remote HTTPS
still shows up with method/URL/status — only bodies stay opaque.

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

## Quick reference

| Endpoint | Purpose |
|---|---|
| `/connect` | Full connect wizard (any browser) |
| `/api/connect/info` | Machine-readable connect info |
| `/proxy.pac` | PAC file for automatic proxy configuration |
| `/ca.crt` | mitmproxy CA download |
| `/connect/qr.svg` | QR code of the connect page |

⚠️ Intercept only traffic to systems you own or are authorized to test —
see [SECURITY.md](../SECURITY.md).
