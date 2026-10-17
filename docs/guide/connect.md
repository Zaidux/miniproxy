# Connect

The **Connect** tab is the answer to "how do I get this browser (or this
phone) to send its traffic through MiniProxy?". It shows the addresses, the
automatic-config URL, the certificate download, a test button, and a device
registry.

The full per-platform walkthrough, including VPS and SSH-tunnel patterns, is
[Connect browsers & devices](../connect.md). This page is the dashboard tab
itself.

## Read the proxy address

**What it's for.** You need a host and a port to type into another device. The
tab works them out for you.

**How to use it.**

1. Open **Connect**.
2. Read **1 · Proxy address**: `host:port` and a badge.
   - `proxy running` means the proxy process is up.
   - `proxy stopped — run miniproxy start` means it is not; the address is
     still shown, but nothing will answer there.
3. Read the **Addresses** list below it. Each line is a host and a label:
   - `this dashboard's address` — the Host you used to open the dashboard.
     This is usually the right one for an SSH tunnel or port-forward.
   - `external interface (VPS / public IP)` — the machine's outbound address.
   - `LAN address` — the local network address.
   - `same machine only` — `127.0.0.1`.

**Worked example.** MiniProxy runs on a VPS and you opened the dashboard
through `ssh -L 5000:127.0.0.1:5000`. The first Addresses line is
`127.0.0.1` labelled `this dashboard's address`, which is exactly what the
tunnel forwards. On the laptop, the proxy is also `127.0.0.1:8080` because you
forwarded that port too.

**What to look for.** A green `proxy running` badge and an address you
recognise. The list order is "most likely correct first".

**Common mistakes / notes.**

- The address is a guess based on how you reached the dashboard. If it is
  wrong, `miniproxy connect --host <ip> --port <port>` prints the correct
  values in a terminal.
- A running proxy on `127.0.0.1` is not reachable from another device, no
  matter what address the tab shows. See the phone section below.
- The badge reflects the proxy process. The dashboard can be open while the
  proxy is stopped (that is how you read old captures).

## Use the PAC URL

**What it's for.** A proxy auto-config (PAC) file lets a browser or OS
configure itself from one URL, instead of typing host and port. It is the
easiest way to point a desktop browser at MiniProxy.

**How to use it.**

1. In **2 · Point the browser here**, copy the value in
   `PAC URL — browser/OS "automatic proxy configuration"`.
2. Paste it into the automatic proxy setting:
   - Firefox: Settings → Network Settings → **Automatic proxy configuration
     URL**.
   - Chrome/Edge: OS proxy settings → **Use setup script**.
   - macOS: System Settings → Network → Wi-Fi → Proxies → **Automatic Proxy
     Configuration**.
   - Windows: Settings → Network & Internet → Proxy → **Use setup script**.
   - Android: Wi-Fi → Modify → Advanced → Proxy → **PAC auto-config** (wording
     varies).
3. Browse. The **Copy** button next to the field saves typing.

**Worked example.** On a laptop, paste the PAC URL into Firefox. Every request
except localhost now goes through MiniProxy, with no per-site settings.

**What to look for.** Traffic appears in **Live**. `localhost` and `127.0.0.1`
deliberately bypass the proxy, so opening the dashboard itself does not loop.

**Common mistakes / notes.**

- The PAC routes everything through MiniProxy, not only your lab. That is why
  noise control matters.
- If the PAC URL uses an address the other device cannot reach, the device
  silently has no internet. Check the URL in the device's browser first.
- Some Android builds label PAC as "Proxy auto-config" and hide it under
  **Advanced**.

## Set the proxy by hand, or use a one-liner

**What it's for.** Same result as the PAC, without automatic configuration. It
is also how you point `curl`, `pip`, or a script at the proxy.

**How to use it.**

1. Read the manual settings under the PAC field: **host** and **port** from
   **1 · Proxy address**.
2. Set an HTTP proxy to that host and port in the client.
3. Or copy one of the one-liners:
   - `curl -x http://host:port https://example.com` for a single command;
   - `export http_proxy=… https_proxy=…` for a shell session.

**Worked example.** To capture a `pip install`, export the two environment
variables in the shell and run the install. Every HTTP request `pip` makes
appears in **Live**.

**What to look for.** The client's next request shows up. For HTTPS, the body is
only readable after the CA is trusted (next section).

**Common mistakes / notes.**

- Environment variables affect only the shell you exported them in. A new
  terminal forgets them.
- Some tools ignore proxy environment variables. Use their explicit flag
  (`curl -x`, `git config http.proxy`, `pip --proxy`).
- The one-liners are examples. Replace the host/port if your proxy is not on
  the default.

## Download and trust the CA

**What it's for.** HTTPS bodies are encrypted. MiniProxy can only show them if
the client trusts MiniProxy's CA. This is the step that turns `CONNECT` rows
into readable requests.

**How to use it.**

1. Under **3 · Trust the CA (HTTPS bodies)**, click **Download CA**.
2. Install and trust the file on the device doing the browsing:
   - **Android**: Settings → Security → Encryption & credentials → Install a
     certificate → CA certificate. The warning about monitoring is expected;
     this is an interception proxy.
   - **iOS**: install the profile, then enable it in Settings → General → About
     → Certificate Trust Settings.
   - **Firefox**: Settings → Privacy & Security → Certificates → View
     Certificates → Import, and tick "trust for websites".
   - **macOS/Windows**: import into the system trust store.
3. Restart the browser if needed.
4. Reload the HTTPS page.

**Worked example.** The lab is HTTPS. Before the CA, **Live** shows a `CONNECT`
row and no readable body. After trusting the CA on the phone and reloading, the
same page appears as a normal `GET` with HTML in the **Response** tab.

**What to look for.** The text under the button says the CA was found on the
proxy host, and HTTPS requests show real methods and bodies. A `CONNECT` row
means the client did not trust the CA (or the client is not using the proxy for
that request).

**Common mistakes / notes.**

- The CA is served from `/ca.crt`. If the file does not exist yet, run
  `mitmdump` once on the proxy host, or set `MINIPROXY_CA_CERT`. HTTPS still
  routes without it; the bodies stay encrypted.
- On Android 7+ most **apps** ignore user-installed CAs. Browsers honour them.
  This workflow captures browser traffic, not arbitrary app traffic.
- Install the CA on the **client**, not on the proxy host. Downloading it on
  the proxy host does nothing for the phone.
- A certificate warning on every site means the CA is not trusted, or was
  installed as a server certificate instead of a CA.

## Verify the path

**What it's for.** A one-click end-to-end check that the proxy is running and
capturing.

**How to use it.**

1. Under **4 · Verify & pair**, click **Send one proxied test request**.
2. Read the result next to the button.
3. Open **Live** and look for the request.

**Worked example.** After starting MiniProxy on a VPS, click the button. It
sends `GET https://api.github.com/zen` from the dashboard host through the
proxy. If that works, the proxy can capture from at least that machine.

**What to look for.** `✔ captured — HTTP 200 (N B), see the Live tab`, and a
new row for `api.github.com`.

**Common mistakes / notes.**

- **This proves the proxy host, not your phone.** The request is generated by
  the dashboard process, not by the device you are holding. To verify the
  phone, browse a page on the phone and check **Live**.
- It needs outbound internet access from the proxy host. A locked-down VPS can
  fail this and still work fine for its own targets.
- If the proxy is stopped, the request fails with a connection error.

## Save a device

**What it's for.** A small registry of the devices you have connected, so you
can remember what `192.168.1.50` was three days later.

**How to use it.**

1. In **4 · Verify & pair**, type a name in
   `Name this device (saved to the device registry)`, for example
   `pixel-chrome`.
2. Click **Save device**.
3. Read **Saved devices** below: name, IP, last seen. Click **Forget** to
   remove one.

**Worked example.** Before changing the phone's Wi-Fi proxy, open the Connect
tab on the phone and save it as `pixel-chrome`. The entry records the phone's
IP and when it was last seen through the dashboard. When the lab is over,
**Forget** it.

**What to look for.** The device appears in the list immediately. Saving the
same name from the same IP again refreshes the last-seen time instead of
creating a duplicate.

**Common mistakes / notes.**

- The IP recorded is the one that reached the dashboard. Behind a tunnel or a
  reverse proxy it may be `127.0.0.1` or the tunnel's address, not the phone's
  LAN address.
- Names are shortened to 40 characters and stripped to letters, digits,
  spaces, `.`, `_`, `-`.
- This registry is informational. It does not authenticate a device, and it
  does not change who may use the proxy.
- **Forget** only removes the registry entry. It does not disconnect or block
  the device.

## Scan the QR code

**What it's for.** Get the Connect page onto a phone without typing a URL.

**How to use it.**

1. Look at **Scan from a phone**.
2. Scan the QR code with the phone camera.
3. The phone opens the `/connect` page for the address it was generated from.
4. Follow the page's per-platform steps.

**Worked example.** The dashboard is on a laptop at `192.168.1.10:5000`. Scan
the QR, and the phone opens `http://192.168.1.10:5000/connect`, where the same
address, PAC URL, and CA download are available on the device that needs them.

**What to look for.** The phone loads the Connect page. If it does not, the
phone cannot reach the dashboard address; fix that before touching proxy
settings.

**Common mistakes / notes.**

- The QR encodes the URL you reached the dashboard on. If you opened it on
  `127.0.0.1`, the QR points at `127.0.0.1`, which means "this phone" and will
  not load. Open the dashboard on its LAN address before scanning.
- The QR only opens the page. It does not configure the proxy for you.

## Connecting a phone: the three things that must be true

1. **The phone can reach the dashboard.** Open
   `http://<host>:5000/connect` in the phone's browser. If that fails, it is a
   network or firewall problem.
2. **The phone can reach the proxy port.** The proxy binds `127.0.0.1` by
   default. Either forward it (`ssh -N -L 8080:127.0.0.1:8080 user@host` and
   point the phone at its own `127.0.0.1:8080` through a local tunnel), or bind
   it to the LAN with `miniproxy start --proxy-host 0.0.0.0` and firewall the
   port so only the phone can reach it. On a VPS, open **both** ports in the
   provider's firewall — `8080` for the proxy and `5000` for the dashboard
   during setup. This is the most common reason a phone cannot connect.
3. **The phone trusts the CA.** Otherwise HTTPS bodies stay encrypted.

Android-specific detail: proxy settings are **per Wi-Fi network**, and mobile
data cannot use an HTTP proxy without a VPN app. The full walkthrough is
[Connect → Android](../connect.md#connecting-an-android-browser-chrome-or-firefox--incl-from-a-vps).

**Common mistakes / notes.**

- Publishing the proxy on `0.0.0.0` without a firewall rule makes it an open
  relay: anyone who can reach the port can send traffic through it and write to
  your database. `--allow-client` is **not** a client allowlist (it filters
  destination hosts through mitmproxy's `allow_hosts`), so use the host
  firewall or a tunnel.
- Exposing the dashboard on `0.0.0.0` without `--dashboard-token` lets anyone
  on that network read your captures. Pair the two flags.
- When you finish on a public network, set the phone's Wi-Fi proxy back to
  **None**. A dead proxy makes every browser look offline.

Next: [Common workflows](workflows.md).
