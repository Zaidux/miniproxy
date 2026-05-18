# MiniProxy

A lightweight HTTP/S interception proxy for local security research — built with **mitmproxy**, **Flask**, and **SQLite**.

## Features

- **Proxy** — Intercept HTTP/HTTPS traffic (toggle on/off). Live request feed streams to the dashboard.
- **Log** — Every request/response stored in SQLite with full headers, bodies, and status codes.
- **Repeater** — Select a logged request, edit method/headers/body, resend it, and inspect the response.
- **Intruder** — Select a request, mark parameters with `§param§` placeholders, upload a wordlist, and fuzz each position. Results are highlighted by response status code.

## Project Structure

```
miniproxy/
├── proxy.py       # mitmproxy addon — intercepts traffic
├── app.py         # Flask dashboard (API + UI)
├── db.py          # SQLite database handler
├── intruder.py    # Fuzzing engine (wordlist-based payload substitution)
├── templates/
│   └── index.html # SPA frontend (vanilla JS, dark theme)
├── requirements.txt
└── README.md
```

## Quick Start

### 1. Install Dependencies

```bash
cd miniproxy
pip install -r requirements.txt
```

### 2. Start the Proxy (mitmproxy)

```bash
mitmdump -s proxy.py --set block_global=false
```

The proxy listens on **`127.0.0.1:8080`** by default.

> **Note:** To intercept HTTPS traffic, you must install the mitmproxy CA certificate on your device/browser:
> - Run `mitmproxy` once (without the addon), visit `http://mitm.it` in your browser while proxied, and download the certificate.
> - Or copy the cert from `~/.mitmproxy/mitmproxy-ca-cert.pem`.

### 3. Start the Dashboard (Flask)

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### 4. Configure Your Browser

Set your browser's HTTP proxy to **`127.0.0.1:8080`**:

| Browser        | Steps |
|---------------|-------|
| **Firefox**   | Settings → Network Settings → Manual proxy → HTTP Proxy: `127.0.0.1`, Port: `8080` → ✓ "Also use this proxy for HTTPS" |
| **Chrome**    | Settings → System → Open proxy settings → LAN settings → ✓ "Use a proxy server" → Address: `127.0.0.1`, Port: `8080` |
| **curl**      | `curl -x http://127.0.0.1:8080 https://example.com` |
| **wget**      | `wget -e use_proxy=yes -e http_proxy=127.0.0.1:8080 https://example.com` |

### 5. Browse

Navigate to any website. Requests appear live in the **Proxy** tab and are archived in the **Log** tab.

## Usage

### Proxy Tab
- **Toggle** — Pause/resume interception. When OFF, traffic still flows but isn't logged.
- **Live Feed** — Auto-updating table shows requests as they pass through the proxy.

### Log Tab
- **Refresh** — Load all captured requests.
- **Click a row** — Expand full headers, body, and response details.

### Repeater Tab
1. Select a request from the dropdown.
2. Edit the method, URL, headers, or body.
3. Click **Send** to fire the modified request.
4. Inspect the response headers and body.

### Intruder Tab
1. Select a request from the dropdown.
2. Edit the URL, headers, or body. Insert `§param§` placeholders where you want payloads injected (e.g. `id=§fuzz§`).
3. Upload a wordlist (`.txt`, one word per line, max 1000).
4. Click **Start Attack**.
5. Results appear in a table. Rows are **color-coded by status code**. Click any row to see the full response.

## Notes

- This tool is intended for **local security research and education only**.
- Responses are capped at 100 KB in the database.
- Wordlists are limited to 1000 entries to prevent timeouts.
- SSL verification is disabled for repeater/intruder requests (local lab use).
- mitmproxy handles full HTTPS interception via its own CA.
