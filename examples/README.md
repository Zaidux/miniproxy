# MiniProxy recipes

Small, copy-paste scripts that route real traffic through MiniProxy so you
can see capture working end-to-end. Start the proxy first:

```bash
miniproxy start
```

| Script | What it shows |
|---|---|
| [capture-curl.sh](capture-curl.sh) | `curl -x` with HTTPS + the mitmproxy CA |
| [capture-pip-npm.sh](capture-pip-npm.sh) | capturing pip/npm/Node via proxy env vars |
| [capture-python-requests.py](capture-python-requests.py) | per-request `proxies=` in Python |
| [remote-vps.sh](remote-vps.sh) | run MiniProxy on a VPS and connect from anywhere |

Everything that arrives at the proxy shows up in `miniproxy tui`, the web
dashboard, and `miniproxy log` (they all read the same capture DB).

To connect a **browser** instead, open the dashboard's **Connect** tab
(`http://127.0.0.1:5000/connect`) — it generates the proxy settings, PAC URL,
CA download, and a QR code for your device. Full walkthrough:
[docs/connect.md](../docs/connect.md).

⚠️ Intercept only traffic to systems you own or are authorized to test.
