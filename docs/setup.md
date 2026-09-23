# Setup

## 1. Install

**Python 3.10+ required** (check with `python3 --version`).

```bash
# From PyPI (recommended)
pip install riciplay-miniproxy

# Or via npm — installs the Python package on postinstall
npm install -g riciplay-miniproxy
```

The npm package is a thin launcher; the real implementation is the Python
package `riciplay-miniproxy`. Both install the same `miniproxy` command.

Verify:

```bash
miniproxy --help
```

## 2. Install mitmproxy (the capture engine)

MiniProxy is a manager + UI layer on top of
[mitmproxy](https://mitmproxy.org/):

```bash
pip install mitmproxy        # provides the `mitmdump` binary
mitmdump --version
```

If `mitmdump` is missing, `miniproxy start` fails with a clear error
instead of half-starting — see
[Troubleshooting → "mitmdump not found"](troubleshooting.md#mitmdump-not-found--proxy-wont-start).

## 3. First run

```bash
miniproxy start
```

You'll see:

```
MiniProxy started on :8080 (PID 12345, db=/home/you/.miniproxy/proxy.db)
Web UI: http://127.0.0.1:5000  (mirrors `miniproxy tui`)
```

`miniproxy start` starts **two** processes:

1. the interception proxy (mitmdump + the MiniProxy addon) on **:8080**
2. the web dashboard on **:5000** — its URL is printed; open it in a browser

Capture is **always on** while the proxy runs. The dashboard only *reads*
the capture DB — it doesn't touch traffic flow, so having it open has zero
effect on interception. Prefer just the proxy? `miniproxy start
--no-dashboard`.

Send a request through it to prove the loop works:

```bash
curl -x http://127.0.0.1:8080 https://api.github.com/zen
```

Then open the Web-UI URL (or run `miniproxy tui`) — the request is there
with status, timing, headers, and body.

Stop everything with:

```bash
miniproxy stop
```

## 4. HTTPS interception (CA certificate)

To read HTTPS bodies, clients must trust MiniProxy's CA. Generate it once
by running mitmproxy directly:

```bash
mitmdump          # Ctrl+C after a second; the CA is now created
ls ~/.mitmproxy/mitmproxy-ca-cert.pem
```

Then install/trust `~/.mitmproxy/mitmproxy-ca-cert.pem`:

| Client | How |
|--------|-----|
| Browser | import in certificate settings (Firefox: Settings → Privacy → Certificates → View → Import) |
| curl | `curl --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem …` |
| Python / requests / pip | `export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem` |
| Node / npm | `export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem` |
| Android/iOS device | visit `http://mitm.it` **while proxied** and follow the instructions |

Without a trusted CA, HTTPS still flows through the proxy (it's logged as a
CONNECT tunnel) but bodies stay encrypted.

## 5. Where state lives

```
~/.miniproxy/
├── proxy.db          # capture DB (all requests/responses, intruder results)
├── mitmdump.pid/.port    # proxy process state
├── dashboard.pid/.port   # web dashboard process state
```

Environment overrides:

| Variable | Purpose | Default |
|----------|---------|---------|
| `MINIPROXY_DB_PATH` | capture DB location | `~/.miniproxy/proxy.db` |
| `MINIPROXY_STATE_DIR` | pid/port files location | `~/.miniproxy` |
| `MINIPROXY_MAX_ROWS` | capture pruning cap | `5000` |
| `MINIPROXY_MAX_AGE_DAYS` | capture pruning by age | `7` |
| `MINIPROXY_MAX_DB_BYTES` | capture pruning by size | `52428800` |

## 6. Updating

```bash
pip install --upgrade riciplay-miniproxy
# or
npm update -g riciplay-miniproxy
```

The capture DB format is stable; upgrades keep your history. If something
looks wrong after an upgrade, stop any running proxy
(`miniproxy stop`) and start again.
