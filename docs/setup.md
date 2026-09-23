# Setup

## 1. Install

**Python 3.10+ required** (check with `python3 --version`).

```bash
# From PyPI (recommended)
pip install riciplay-miniproxy

# Or via npm — installs the Python package on postinstall
npm install -g riciplay-miniproxy
```

### Modern Debian/Ubuntu (PEP 668 "externally-managed-environment")

On Debian 12+, Ubuntu 23.04+, and most current cloud images, a bare
`pip install .` (or `pip install riciplay-miniproxy`) refuses to run:

```
error: externally-managed-environment
× This environment is externally managed …
```

That's the OS protecting its system Python. Don't reach for
`--break-system-packages` — it downgrades shared libraries (cryptography,
typing-extensions, rich, …) and breaks *other* tools installed on the same
box (selenium, pydantic, semgrep, …). Use an isolated environment instead:

```bash
# Option A — pipx (cleanest for CLI tools like miniproxy)
apt install pipx
pipx install riciplay-miniproxy        # or: pipx install /root/projects/miniproxy

# Option B — plain venv
python3 -m venv ~/.venvs/miniproxy
~/.venvs/miniproxy/bin/pip install riciplay-miniproxy
# then either add ~/.venvs/miniproxy/bin to PATH, or link the entry point:
ln -sf ~/.venvs/miniproxy/bin/miniproxy /usr/local/bin/miniproxy

# Option C — user site (no venv, no sudo)
pip install --user --break-system-packages riciplay-miniproxy   # LAST resort
```

Installing from a git checkout on the VPS: `git pull`, then re-run the
install step above from the repo root (`pipx install .` / the venv pip
with `.`), so the installed package matches the pulled code.

The npm package is a thin launcher; the real implementation is the Python
package `riciplay-miniproxy`. Both install the same `miniproxy` command.

Verify:

```bash
miniproxy --help
miniproxy version
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

(PEP 668 systems: upgrade inside the same pipx/venv you installed with,
e.g. `pipx upgrade riciplay-miniproxy`.)

The capture DB format is stable; upgrades keep your history. If something
looks wrong after an upgrade, stop any running proxy
(`miniproxy stop`) and start again.
