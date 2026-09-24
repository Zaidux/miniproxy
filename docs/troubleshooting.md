# Troubleshooting

Quick diagnosis order: `miniproxy status` → is the proxy in the list? →
check the Web UI header (proxy dot) → send a test request
(`curl -x http://127.0.0.1:8080 http://example.com`) → check the Live tab.

## `conflicting subparser: web` / any `miniproxy` command crashes with an argparse traceback

You're on a release older than the fix, or the installed package and the
repo checkout are out of sync. Upgrade the installed package (and make
sure `pip install .` was re-run after `git pull`):

```bash
pip install --upgrade riciplay-miniproxy   # or pipx upgrade / venv pip
miniproxy --help
```

If you installed from source, re-install from source after every pull.

## "externally-managed-environment" when installing on a VPS

PEP 668 — Debian/Ubuntu protect the system Python. Use pipx or a venv
(instead of `--break-system-packages`, which downgrades shared libraries
other tools depend on) — see
[Setup → Install](setup.md#1-install).

## "mitmdump not found" / proxy won't start

The capture engine is missing.

```bash
pip install mitmproxy
mitmdump --version
```

Or point at a specific binary: `miniproxy start --mitmdump /usr/local/bin/mitmdump`.

## "Port 8080 is already in use"

Since the dynamic-port update this rarely errors at all: if the requested
port is busy, MiniProxy **moves up to the next free port** and says so in
the startup output ("requested port was busy, moved up"). Everything
else — dashboard URL, `miniproxy connect`, the connect wizard — reads the
actual bound port from state, so follow the printed addresses.

Prefer a deterministic pick? `--port auto` always chooses a free port:

```bash
miniproxy start --port auto --dashboard-port auto
miniproxy status                    # shows where it actually landed
```

To see what holds a specific port: `lsof -i :8080` or `ss -ltnp | grep 8080`.

## "Port 5000 is already in use" (dashboard)

macOS Monterey+ uses :5000 for AirPlay Receiver. Either disable that in
System Settings, or pick another port:

```bash
miniproxy start --dashboard-port 5050
```

## The VPS prints a URL but the browser shows nothing

`0.0.0.0` is only a bind address; it is not a destination you can type into
another device. When the dashboard is exposed with
`--dashboard-host 0.0.0.0`, MiniProxy now prints the VPS/LAN address it
discovered (for example, `http://203.0.113.7:5000`) instead of the wildcard.
If the output still says `127.0.0.1`, the dashboard is loopback-only and the
browser must reach it through SSH:

```bash
ssh -N -L 5000:127.0.0.1:5000 user@your-vps
# then open http://127.0.0.1:5000/connect on your laptop
```

For direct remote access, explicitly expose the dashboard and use a token:

```bash
miniproxy stop
miniproxy start --dashboard-host 0.0.0.0 --dashboard-token 'use-a-long-secret'
```

Open the **printed** `http://<vps-ip>:<port>/connect` URL, not
`http://0.0.0.0:<port>`, and allow both the dashboard and proxy ports in the
VPS provider firewall/security group. If the printed address is still
`127.0.0.1`, the machine has no discoverable non-loopback address; use the SSH
tunnel above or provide a public DNS name/forwarded port.

## Web UI shows "proxy stopped" but traffic flows

They're independent processes. The header reflects the *capture proxy*
only. If you started mitmdump yourself (outside `miniproxy start`), the
dashboard can't see it via pid files — start via `miniproxy start`/`web`
or the Web UI button to get full lifecycle control.

## Proxy status says running, but nothing captures

1. Is traffic actually routed through the proxy? Test with
   `curl -x http://127.0.0.1:8080 http://example.com` — if that shows up
   in the Live tab, the proxy works; the problem is your other client's
   proxy config.
2. Using a scope? `miniproxy start --scope '*.target.com'` only captures
   those hosts — out-of-scope flows pass through unlogged (or are
   403-blocked with `--block-out-of-scope`).
3. HTTPS without a trusted CA shows CONNECT tunnels but no bodies →
   [Setup → CA certificates](setup.md#4-https-interception-ca-certificate).
4. Wrong DB? The UI header shows the DB path. If you started things with
   `MINIPROXY_DB_PATH` set differently, point the reader at the same file.

## Status shows a PID, but stop() says "stale (dead or not mitmdump)"

A stale pid file pointed at a recycled PID. MiniProxy verifies the
process's command line before trusting it and cleans the state — this is
the safe path, not a bug. Run `miniproxy start` again.

## The dashboard didn't start ("did not bind :5000 within 8s")

Usually a port conflict or a slow machine. Check manually:

```bash
miniproxy dashboard --port 5000     # foreground; errors print directly
```

If it says the port is taken, see the port section above. The proxy keeps
running regardless — capture is unaffected by dashboard failures.

## Requests appear but bodies are empty

- Response not finished yet (status shows `…`/pending) — wait a tick.
- Transport error (status `ERR`) — the flow died; the Response tab shows
  the reason.
- HTTPS without the CA installed — bodies are encrypted; install the CA.

## Intruder attack failed / all results are ERR

- Wordlist over 1000 entries → split it.
- Target unreachable from the dashboard process (firewall/VPN) — the
  Repeater shares this behavior; test with `miniproxy send`.
- `§placeholders§` misspelled (they must be `§…§` on both sides).

## TUI won't start ("needs an interactive terminal")

`miniproxy tui` refuses to run inside pipes/CI where there's no TTY.
Use SSH with a real terminal (`ssh -t`), or run inside `tmux`/`screen`,
or fall back to `miniproxy log` / the Web UI over a port-forward:

```bash
ssh -L 5000:127.0.0.1:5000 user@host   # then open http://127.0.0.1:5000
```

## Clipboard copy doesn't work in the TUI

Terminals need an OSC-52-capable terminal (kitty, alacritty, WezTerm,
Windows Terminal) or a clipboard bridge; over SSH the local terminal must
support OSC-52 passthrough. The Web UI's **Copy curl/Copy body** buttons
are the always-works fallback.

## Captures disappeared / old rows gone

Pruning is on by design (default: keep 5,000 rows / 7 days / 50 MB).
Raise or disable via env before starting the proxy:

```bash
export MINIPROXY_MAX_ROWS=50000 MINIPROXY_MAX_AGE_DAYS=30 MINIPROXY_MAX_DB_BYTES=0
miniproxy start
```

## My antivirus / corporate TLS breaks HTTPS capture

Some environments pin certificates (HSTS, cert pinning in apps, AV
TLS-inspection). Nothing MiniProxy can do about pinned clients — capture
plain-HTTP endpoints, use clients that allow custom CAs, or chain via
[upstream mode](integrations.md#chaining-with-other-proxies).

## Clean slate

```bash
miniproxy stop
rm -rf ~/.miniproxy        # removes captures, pid/port files
mitmdump                   # regenerate CA if needed, then Ctrl+C
miniproxy start
```

## FAQ

**Does the web UI affect capture?**
No — it only reads the DB. Opening 10 tabs changes nothing on the wire.

**`miniproxy version` says "unknown"?**
The dist metadata didn't install (e.g. running from a source checkout
without `pip install -e .`). It's cosmetic — every other command works.

**Do I need the dashboard running to use the TUI (or vice versa)?**
No. Any number of readers can be open at once; they'd all show the same
data.

**Can I run two proxies at once?**
Not with the same state dir (pid files collide). Use
`MINIPROXY_STATE_DIR=/tmp/mp2 MINIPROXY_DB_PATH=/tmp/mp2/proxy.db
miniproxy start --port 9090 --dashboard-port 5050`.

**Is this legal?**
Only intercept traffic you own or are authorized to test. It's built for
local labs, CTFs, and authorized security research.
