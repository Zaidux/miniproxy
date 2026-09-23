# CLI & TUI

Every subcommand of `miniproxy`:

```
miniproxy start      Start the interception proxy (+ web dashboard) and print the UI URL
miniproxy web        Alias of `start` — proxy AND web dashboard in one step
miniproxy stop       Stop the proxy and the dashboard
miniproxy status     Is the proxy running? Which port? Where's the Web UI?
miniproxy tui        Terminal UI (Textual) — live feed, filters, Repeater
miniproxy dashboard  Run the web dashboard in the foreground (no proxy)
miniproxy log        One-shot dump of captured requests
miniproxy send       One-shot request (Repeater semantics) without the dashboard
```

`log`, `send`, and `tui` read the capture DB directly — the dashboard does
**not** need to be running, and neither does the proxy.

## start

```bash
miniproxy start                          # proxy :8080 + web UI :5000
miniproxy start --port 8888              # custom proxy port
miniproxy start --dashboard-port 8081    # custom web UI port
miniproxy start --dashboard-host 0.0.0.0 # LAN access (default is 127.0.0.1)
miniproxy start --dashboard-host 0.0.0.0 --dashboard-token s3cret
                                         # LAN access + token-gated mutations
miniproxy start --no-dashboard           # proxy only, no web UI
miniproxy start --db /tmp/lab.db         # separate capture DB
miniproxy start --scope '*.target.com'   # capture only in-scope hosts
miniproxy start --scope '*.a.com' '*.b.com' --block-out-of-scope
                                         # 403 anything outside scope
```

Output:

```
MiniProxy started on :8080 (PID 12345, db=/home/you/.miniproxy/proxy.db)
Web UI: http://127.0.0.1:5000  (mirrors `miniproxy tui`)
```

The dashboard listens on `127.0.0.1` by default. Binding it to a LAN
address prints a warning; pair it with `--dashboard-token` to require a
token on state-changing endpoints (see [web UI](web-ui.md#getting-the-url)).

Both processes survive your terminal (they run in their own session).
`miniproxy stop` takes them down.

## The TUI — `miniproxy tui`

```bash
miniproxy tui                 # uses ~/.miniproxy/proxy.db
miniproxy tui --db /tmp/lab.db
miniproxy tui --refresh 0.5   # faster polling (seconds)
```

Layout:

```
┌ proxy bar ──────────────────────────────────────────────────────┐
├─────────────────────────────────────────────────────────────────┤
│ [method ▾] [status ▾] [ url substring…                        ] │
├───────────────────────────────┬─────────────────────────────────┤
│ live capture table            │ Request / Response / Intruder   │
│ ID · Method · Status · ms · URL│ detail tabs                    │
├───────────────────────────────┴─────────────────────────────────┤
│ footer: key shortcuts                                           │
└─────────────────────────────────────────────────────────────────┘
```

### Keys

| Key | Action |
|-----|--------|
| `j` / `↓`, `k` / `↑` | move in the request table |
| `g` / `home`, `G` / `end` | jump to top / bottom |
| `r` or `enter` | open the **Repeater** for the selected request |
| `i` | show **Intruder** results for the selected request |
| `c` | copy the request as a **curl** command |
| `y` | copy the **response body** |
| `e` | **save the response body** to a timestamped file in the current directory |
| `p` | **start/stop the proxy** (blocks ≤ 8s; runs off-thread) |
| `f` | focus the URL filter |
| `t` / `s` | focus method / status filter |
| `R` | force-refresh the table |
| `?` | help screen |
| `q` | quit |

In the Repeater modal: edit method/URL/headers/body, then **Ctrl+S** to
send (Esc closes). The response renders inline, headers + body.

### Workflows

**Find a suspicious endpoint:** type a URL fragment in the filter box (`f`),
narrow with the status filter (`s` → 5xx), walk the rows with `j`/`k`,
inspect headers/bodies in the right pane.

**Replay with changes:** select a request, `r`, tweak the body in the
modal, Ctrl+S. Compare the status against the original.

**Grab a reproducible command:** `c` on any request → paste anywhere. The
curl includes original headers and body.

**Capture only your target:** quit, restart with
`miniproxy start --scope '*.yourtarget.com'`, reopen the TUI.

## log

```bash
miniproxy log                # last 30 requests
miniproxy log --limit 100
miniproxy log --id 42        # full detail for one request
```

Table output includes method, status, and total ms — handy for quick
sanity checks over SSH or in scripts.

## send

```bash
miniproxy send --url https://example.com/api --method POST \
  --headers '{"Content-Type":"application/json"}' \
  --body '{"key":"value"}'
```

Same semantics as the Repeater (no redirects, self-signed certs allowed,
15s timeout). Useful in shell pipelines and scripts.

## stop / status

```bash
miniproxy status
# MiniProxy is running (PID 12345).
# Web UI: http://127.0.0.1:5000

miniproxy stop
# MiniProxy terminated (PID 12345).
# Dashboard stopped (PID 12346).
```

Both are safe to run repeatedly — stale pid files (dead or recycled PIDs)
are detected and cleaned instead of acted on.
