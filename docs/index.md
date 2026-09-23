# MiniProxy Documentation

MiniProxy is a lightweight HTTP/S interception proxy for local security
research — think "Burp Suite in your terminal and browser", built on
**mitmproxy**, **Flask**, **SQLite**, and **Textual**.

Everything (TUI, web dashboard, CLI) reads the same SQLite capture DB, so
you can start the proxy once and inspect traffic from any interface.

| Doc | What's in it |
|-----|--------------|
| [Setup](setup.md) | Install, first run, HTTPS/CA certificates, updating |
| [CLI & TUI](cli-and-tui.md) | Every `miniproxy` command, TUI keys & workflows |
| [Web UI](web-ui.md) | The browser dashboard that mirrors the TUI |
| [Integrations](integrations.md) | curl, pip, Node, Python, Git, Docker, mobile devices, Burp/other proxies |
| [Troubleshooting](troubleshooting.md) | Common errors and fixes, FAQ |

## The 30-second tour

```bash
pip install riciplay-miniproxy   # or: npm install -g riciplay-miniproxy
miniproxy start                  # proxy on :8080 + web UI on :5000 (URL is printed)
```

Point any client (browser, curl, pip…) at `http://127.0.0.1:8080`, open the
printed Web-UI URL in your browser — or run `miniproxy tui` in a terminal.
Traffic shows up live in both.

```bash
miniproxy stop                   # when you're done
```

## Which interface should I use?

| | TUI (`miniproxy tui`) | Web UI (`miniproxy start`) | CLI (`miniproxy log`/`send`) |
|---|---|---|---|
| Live feed + filters | ✓ | ✓ | — |
| Request/Response inspection | ✓ | ✓ | `log --id N` |
| Repeater | ✓ (modal, Ctrl+S) | ✓ (modal + full tab) | `send --url …` |
| Intruder results | ✓ (read-only) | ✓ (run + view) | — |
| Copy as curl | ✓ (`c`) | ✓ (button) | — |
| Start/stop proxy | ✓ (`p`) | ✓ (header button) | `miniproxy start/stop` |
| Needs a terminal | ✓ | ✗ | ✗ |
| Works over SSH on a server | ✓ | ✓ (port-forward) | ✓ |

## Safety & scope

MiniProxy is for **local security research and education** on systems you
own or are authorized to test. Use the scope guard
(`miniproxy start --scope '*.target.com'`) to keep unrelated traffic out of
your capture DB, and never point it at production systems you don't control.

## License

MIT — see [LICENSE](../LICENSE).
