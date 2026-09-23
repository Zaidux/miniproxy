"""MiniProxy entry point — ``miniproxy`` / ``python -m miniproxy``.

Subcommands:
  start      Start the interception proxy (mitmdump + v4 addon) — the web
             dashboard is launched alongside and its URL printed, unless
             --no-dashboard is given. Capture is unchanged either way.
  stop       Stop the proxy (and the dashboard)
  status     Proxy + dashboard status
  dashboard  Run the Flask dashboard in the foreground
  web        Start the proxy AND the web dashboard in one step (alias of
             `start` with the dashboard forced on)
  tui        Run the terminal UI (Textual) — live feed, details, repeater
  send       Send a request through the dashboard's Repeater
  log        Show captured requests
"""
from __future__ import annotations

import argparse
import os
import sys


def _same_option(p: argparse.ArgumentParser, flag: str) -> dict:
    """Copy an option's kwargs from one subparser to build it on another."""
    for action in p._actions:
        if flag in action.option_strings:
            kwargs = {"default": action.default, "help": action.help}
            if action.__class__.__name__ == "_StoreTrueAction":
                kwargs["action"] = "store_true"
            return kwargs
    return {"default": None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="miniproxy",
        description="HTTP/S interception proxy for security research.",
    )
    sub = parser.add_subparsers(dest="command")

    p_start = sub.add_parser("start", help="Start the interception proxy (+ web dashboard)")
    p_start.add_argument("--port", type=int, default=8080)
    p_start.add_argument("--db", default=None, help="SQLite capture DB path")
    p_start.add_argument("--scope", nargs="*", default=None,
                         help="Capture-scope hosts (*.domain wildcards); "
                              "out-of-scope traffic is not captured")
    p_start.add_argument("--block-out-of-scope", action="store_true",
                         help="403-block out-of-scope traffic instead of passing it through")
    p_start.add_argument("--mitmdump", default="mitmdump")
    p_start.add_argument("--dashboard-port", type=int, default=5000,
                         help="Port for the web dashboard (default 5000)")
    p_start.add_argument("--dashboard-host", default="127.0.0.1",
                         help="Bind address for the web dashboard "
                              "(default 127.0.0.1; pass 0.0.0.0 explicitly for LAN access)")
    p_start.add_argument("--dashboard-token", default=None,
                         help="Require this token for the dashboard's mutating "
                              "endpoints (recommended with --dashboard-host 0.0.0.0)")
    p_start.add_argument("--no-dashboard", action="store_true",
                         help="Do not launch the web dashboard")

    sub.add_parser("web", help="Start the proxy AND the web dashboard (alias of start)")
    p_web = sub.add_parser("web")
    for opt in ("--port", "--db", "--scope", "--mitmdump", "--dashboard-port",
                "--dashboard-host", "--dashboard-token", "--no-dashboard"):
        p_web.add_argument(opt, **_same_option(p_start, opt))
    p_web.add_argument("--block-out-of-scope", action="store_true")

    sub.add_parser("stop", help="Stop the proxy and the dashboard")
    sub.add_parser("status", help="Proxy + dashboard status")

    p_dash = sub.add_parser("dashboard", help="Run the Flask dashboard")
    p_dash.add_argument("--port", type=int, default=5000)
    p_dash.add_argument("--host", default="127.0.0.1")
    p_dash.add_argument("--token", default=None,
                        help="Require a token on mutating endpoints")

    p_tui = sub.add_parser("tui", help="Run the terminal UI (Textual)")
    p_tui.add_argument("--db", default=None, help="SQLite capture DB path")
    p_tui.add_argument("--refresh", type=float, default=2.0,
                       help="Poll interval in seconds (default 2.0)")

    p_send = sub.add_parser("send", help="Send a request via the dashboard Repeater")
    p_send.add_argument("--url", required=True)
    p_send.add_argument("--method", default="GET")
    p_send.add_argument("--headers", default="{}", help="JSON object of headers")
    p_send.add_argument("--body", default="")

    p_log = sub.add_parser("log", help="Show captured requests")
    p_log.add_argument("--id", type=int, default=None)
    p_log.add_argument("--limit", type=int, default=30)

    args = parser.parse_args(argv)

    if args.command in ("start", "web"):
        from miniproxy import server
        dash_host = getattr(args, "dashboard_host", None) or "127.0.0.1"
        result = server.start(
            port=args.port, db_path=args.db, scope_hosts=args.scope,
            out_of_scope="block" if args.block_out_of_scope else "skip",
            mitmdump_path=args.mitmdump,
            dashboard=not args.no_dashboard,
            dash_port=args.dashboard_port,
            dash_host=dash_host,
            dash_token=args.dashboard_token,
        )
        if dash_host not in ("127.0.0.1", "localhost"):
            print("⚠  Dashboard is LAN-exposed: captures contain tokens, cookies "
                  "and session data. Pass --dashboard-token to require auth.")
        print(result["message"])
        if result.get("dashboard"):
            print(f"Web UI: {result['dashboard']['url']}  (mirrors `miniproxy tui`)")
        return 0 if result["status"] in ("started", "already_running") else 1

    if args.command == "stop":
        from miniproxy import server
        result = server.stop()
        print(result["message"])
        dash = server.stop_dashboard()
        print(dash["message"])
        ok = result["status"] in ("stopped", "not_running") and dash["status"] in ("stopped", "not_running")
        return 0 if ok else 1

    if args.command == "status":
        from miniproxy import server
        result = server.status()
        print(result["message"])
        dash_port = result.get("dashboard")
        if result["status"] == "running" and dash_port:
            print(f"Web UI: http://127.0.0.1:{dash_port}")
        return 0 if result["status"] == "running" else 1

    if args.command == "dashboard":
        import miniproxy.app as appmod
        if args.token:
            os.environ["MINIPROXY_DASHBOARD_TOKEN"] = args.token
            appmod.DASHBOARD_TOKEN = args.token
        if args.host not in ("127.0.0.1", "localhost"):
            print("⚠  Dashboard is LAN-exposed: captures contain tokens, cookies "
                  "and session data. Pass --token to require auth.")
        appmod.app.run(host=args.host, port=args.port, debug=False)
        return 0

    if args.command == "tui":
        # The TUI needs a real terminal; refuse to hang inside pipes/CI.
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("Error: `miniproxy tui` needs an interactive terminal.",
                  file=sys.stderr)
            return 1
        from miniproxy.tui import run_tui
        return run_tui(db_path=args.db, refresh=args.refresh)

    if args.command == "send":
        # Direct request — no dashboard needed (mirrors the Repeater API's
        # semantics: no redirects, self-signed certs allowed, 15s timeout).
        import json as _json

        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            headers = _json.loads(args.headers)
            if not isinstance(headers, dict):
                headers = {}
        except ValueError:
            print("Error: --headers must be a JSON object", file=sys.stderr)
            return 1
        try:
            resp = requests.request(
                method=args.method.upper(), url=args.url, headers=headers,
                data=args.body, timeout=15, verify=False, allow_redirects=False,
            )
        except requests.RequestException as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Status: {resp.status_code}")
        print(f"Headers: {_json.dumps(dict(resp.headers), indent=2)}")
        body_text = resp.text or ""
        print(f"Body ({len(body_text)} chars):")
        print(body_text[:2000] + ("..." if len(body_text) > 2000 else ""))
        return 0

    if args.command == "log":
        # Reads the capture DB directly — the dashboard does not need to
        # be running to inspect what the proxy captured.
        from miniproxy.addon.db import Database
        from miniproxy.server import STATE_DIR

        db = Database(os.environ.get("MINIPROXY_DB_PATH") or (STATE_DIR / "proxy.db"))
        if args.id is not None:
            row = db.get_request(args.id)
            if row is None:
                print(f"No captured request with id={args.id}.", file=sys.stderr)
                return 1
            print(f"ID:      {row.get('id')}")
            print(f"Method:  {row.get('method')}")
            print(f"URL:     {row.get('url')}")
            print(f"Status:  {row.get('response_code')}")
            print(f"TTFB:    {row.get('ttfb_ms')} ms | Total: {row.get('total_ms')} ms")
            print(f"Headers: {str(row.get('headers') or '')[:500]}")
            print(f"Body:    {str(row.get('body') or '')[:1000]}")
            return 0
        logs = db.get_logs(limit=max(args.limit, 1))
        print(f"{'ID':>4} {'METHOD':<7} {'STATUS':<5} {'MS':>7}  URL")
        print("-" * 72)
        for r in logs:
            ms = r.get("total_ms")
            ms_s = f"{ms:.0f}" if isinstance(ms, (int, float)) else "?"
            print(f"{r.get('id', '?'):>4} {r.get('method', '?'):<7} "
                  f"{r.get('response_code', '?'):<5} {ms_s:>7}  "
                  f"{str(r.get('url', ''))[:60]}")
        if not logs:
            print("(no captured requests yet)")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
