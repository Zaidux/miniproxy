"""MiniProxy entry point — ``miniproxy`` / ``python -m miniproxy``.

Subcommands:
  start      Start the interception proxy (mitmdump + v4 addon)
  stop       Stop the proxy
  status     Proxy status
  dashboard  Run the Flask dashboard (Log / Repeater / Intruder UI)
  send       Send a request through the dashboard's Repeater
  log        Show captured requests
"""
from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="miniproxy",
        description="HTTP/S interception proxy for security research.",
    )
    sub = parser.add_subparsers(dest="command")

    p_start = sub.add_parser("start", help="Start the interception proxy")
    p_start.add_argument("--port", type=int, default=8080)
    p_start.add_argument("--db", default=None, help="SQLite capture DB path")
    p_start.add_argument("--scope", nargs="*", default=None,
                         help="Capture-scope hosts (*.domain wildcards); "
                              "out-of-scope traffic is not captured")
    p_start.add_argument("--block-out-of-scope", action="store_true",
                         help="403-block out-of-scope traffic instead of passing it through")
    p_start.add_argument("--mitmdump", default="mitmdump")

    sub.add_parser("stop", help="Stop the proxy")
    sub.add_parser("status", help="Proxy status")

    p_dash = sub.add_parser("dashboard", help="Run the Flask dashboard")
    p_dash.add_argument("--port", type=int, default=5000)
    p_dash.add_argument("--host", default="127.0.0.1")

    p_send = sub.add_parser("send", help="Send a request via the dashboard Repeater")
    p_send.add_argument("--url", required=True)
    p_send.add_argument("--method", default="GET")
    p_send.add_argument("--headers", default="{}", help="JSON object of headers")
    p_send.add_argument("--body", default="")

    p_log = sub.add_parser("log", help="Show captured requests")
    p_log.add_argument("--id", type=int, default=None)
    p_log.add_argument("--limit", type=int, default=30)

    args = parser.parse_args(argv)

    if args.command == "start":
        from miniproxy import server
        result = server.start(
            port=args.port, db_path=args.db, scope_hosts=args.scope,
            out_of_scope="block" if args.block_out_of_scope else "skip",
            mitmdump_path=args.mitmdump,
        )
        print(result["message"])
        return 0 if result["status"] in ("started", "already_running") else 1

    if args.command == "stop":
        from miniproxy import server
        result = server.stop()
        print(result["message"])
        return 0 if result["status"] in ("stopped", "not_running") else 1

    if args.command == "status":
        from miniproxy import server
        result = server.status()
        print(result["message"])
        return 0 if result["status"] == "running" else 1

    if args.command == "dashboard":
        from miniproxy.app import app
        app.run(host=args.host, port=args.port, debug=False)
        return 0

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
