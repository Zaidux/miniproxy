#!/usr/bin/env python3
"""
MiniProxy CLI — send requests through the Repeater API from the command line.

Usage:
  python3 cli.py send --url https://example.com/api --method POST    \\
                      --headers '{"Content-Type":"application/json"}' \\
                      --body '{"key":"value"}'

  python3 cli.py log                     # Show recent logged requests
  python3 cli.py log --id 5              # Show detail for request #5
  python3 cli.py status                  # Check if dashboard is running
"""

import json
import sys
import urllib.request
import urllib.error

DASHBOARD = "http://127.0.0.1:5000"


def api_post(path: str, payload: dict) -> dict:
    url = f"{DASHBOARD}{path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": body}
    except urllib.error.URLError:
        return {"error": f"Cannot connect to dashboard at {DASHBOARD}"}


def api_get(path: str) -> dict | list:
    url = f"{DASHBOARD}{path}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": body}
    except urllib.error.URLError:
        return {"error": f"Cannot connect to dashboard at {DASHBOARD}"}


def cmd_send(args: list[str]) -> None:
    """Send a modified request via the Repeater API."""
    url = ""
    method = "GET"
    headers = {}
    body = ""

    i = 0
    while i < len(args):
        if args[i] == "--url" and i + 1 < len(args):
            url = args[i + 1]
            i += 2
        elif args[i] == "--method" and i + 1 < len(args):
            method = args[i + 1].upper()
            i += 2
        elif args[i] == "--headers" and i + 1 < len(args):
            try:
                headers = json.loads(args[i + 1])
            except json.JSONDecodeError:
                print("Error: --headers must be valid JSON", file=sys.stderr)
                sys.exit(1)
            i += 2
        elif args[i] == "--body" and i + 1 < len(args):
            body = args[i + 1]
            i += 2
        else:
            i += 1

    if not url:
        print("Usage: cli.py send --url URL [--method METHOD] [--headers JSON] [--body BODY]", file=sys.stderr)
        sys.exit(1)

    payload = {"method": method, "url": url, "headers": headers, "body": body}
    result = api_post("/api/repeater/send", payload)

    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    print(f"Status: {result['status_code']}")
    print(f"Headers: {json.dumps(result.get('headers', {}), indent=2)}")
    body_text = result.get("body", "")
    print(f"Body ({len(body_text)} chars):")
    print(body_text[:2000] + ("..." if len(body_text) > 2000 else ""))


def cmd_log(args: list[str]) -> None:
    """Show logged proxy requests."""
    log_id = None
    i = 0
    while i < len(args):
        if args[i] == "--id" and i + 1 < len(args):
            log_id = int(args[i + 1])
            i += 2
        else:
            i += 1

    if log_id is not None:
        result = api_get(f"/api/logs/{log_id}")
        if isinstance(result, dict):
            print(f"ID:      {result.get('id')}")
            print(f"Method:  {result.get('method')}")
            print(f"URL:     {result.get('url')}")
            print(f"Status:  {result.get('response_code')}")
            print(f"Headers: {result.get('headers', '')[:500]}")
            print(f"Body:    {(result.get('body') or '')[:1000]}")
        else:
            print(f"Result: {result}")
    else:
        logs = api_get("/api/logs")
        if isinstance(logs, list):
            print(f"{'ID':>4} {'METHOD':<7} {'STATUS':<5} URL")
            print("-" * 60)
            for r in logs[:30]:
                print(f"{r.get('id', '?'):>4} {r.get('method','?'):<7} {r.get('response_code','?'):<5} {r.get('url','')[:70]}")
            if len(logs) > 30:
                print(f"... and {len(logs) - 30} more")
        else:
            print(f"Logs: {logs}")


def cmd_status(args: list[str]) -> None:
    """Check if dashboard is running."""
    result = api_get("/api/proxy/status")
    if isinstance(result, dict):
        intercept = result.get("intercept_enabled", "?")
        print(f"Dashboard:  RUNNING at {DASHBOARD}")
        print(f"Intercept:  {'ON' if intercept else 'OFF'}")
        print(f"Proxy:      127.0.0.1:8080")
        print(f"Logs:       /root/miniproxy/logs/")
    else:
        print(f"Dashboard:  NOT RUNNING (start with ./start.sh)")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        "send": cmd_send,
        "log": cmd_log,
        "status": cmd_status,
    }

    if command in commands:
        commands[command](args)
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()