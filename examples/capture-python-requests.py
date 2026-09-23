#!/usr/bin/env python3
"""Capture Python `requests` traffic with MiniProxy.

    miniproxy start
    python3 examples/capture-python-requests.py https://api.github.com/zen

Explicit per-call proxies (no environment variables needed). The CA bundle
is only required to read HTTPS *bodies* — without it the request still
routes through the proxy but TLS is end-to-end.
"""
from __future__ import annotations

import os
import sys

import requests

PROXY = os.environ.get("MINIPROXY_PROXY", "http://127.0.0.1:8080")
CA = os.environ.get("MINIPROXY_CA") or os.path.expanduser(
    "~/.mitmproxy/mitmproxy-ca-cert.pem"
)

# Route through MiniProxy; verify against mitmproxy's CA for HTTPS.
proxies = {"http": PROXY, "https": PROXY}


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "https://api.github.com/zen"
    verify = CA  # mitmproxy's CA, not the system store
    try:
        resp = requests.get(url, proxies=proxies, verify=verify, timeout=15)
    except requests.RequestException as exc:
        print(f"request failed: {exc}", file=sys.stderr)
        print("is `miniproxy start` running? missing CA? (run `mitmdump` once)",
              file=sys.stderr)
        return 1
    print(f"{resp.status_code} {url}  ({len(resp.text)} bytes)")
    print(resp.text[:500])
    print("\n▸ captured — see it in `miniproxy log`, the TUI, or the dashboard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
