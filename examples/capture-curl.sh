#!/usr/bin/env bash
# Route curl through MiniProxy (HTTP + HTTPS) and see it captured.
#
#   miniproxy start          # proxy on :8080, dashboard on :5000
#   bash examples/capture-curl.sh https://api.github.com/zen
#
# Plain HTTP needs no setup; HTTPS needs mitmproxy's CA (see --ca below).
set -euo pipefail

PROXY="${MINIPROXY_PROXY:-http://127.0.0.1:8080}"
CA="${MINIPROXY_CA:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <url> [--no-ca]" >&2
  exit 1
fi

url="$1"
args=(-x "$PROXY" -sS -i)

# Trust the mitmproxy CA for HTTPS bodies (generate once: run `mitmdump`).
if [[ "${2:-}" != "--no-ca" && "$url" == https:* && -f "$CA" ]]; then
  args+=(--cacert "$CA")
fi

echo "▸ routing through $PROXY — watch it appear in the dashboard/TUI"
exec curl "${args[@]}" "$url"
