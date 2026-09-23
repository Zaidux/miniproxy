#!/usr/bin/env bash
# Run MiniProxy on a VPS and connect a browser from anywhere.
#
#   ssh root@your-vps
#   bash examples/remote-vps.sh            # installs + starts proxy & dashboard
#
# Then, from any device on any network, open the printed /connect URL and
# follow the wizard (PAC URL, CA download, QR code).
#
# ⚠️ This exposes the dashboard to the internet. The script generates a random
# token and requires Basic-auth protection via an SSH tunnel in "tunnel"
# mode — prefer mode 1 unless you know you need 0.0.0.0.
set -euo pipefail

PROXY_PORT="${MINIPROXY_PROXY_PORT:-8080}"
DASH_PORT="${MINIPROXY_DASH_PORT:-5000}"
MODE="${1:-tunnel}"          # tunnel | public

if [[ "$MODE" == "public" ]]; then
  # Direct internet exposure — a token is mandatory on mutating endpoints.
  TOKEN_FILE="$HOME/.miniproxy/dashboard.token"
  mkdir -p "$HOME/.miniproxy"
  if [[ -f "$TOKEN_FILE" ]]; then
    TOKEN="$(cat "$TOKEN_FILE")"
  else
    TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '=+/' | head -c 24)"
    printf '%s' "$TOKEN" > "$TOKEN_FILE"; chmod 600 "$TOKEN_FILE"
  fi
  DASH_HOST="0.0.0.0"
  TOKEN_ARGS=(--dashboard-token "$TOKEN")
else
  TOKEN_ARGS=()
  DASH_HOST="127.0.0.1"
fi

# ── 1. install (idempotent) ─────────────────────────────────────────
if ! command -v miniproxy >/dev/null 2>&1; then
  pip3 install --upgrade riciplay-miniproxy
fi
if ! command -v mitmdump >/dev/null 2>&1; then
  pip3 install --upgrade mitmproxy
  mitmdump --version >/dev/null   # generates the CA under ~/.mitmproxy
fi

# ── 2. start (binds the proxy on all interfaces so any device can reach it) ──
miniproxy stop >/dev/null 2>&1 || true
miniproxy start \
  --port "$PROXY_PORT" \
  --dashboard-host "$DASH_HOST" --dashboard-port "$DASH_PORT" \
  "${TOKEN_ARGS[@]}"

echo
echo "══════════════════════════════════════════════════════════════"
if [[ "$MODE" == "public" ]]; then
  IP="$(curl -s https://ifconfig.me || hostname -I | awk '{print $1}')"
  echo "  Connect tab : http://$IP:$DASH_PORT/connect"
  echo "  Token       : $TOKEN   (paste it once in the dashboard)"
  echo "  PAC URL     : http://$IP:$DASH_PORT/proxy.pac"
  echo "  CA download : http://$IP:$DASH_PORT/ca.crt"
  echo
  echo "  ⚠️  Dashboard is internet-exposed. Use a firewall rule to limit"
  echo "  access, and stop with 'miniproxy stop' when done."
else
  echo "  Local port-forward (run on YOUR laptop):"
  echo "    ssh -L $DASH_PORT:127.0.0.1:$DASH_PORT -L $PROXY_PORT:127.0.0.1:$PROXY_PORT user@this-vps"
  echo
  echo "  Then open http://127.0.0.1:$DASH_PORT/connect on your machine."
fi
echo "══════════════════════════════════════════════════════════════"
