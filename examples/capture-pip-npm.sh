#!/usr/bin/env bash
# Capture pip and npm package traffic with MiniProxy.
#
#   miniproxy start
#   bash examples/capture-pip-npm.sh
#
# Every package index request, wheel download, and registry ping shows up in
# the capture DB — handy for supply-chain audits and dependency reviews.
set -euo pipefail

PROXY="${MINIPROXY_PROXY:-http://127.0.0.1:8080}"
CA="${MINIPROXY_CA:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"

export http_proxy="$PROXY"  https_proxy="$PROXY"
export HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY"
export NO_PROXY="localhost,127.0.0.1"

# Clients need to trust mitmproxy's CA for HTTPS bodies.
export REQUESTS_CA_BUNDLE="$CA"        # pip (uses requests/urllib3)
export NODE_EXTRA_CA_CERTS="$CA"       # npm / Node

echo "▸ pip install (captured)"
pip install --quiet --dry-run requests

echo "▸ npm ping (captured)"
npm ping --silent

echo "▸ captured — run 'miniproxy log' or open the dashboard to inspect"
