#!/usr/bin/env bash
set -e

# ─── MiniProxy Launcher ────────────────────────────────────────────────
# Boots mitmdump (interception proxy) + Flask dashboard in one command.
# Usage:  ./start.sh              # foreground, both logs to stdout
#         ./start.sh --daemon     # background, logs to dir
#         ./start.sh --kill       # stop background processes
# ────────────────────────────────────────────────────────────────────────

ROOT="$(cd "$(dirname "$0")" && pwd)"
LOGDIR="$ROOT/logs"
mkdir -p "$LOGDIR"

case "${1:-}" in
  --kill)
    echo "[miniproxy] Stopping..."
    pkill -f "mitmdump.*miniproxy" 2>/dev/null || true
    pkill -f "flask.*miniproxy" 2>/dev/null || true
    pkill -f "python3.*app.py" 2>/dev/null || true
    echo "[miniproxy] Stopped."
    exit 0
    ;;
  --daemon)
    echo "[miniproxy] Starting daemon..."
    mitmdump -s "$ROOT/proxy.py" --set block_global=false \
      > "$LOGDIR/mitmdump.log" 2>&1 &
    MITM_PID=$!
    echo "[miniproxy] mitmdump PID $MITM_PID"

    cd "$ROOT" && python3 app.py \
      > "$LOGDIR/flask.log" 2>&1 &
    FLASK_PID=$!
    echo "[miniproxy] flask PID $FLASK_PID"

    echo "$MITM_PID" > "$LOGDIR/mitmdump.pid"
    echo "$FLASK_PID" > "$LOGDIR/flask.pid"
    echo "[miniproxy] Daemon started (proxy :8080 | dashboard :5000)"
    ;;
  *)
    echo "[miniproxy] Starting (foreground) — proxy :8080 | dashboard :5000"
    echo "[miniproxy] Press Ctrl+C to stop both."
    echo ""
    # Start mitmdump in background (its logs go to stdout)
    mitmdump -s "$ROOT/proxy.py" --set block_global=false &
    MITM_PID=$!
    
    # Start flask in foreground (so Ctrl+C catches it)
    cd "$ROOT" && python3 app.py &
    FLASK_PID=$!
    
    # Trap to clean up
    trap "echo '[miniproxy] Shutting down...'; kill $MITM_PID $FLASK_PID 2>/dev/null; exit 0" SIGINT SIGTERM
    
    wait $MITM_PID $FLASK_PID
    ;;
esac