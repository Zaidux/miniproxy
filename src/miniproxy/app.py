"""MiniProxy Flask dashboard — web UI and API for Log, Repeater, and Intruder.

The web UI mirrors the Textual TUI: a live capture table with filters on the
left, Request/Response/Intruder detail tabs on the right, and a Repeater
modal. It reads the same SQLite capture DB, so both views show identical
data whether or not the proxy is running.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from flask import (
    Response,
    Flask,
    jsonify,
    render_template,
    request as flask_request,
)

from miniproxy import connect as connect_helpers
from miniproxy import server as proxy_server
from miniproxy.addon.db import Database
from miniproxy.intruder import Intruder

app = Flask(__name__)
db = Database()
intruder = Intruder()

# Optional dashboard auth: set MINIPROXY_DASHBOARD_TOKEN and every mutating
# endpoint (plus the UI itself) requires the token via the X-MiniProxy-Token
# header or ?token= query parameter. GETs stay open so plain links/exports
# work; anything that can change state or drive the proxy is gated.
DASHBOARD_TOKEN = os.environ.get("MINIPROXY_DASHBOARD_TOKEN", "")

# ── CORS + optional token auth ──────────────────────────────────────


@app.before_request
def _token_auth():
    if not DASHBOARD_TOKEN:
        return None  # auth disabled (default for a loopback-only dashboard)
    if flask_request.method in ("GET", "HEAD", "OPTIONS"):
        return None  # read-only access stays open
    supplied = (
        flask_request.headers.get("X-MiniProxy-Token")
        or flask_request.args.get("token")
        or ""
    )
    if supplied == DASHBOARD_TOKEN:
        return None
    return jsonify({"error": "unauthorized — missing or wrong token"}), 401


@app.after_request
def add_cors_headers(response):
    # Only echo the dashboard's own origin; `*` would let any website read
    # captures (or use the token from a same-page script) cross-origin.
    origin = flask_request.headers.get("Origin", "")
    if origin.startswith(("http://127.0.0.1", "http://localhost")):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Requested-With, X-MiniProxy-Token"
        )
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


# Suppress SSL warnings for local repeater/intruder requests
import urllib3  # noqa: E402
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_REPEATER_BODY = 50000

# ── Background intruder runs ────────────────────────────────────────
# Attacks used to run inside the HTTP request thread: a 1000-word wordlist
# blocked the dashboard for the whole run and the browser timed out. Now the
# attack executes in a daemon thread and clients poll /api/intruder/status.
_intruder_lock = threading.Lock()
_intruder_job: dict[str, Any] | None = None  # {request_id, running, progress, results, error, started}


def _run_intruder_job(req_id: int, base: dict, wordlist: list[str]) -> None:
    global _intruder_job
    try:
        results = intruder.run_attack(base, wordlist, req_id)
        try:
            db.store_intruder_results(results)
        except Exception:
            pass  # results are still returned to the client even if persistence fails
        with _intruder_lock:
            _intruder_job = {
                "request_id": req_id, "running": False, "progress": len(wordlist),
                "total": len(wordlist), "results": results, "error": None,
            }
    except Exception as exc:
        with _intruder_lock:
            _intruder_job = {
                "request_id": req_id, "running": False,
                "progress": 0, "total": len(wordlist),
                "results": [], "error": str(exc),
            }


def _safe_filename(name: str, fallback: str = "miniproxy") -> str:
    """Sanitize a user-supplied string for use in a Content-Disposition filename."""
    cleaned = "".join(c for c in name if c.isalnum() or c in "._-").strip("._-")
    return cleaned or fallback


# ── Routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── Remote-browser connect flow ────────────────────────────────────────
# Point ANY browser or HTTP client — on any OS, device, or network — at the
# interception proxy: /connect explains it, /proxy.pac configures it,
# /ca.crt decrypts it. `curl -x` style explicit proxies keep working too.
# Host detection / PAC generation live in miniproxy.connect so the CLI,
# TUI, and dashboard all advertise the same addresses.

PAC_MIME = connect_helpers.PAC_MIME


def _candidate_hosts() -> list[dict[str, str]]:
    """Candidate proxy hosts, best first (the request's Host header wins)."""
    return connect_helpers.candidate_hosts(flask_request.host)


def _proxy_target(proxy_host: str | None, proxy_port: int | None) -> tuple[str, int]:
    """Resolve the proxy host:port to advertise (query overrides → running
    proxy → defaults)."""
    args = flask_request.args
    running = proxy_server.status().get("port")
    return connect_helpers.resolve_proxy_target(
        proxy_host or args.get("proxy_host", ""),
        proxy_port or args.get("port", type=int),
        flask_request.host,
        running_port=running,
        default_port=proxy_server.DEFAULT_PORT,
    )


@app.route("/proxy.pac")
def proxy_pac():
    """Proxy auto-config so browsers/OSes can point themselves at MiniProxy."""
    host, port = _proxy_target(None, None)
    return Response(
        connect_helpers.pac_body(host, port),
        mimetype=PAC_MIME,
        headers={"Cache-Control": "no-store"},
    )


@app.route("/ca.crt")
def ca_cert():
    """Serve mitmproxy's CA so devices can trust HTTPS interception without
    shell access. Read-only — never requires the dashboard token."""
    ca = connect_helpers.ca_cert_path()
    if not ca.is_file():
        return jsonify({
            "error": "CA certificate not found — run `mitmdump` once to generate it "
                     "(or set MINIPROXY_CA_CERT).",
        }), 404
    pem = ca.read_bytes()
    return Response(
        pem,
        mimetype="application/x-x509-ca-cert",
        headers={
            "Content-Disposition": 'attachment; filename="miniproxy-ca-cert.pem"',
            "Cache-Control": "no-store",
        },
    )


@app.route("/connect/qr.svg")
def connect_qr():
    """QR code (SVG) of the connect page URL — scan it from a phone."""
    from miniproxy import qrcode

    url = flask_request.url.replace("/connect/qr.svg", "/connect", 1)
    try:
        svg = qrcode.qr_svg(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return Response(svg, mimetype="image/svg+xml")


@app.route("/api/connect/info")
def connect_info():
    """Everything the Connect wizard needs: addresses, PAC/CA URLs, samples."""
    host, port = _proxy_target(None, None)
    hdr = urlsplit(f"//{flask_request.host or ''}")
    base = f"{hdr.scheme or 'http'}://{flask_request.host}"
    ca = connect_helpers.ca_cert_path()
    st = proxy_server.status()
    proxy_running = st["status"] == "running"
    curl = f"curl -x http://{host}:{port} https://example.com"
    return jsonify({
        "proxy": {"host": host, "port": port, "running": proxy_running,
                  "address": f"{host}:{port}"},
        "dashboard": {"url": base + "/", "token_required": bool(DASHBOARD_TOKEN)},
        "pac_url": base + "/proxy.pac",
        "ca_url": base + "/ca.crt",
        "ca_available": ca.is_file(),
        "ca_path": str(ca),
        "connect_url": base + "/connect",
        "hosts": _candidate_hosts(),
        "curl": {
            "plain": curl,
            "with_ca": f"curl --cacert ca.pem -x http://{host}:{port} https://example.com",
        },
    })


@app.route("/api/connect/verify", methods=["POST"])
def connect_verify():
    """Generate one proxied request from the dashboard so the user can see
    capture working end-to-end (only useful when the proxy is on this host)."""
    host, port = _proxy_target(None, None)
    proxies = {"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
    try:
        resp = requests.get(
            "https://api.github.com/zen", proxies=proxies, timeout=10,
            verify=False, allow_redirects=False,
        )
        return jsonify({"ok": True, "status": resp.status_code, "bytes": len(resp.content)})
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": str(exc)[:200]}), 200


@app.route("/api/connect/pair", methods=["GET", "POST"])
def connect_pair():
    """Record/confirm that a device completed the connect steps.

    GET returns the last pair event; POST records one (name optional).
    Stored in the capture DB's config table — survives restarts, is capped
    and sanitized, and is visible in both UIs' client lists.
    """
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        name = str(data.get("name") or "device").strip()
        # Keep it a safe short label (it is shown in dashboards/TUIs).
        name = "".join(c for c in name if c.isalnum() or c in " ._-")[:40] or "device"
        db.set_config("last_pair", name)
        db.set_config("last_pair_at", _utcnow_iso())
        return jsonify({"paired": True, "name": name})
    name = db.get_config("last_pair")
    if not name:
        return jsonify({"paired": False})
    return jsonify({"paired": True, "name": name, "at": db.get_config("last_pair_at")})


def _utcnow_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


@app.route("/connect")
def connect_page():
    """Standalone wizard: connect any browser/device to the proxy."""
    return render_template("connect.html")


# ── Proxy API ──────────────────────────────────────────────────────────

@app.route("/api/proxy/status", methods=["GET", "POST"])
def proxy_status():
    """Capture status.

    Since the v4 engine, capture is ALWAYS on — the old intercept toggle
    gated capture on a config flag that fresh DBs didn't have, silently
    producing routed-but-empty proxies. The endpoint stays for UI
    compatibility and still stores the preference, but capture no longer
    pauses.
    """
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        db.set_intercept(bool(data.get("enabled", True)))
    return jsonify({
        "intercept_enabled": True,
        "capture": "always",
        "note": "v4 engine captures unconditionally; the toggle is kept for UI compatibility.",
    })


@app.route("/api/proxy/state")
def proxy_state():
    """Live proxy process state for the header bar (mirrors the TUI proxy bar)."""
    st = proxy_server.status()
    return jsonify({
        "running": st["status"] == "running",
        "pid": st.get("pid"),
        "port": st.get("port"),
        "db_path": st.get("db"),
        "message": st.get("message", ""),
    })


@app.route("/api/proxy/toggle", methods=["POST"])
def proxy_toggle():
    """Start or stop the capture proxy (equivalent of the TUI's `p` key)."""
    data = flask_request.get_json(silent=True) or {}
    action = str(data.get("action", "")).lower()
    st = proxy_server.status()
    if action == "start" or (not action and st["status"] != "running"):
        result = proxy_server.start(with_dashboard=False)
    elif action == "stop" or (not action and st["status"] == "running"):
        result = proxy_server.stop()
    else:
        return jsonify({"error": "action must be 'start' or 'stop'"}), 400
    code = 200 if result["status"] in ("started", "stopped", "already_running", "not_running") else 503
    return jsonify(result), code


# ── Log API ────────────────────────────────────────────────────────────

@app.route("/api/logs")
def get_logs():
    since = flask_request.args.get("since", 0, type=int)
    limit = flask_request.args.get("limit", 100, type=int)
    # Server-side filters — SQL-level, so exports/polls over huge DBs stay
    # bounded instead of shipping everything and filtering client-side.
    method = flask_request.args.get("method", "").strip()
    status_class = flask_request.args.get("status", "").strip()
    url_substr = flask_request.args.get("url", "").strip()
    try:
        logs = db.get_logs(
            limit=min(max(limit, 1), 1000), since_id=since,
            method=method, status_class=status_class, url_substr=url_substr,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(logs)


@app.route("/api/logs/count")
def get_logs_count():
    """Matched-row count for the current filters (for 'N of M captures')."""
    try:
        total = db.count_logs(
            method=flask_request.args.get("method", "").strip(),
            status_class=flask_request.args.get("status", "").strip(),
            url_substr=flask_request.args.get("url", "").strip(),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"count": total})


@app.route("/api/logs/<int:req_id>")
def get_log_detail(req_id):
    entry = db.get_request(req_id)
    if entry is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(entry)


# ── Meta API ───────────────────────────────────────────────────────────

@app.route("/api/meta")
def meta():
    """Header-bar info: db path, proxy state, dashboard + proxy URLs."""
    from miniproxy import __version__
    st = proxy_server.status()
    return jsonify({
        "version": __version__,
        "db_path": db.db_path,
        "proxy_running": st["status"] == "running",
        "proxy_port": st.get("port"),
        "proxy_pid": st.get("pid"),
    })


# ── Repeater API ───────────────────────────────────────────────────────

@app.route("/api/repeater/send", methods=["POST"])
def repeater_send():
    data = flask_request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "empty request body"}), 400

    method = data.get("method", "GET").upper()
    url = data.get("url", "").strip()
    raw_headers = data.get("headers", {})
    if isinstance(raw_headers, str):
        try:
            raw_headers = json.loads(raw_headers)
        except json.JSONDecodeError:
            raw_headers = {}
    body = data.get("body", "")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=raw_headers,
            data=body,
            timeout=15,
            verify=False,
            allow_redirects=False,
        )
        return jsonify({
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:MAX_REPEATER_BODY],
        })
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


# ── Intruder API ───────────────────────────────────────────────────────

@app.route("/api/intruder/start", methods=["POST"])
def intruder_start():
    data = flask_request.get_json(silent=True) or {}
    req_id = data.get("request_id")
    wordlist = data.get("wordlist", [])

    if not req_id:
        return jsonify({"error": "request_id is required"}), 400
    if not wordlist or not isinstance(wordlist, list):
        return jsonify({"error": "wordlist must be a non-empty array"}), 400

    base = db.get_request(int(req_id))
    if base is None:
        return jsonify({"error": "base request not found"}), 404

    global _intruder_job
    with _intruder_lock:
        if _intruder_job and _intruder_job.get("running"):
            return jsonify({
                "error": "an attack is already running",
                "job": {k: _intruder_job[k] for k in ("request_id", "progress", "total")},
            }), 409
        _intruder_job = {
            "request_id": int(req_id), "running": True,
            "progress": 0, "total": len(wordlist), "results": [], "error": None,
        }
    threading.Thread(
        target=_run_intruder_job, args=(int(req_id), base, list(wordlist)),
        daemon=True, name="miniproxy-intruder",
    ).start()
    return jsonify({"started": True, "total": len(wordlist)}), 202


@app.route("/api/intruder/status")
def intruder_status():
    """Poll the running (or last) attack: progress bar + finished results."""
    with _intruder_lock:
        job = dict(_intruder_job) if _intruder_job else None
    if not job:
        return jsonify({"running": False, "has_result": False})
    payload = {
        "running": bool(job.get("running")),
        "request_id": job.get("request_id"),
        "progress": job.get("progress", 0),
        "total": job.get("total", 0),
        "error": job.get("error"),
        "has_result": bool(job.get("results")),
    }
    if not job.get("running"):
        payload["results"] = job.get("results", [])
        payload["count"] = len(job.get("results", []))
    return jsonify(payload)


@app.route("/api/intruder/results/<int:req_id>")
def intruder_results(req_id):
    results = db.get_intruder_results(req_id)
    return jsonify(results)


# ── Export / maintenance API ─────────────────────────────────────────


@app.route("/api/export/har")
def export_har():
    """Export the filtered capture set as HAR 1.2 (DevTools / Burp importable)."""
    f = _export_filters()
    try:
        rows = db.get_logs(limit=f["limit"], since_id=f["since"],
                           method=f["method"], status_class=f["status"],
                           url_substr=f["url"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # corrupted DB / IO error
        return jsonify({"error": f"export failed: {exc}"}), 500
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "MiniProxy", "version": _mp_version()},
            "entries": [_row_to_har(r) for r in rows],
        }
    }
    body = json.dumps(har, indent=2, default=str)
    fname = _safe_filename(f["url"] or "captures")
    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}.har"',
            "X-Capture-Count": str(len(rows)),
        },
    )


@app.route("/api/export/json")
def export_json():
    """Export the filtered capture set as MiniProxy's own JSON dump."""
    f = _export_filters()
    try:
        rows = db.get_logs(limit=f["limit"], since_id=f["since"],
                           method=f["method"], status_class=f["status"],
                           url_substr=f["url"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"export failed: {exc}"}), 500
    body = json.dumps(rows, indent=2, default=str)
    fname = _safe_filename(f["url"] or "captures")
    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}.json"',
            "X-Capture-Count": str(len(rows)),
        },
    )


@app.route("/api/export/db")
def export_db():
    """Download a consistent snapshot of the whole capture DB (SQLite)."""
    import tempfile

    src = Path(db.db_path)
    if not src.exists():
        return jsonify({"error": "capture DB does not exist yet"}), 404
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix="miniproxy-export-", suffix=".db")
        os.close(fd)
        src_conn = sqlite3.connect(src)
        try:
            dst_conn = sqlite3.connect(tmp)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()
        # Read into memory and delete the temp file immediately — the DB is
        # size-capped (default 50 MB) and this avoids leaking temp files on
        # clients that never "close" the response.
        payload = Path(tmp).read_bytes()
        Path(tmp).unlink(missing_ok=True)
        tmp = None
    except Exception as exc:
        if tmp:
            Path(tmp).unlink(missing_ok=True)
        return jsonify({"error": f"snapshot failed: {exc}"}), 500

    return Response(
        payload,
        mimetype="application/x-sqlite3",
        headers={"Content-Disposition": 'attachment; filename="miniproxy-captures.db"'},
    )


@app.route("/api/export/body/<int:req_id>")
def export_body(req_id):
    """Download a stored response body (falls back to the request body)."""
    row = db.get_request(req_id)
    if row is None:
        return jsonify({"error": "not found"}), 404
    payload = row.get("response_body") or ""
    if not payload and row.get("body"):
        payload = row["body"]
    if not payload:
        return jsonify({"error": "this capture has no stored body"}), 404
    ext = _body_ext(row.get("content_type") or "")
    fname = _safe_filename(row.get("url", "").rstrip("/").rsplit("/", 1)[-1] or f"body-{req_id}")
    return Response(
        payload,
        mimetype=(row.get("content_type") or "text/plain").split(";")[0].strip() or "text/plain",
        headers={"Content-Disposition": f'attachment; filename="{fname}.{ext}"'},
    )


@app.route("/api/clear", methods=["POST"])
def clear_captures():
    """Delete all captures and intruder results (irreversible)."""
    try:
        removed = db.clear()
    except Exception as exc:
        return jsonify({"error": f"clear failed: {exc}"}), 500
    return jsonify({"removed": removed})


# ── Export helpers ─────────────────────────────────────────────────────


def _mp_version() -> str:
    try:
        from miniproxy import __version__

        return __version__
    except Exception:
        return "unknown"


def _parse_headers(raw: object) -> list[dict[str, str]]:
    """Convert a stored JSON headers blob into HAR's name/value list."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raw = {}
    if not isinstance(raw, dict):
        return []
    return [{"name": str(k), "value": str(v)} for k, v in raw.items()]


def _iso_to_millis(ts: object) -> int:
    """Best-effort ISO-8601 → epoch milliseconds (HAR startedDateTime needs ISO,
    but some tooling prefers millis; we keep ISO and use millis only for order)."""
    if isinstance(ts, str):
        try:
            from datetime import datetime

            return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError:
            return 0
    return 0


def _row_to_har(r: dict) -> dict:
    """Map a capture row onto a HAR 1.2 entry (bodies included when stored)."""
    parts = urlsplit(r.get("url", ""))
    qs = []
    if parts.query:
        from urllib.parse import parse_qsl

        qs = [{"name": k, "value": v} for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    code = r.get("response_code")
    pending = code is None
    error = None
    if code == 0:
        error = "transport error (see capture detail)"
        code = 0
    started = r.get("timestamp") or ""
    total_ms = float(r.get("total_ms") or 0.0)
    req_body = r.get("body") or ""
    resp_body = r.get("response_body")
    return {
        "startedDateTime": started,
        "time": round(total_ms, 2),
        "_miniproxyId": r.get("id"),
        "_ttfbMs": r.get("ttfb_ms"),
        "request": {
            "method": r.get("method", "GET"),
            "url": r.get("url", ""),
            "httpVersion": "HTTP/1.1",
            "headers": _parse_headers(r.get("headers")),
            "queryString": qs,
            "headersSize": -1,
            "bodySize": len(req_body.encode("utf-8", "replace")),
            "postData": (
                {
                    "mimeType": "application/octet-stream",
                    "text": req_body,
                }
                if req_body
                else None
            ),
        },
        "response": {
            "status": int(code) if code else 0,
            "statusText": "" if pending else ("" if not code else ""),
            "httpVersion": "HTTP/1.1",
            "headers": _parse_headers(r.get("response_headers")),
            "content": {
                "size": len((resp_body or "").encode("utf-8", "replace")),
                "mimeType": r.get("content_type") or "",
                "text": resp_body if isinstance(resp_body, str) else "",
                "comment": "response body not captured (non-API content type)" if resp_body is None else None,
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len((resp_body or "").encode("utf-8", "replace")),
            "_transportError": error,
        },
        "cache": {},
        "timings": {
            "send": 0,
            "wait": round(float(r.get("ttfb_ms") or 0.0), 2),
            "receive": round(max(total_ms - float(r.get("ttfb_ms") or 0.0), 0.0), 2),
            "comment": "wait = ttfb_ms, receive = remainder of total_ms",
        },
    }


def _body_ext(content_type: str) -> str:
    """Pick a sensible file extension for a stored body download."""
    ct = (content_type or "").split(";")[0].strip().lower()
    return {
        "application/json": "json",
        "text/html": "html",
        "text/xml": "xml",
        "application/xml": "xml",
        "text/plain": "txt",
        "application/x-www-form-urlencoded": "txt",
        "application/pdf": "pdf",
        "image/png": "png",
        "image/jpeg": "jpg",
        "image/gif": "gif",
        "image/svg+xml": "svg",
        "text/css": "css",
        "application/javascript": "js",
        "text/javascript": "js",
    }.get(ct, "bin")


def _export_filters() -> dict:
    """Read export filters from the query string (mirrors the Live-tab filters).

    method/status/url are applied server-side (SQL) so exporting a huge DB
    stays bounded; limit caps the result either way.
    """
    args = flask_request.args
    limit = min(max(args.get("limit", 1000, type=int), 1), 10_000)
    since = max(args.get("since", 0, type=int), 0)
    return {
        "limit": limit,
        "since": since,
        "method": args.get("method", "").strip(),
        "status": args.get("status", "").strip(),
        "url": args.get("url", "").strip(),
    }


# ── Entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("MINIPROXY_DASHBOARD_PORT", 5000))
    host = os.environ.get("MINIPROXY_DASHBOARD_HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)
