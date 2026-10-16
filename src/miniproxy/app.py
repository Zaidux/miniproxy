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
from miniproxy.addon.db import HIGHLIGHT_COLORS, Database
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


def _run_intruder_job(req_id: int, base: dict,
                      wordlist: list[str]) -> None:
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


def _run_pitchfork_job(req_id: int, base: dict,
                       lists: dict[str, list[str]]) -> None:
    """Background runner for a multi-position attack."""
    global _intruder_job
    total = 1
    for words in lists.values():
        total *= max(len(words), 1)
    try:
        results = intruder.run_pitchfork(base, lists, req_id)
        try:
            db.store_intruder_results(results)
        except Exception:
            pass
        with _intruder_lock:
            _intruder_job = {
                "request_id": req_id, "running": False, "progress": total,
                "total": total, "results": results, "error": None,
                "mode": "pitchfork",
            }
    except Exception as exc:
        with _intruder_lock:
            _intruder_job = {
                "request_id": req_id, "running": False, "progress": 0,
                "total": total, "results": [], "error": str(exc),
                "mode": "pitchfork",
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
    st = proxy_server.status()
    return connect_helpers.resolve_proxy_target(
        proxy_host or args.get("proxy_host", ""),
        proxy_port or args.get("port", type=int),
        flask_request.host,
        running_port=st.get("port"),
        default_port=proxy_server.DEFAULT_PORT,
        # Keeps the PAC honest when the proxy is loopback-only: devices must
        # use their own 127.0.0.1 (via a port forward), not this server's
        # public IP, which no longer accepts proxy connections.
        bind_host=st.get("host"),
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
    """Pair the device that made this request (legacy single-device view).

    POST registers the caller in the persistent device registry (name,
    source IP, user agent) and records the last pair event. GET returns
    the last pair event only. Prefer /api/connect/devices for the full
    registry.
    """
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        name = str(data.get("name") or "device").strip()
        # Keep it a safe short label (it is shown in dashboards/TUIs).
        name = "".join(c for c in name if c.isalnum() or c in " ._-")[:40] or "device"
        db.register_device(name, _client_ip(),
                           flask_request.headers.get("User-Agent", "")[:200])
        db.set_config("last_pair", name)
        db.set_config("last_pair_at", _utcnow_iso())
        return jsonify({"paired": True, "name": name})
    name = db.get_config("last_pair")
    if not name:
        return jsonify({"paired": False})
    return jsonify({"paired": True, "name": name, "at": db.get_config("last_pair_at")})


@app.route("/api/connect/devices", methods=["GET", "POST"])
def connect_devices():
    """Persistent registry of connected devices.

    GET lists saved devices (most recently active first). POST saves one:
    the caller's own IP/User-Agent are recorded automatically — a device
    always pairs as itself — with the JSON body supplying the name.
    Pairing the same name from the same IP again refreshes last_seen
    instead of duplicating.
    """
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        name = str(data.get("name") or "device").strip()
        name = "".join(c for c in name if c.isalnum() or c in " ._-")[:40] or "device"
        device_id = db.register_device(
            name, _client_ip(),
            flask_request.headers.get("User-Agent", "")[:200],
        )
        return jsonify({"saved": True, "id": device_id, "name": name}), 201
    return jsonify({"devices": db.get_devices(),
                    "your_ip": _client_ip()})


@app.route("/api/connect/devices/<int:device_id>", methods=["DELETE"])
def connect_device_delete(device_id):
    """Forget one saved device."""
    if not db.remove_device(device_id):
        return jsonify({"error": "no such device"}), 404
    return jsonify({"removed": True, "id": device_id})


def _client_ip() -> str:
    """The remote address that actually reached us (X-Forwarded-For is
    trivially spoofable and the registry is informational — keep the
    socket truth)."""
    return (flask_request.remote_addr or "").strip()[:45]


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

    Capture itself is ALWAYS on in the v4 engine — an earlier intercept
    toggle gated capture on a config flag that fresh DBs didn't have, which
    silently produced routed-but-empty proxies. The preference is still
    stored, and it is now the value actually read back by the intercept
    addon (both sides use the same 'intercept' config key), so the reported
    value reflects stored state instead of a hardcoded True.
    """
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        db.set_intercept(bool(data.get("enabled", True)))
    return jsonify({
        "intercept_enabled": db.get_intercept(),
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

def _truthy(value: str | None) -> bool:
    """Query-string truthiness: 1/true/yes/on (case-insensitive)."""
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _log_filters(**overrides: Any) -> dict[str, Any]:
    """Read the shared capture filters off the query string.

    Every filter-consuming endpoint goes through here (listing, count, the
    hosts rollup and all exports) so the Live tab, the request picker and the
    export menu can never drift apart.  ``id`` is the shared id selector —
    ``42``, ``1,5,9``, ``100-200``, or any comma/space separated mix.

    ``host`` narrows to one target, ``exclude_host`` removes one, and
    ``hide_static`` drops images/fonts/css/js/media — together these are the
    dashboard-side answer to browser noise on an already-captured DB.
    """
    args = flask_request.args
    filters: dict[str, Any] = {
        "method": args.get("method", "").strip(),
        "status_class": args.get("status", "").strip(),
        "url_substr": args.get("url", "").strip(),
        "ids": args.get("id", "").strip(),
        "host": args.get("host", "").strip(),
        "exclude_host": args.get("exclude_host", "").strip(),
        "hide_static": _truthy(args.get("hide_static")),
        "highlighted_only": _truthy(args.get("highlighted_only")),
        "body_substr": args.get("body", "").strip(),
        "exclude_body": args.get("exclude_body", "").strip(),
        "min_length": max(args.get("min_length", 0, type=int), 0),
    }
    filters.update(overrides)
    return filters


@app.route("/api/logs")
def get_logs():
    since = flask_request.args.get("since", 0, type=int)
    limit = flask_request.args.get("limit", 100, type=int)
    # Server-side filters — SQL-level, so exports/polls over huge DBs stay
    # bounded instead of shipping everything and filtering client-side.
    try:
        logs = db.get_logs(
            limit=min(max(limit, 1), 1000), since_id=since, **_log_filters()
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(logs)


@app.route("/api/logs/count")
def get_logs_count():
    """Matched-row count for the current filters (for 'N of M captures')."""
    try:
        total = db.count_logs(**_log_filters())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"count": total})


@app.route("/api/logs/<int:req_id>")
def get_log_detail(req_id):
    entry = db.get_request(req_id)
    if entry is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(entry)


@app.route("/api/logs/<int:req_id>", methods=["PATCH"])
def annotate_log(req_id):
    """Set a capture's highlight color and/or note.

    Only the keys present in the body are touched, so a note edit never clears
    the highlight (and vice versa). Colors are validated against the palette:
    the value is rendered into a style attribute, so free-form CSS here would
    be a stored-XSS hole.
    """
    data = flask_request.get_json(silent=True) or {}
    highlight = data["highlight"] if "highlight" in data else None
    note = data["note"] if "note" in data else None
    try:
        ok = db.annotate(req_id, highlight=highlight, note=note)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not ok:
        return jsonify({"error": "not found"}), 404
    row = db.get_request(req_id)
    return jsonify({"id": req_id, "highlight": row.get("highlight"),
                    "note": row.get("note") or ""})


@app.route("/api/hosts")
def list_hosts():
    """Distinct hosts with capture counts, busiest first.

    Drives the focus-host picker and the 'N hidden as noise' badge: it is the
    cheapest way to see at a glance which host is eating the capture DB.
    """
    return jsonify({
        "hosts": db.list_hosts(limit=flask_request.args.get("limit", 200, type=int)),
    })


# ── Noise API ──────────────────────────────────────────────────────────

@app.route("/api/noise/rules", methods=["GET", "POST"])
def noise_rules():
    """List or add noise rules (hosts whose traffic should never be captured).

    POST ``{"value": "ads.example.com", "kind": "host", "enabled": true}``.
    POST with ``{"enable_builtin": true}`` flips the whole seeded telemetry
    list at once — the one-click opt-in for the browser-noise problem.
    """
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        if "enable_builtin" in data:
            changed = db.enable_all_noise_rules(bool(data["enable_builtin"]))
            return jsonify({"ok": True, "rules": db.list_noise_rules(),
                            "changed": changed})
        value = data.get("value", "")
        kind = data.get("kind", "host")
        enabled = data.get("enabled", True)
        try:
            rule_id = db.add_noise_rule(value, kind, bool(enabled))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": True, "id": rule_id,
                        "rules": db.list_noise_rules()}), 201
    return jsonify({"rules": db.list_noise_rules(),
                    "palette": list(HIGHLIGHT_COLORS)})


@app.route("/api/noise/rules/<int:rule_id>", methods=["PATCH", "DELETE"])
def noise_rule(rule_id):
    """Enable/disable one rule, or delete it."""
    if flask_request.method == "DELETE":
        if not db.delete_noise_rule(rule_id):
            return jsonify({"error": "no such rule"}), 404
        return jsonify({"ok": True, "rules": db.list_noise_rules()})
    data = flask_request.get_json(silent=True) or {}
    ok = db.set_noise_rule_enabled(rule_id, bool(data.get("enabled", True)))
    if not ok:
        return jsonify({"error": "no such rule"}), 404
    return jsonify({"ok": True, "rules": db.list_noise_rules()})


@app.route("/api/noise/scan")
def noise_scan():
    """Dry run: what a cleanup would remove, and why. Never deletes."""
    return jsonify(db.scan_noise())


@app.route("/api/noise/clean", methods=["POST"])
def noise_clean():
    """Bulk-delete captures matching the enabled rules (and static assets).

    Refuses without ``{"confirm": true}`` so a stray POST can't wipe a
    session, and takes a ``.noise-backup-*.db`` snapshot first — the
    response returns that path so it can be restored from.
    """
    data = flask_request.get_json(silent=True) or {}
    if not data.get("confirm"):
        preview = db.scan_noise()
        return jsonify({
            "error": "confirmation required",
            "matched": preview["matched"],
            "keep": preview["keep"],
            "by_host": preview["by_host"],
        }), 400
    keep = data.get("keep_hosts") or []
    if not isinstance(keep, list):
        return jsonify({"error": "keep_hosts must be a list"}), 400
    result = db.clean_noise(keep_hosts=[str(h) for h in keep])
    return jsonify({"ok": True, **result})


# ── Meta API ───────────────────────────────────────────────────────────

# ── Diff API ──────────────────────────────────────────────────────────

@app.route("/api/diff/<int:a_id>/<int:b_id>")
def diff_captures(a_id: int, b_id: int):
    """Compare two captures the way Burp's Compare Responses does.

    The access-control workflow: send the same request twice with one
    parameter changed, then ask "what actually changed?". Picks the best
    available mode automatically (JSON → token → character) so HTML pages do
    not degrade into one unreadable changed-bytes blob.

    ``?mode=json|token|char`` forces a specific view.
    """
    from miniproxy.diff import diff_captures as _diff

    a, b = db.get_request(a_id), db.get_request(b_id)
    if a is None or b is None:
        missing = a_id if a is None else b_id
        return jsonify({"error": f"capture {missing} not found"}), 404
    if a_id == b_id:
        # Comparing a capture with itself is almost certainly a mis-click;
        # say so rather than returning a confident "identical".
        return jsonify({"error": "pick two different captures to compare"}), 400
    try:
        result = _diff(a, b, mode=flask_request.args.get("mode", "auto"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    # Bodies are returned separately below only when requested, so the
    # default payload stays small enough to render instantly.
    if not _truthy(flask_request.args.get("include_bodies")):
        result = {k: v for k, v in result.items() if k != "body"}
        result["body_withheld"] = True
    return jsonify(result)


@app.route("/api/diff/<int:a_id>/<int:b_id>/bodies")
def diff_bodies(a_id: int, b_id: int):
    """The two raw bodies for the diff view (fetched on demand)."""
    a, b = db.get_request(a_id), db.get_request(b_id)
    if a is None or b is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "a": {"body": a.get("body") or "", "response_body": a.get("response_body") or ""},
        "b": {"body": b.get("body") or "", "response_body": b.get("response_body") or ""},
    })


# ── Repeater tabs / history API ───────────────────────────────────────

@app.route("/api/repeater/tabs", methods=["GET", "POST"])
def repeater_tabs():
    """List or create persistent repeater tabs.

    Tabs survive a page refresh (unlike the previous single shared editor,
    where every send overwrote your work) and each tab keeps its own send
    history, which is what makes A/B comparison practical.
    """
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        try:
            row = db.create_repeater_tab(
                title=str(data.get("title") or "")[:120],
                method=str(data.get("method") or "GET").upper(),
                url=str(data.get("url") or ""),
                headers=data.get("headers") or {},
                body=str(data.get("body") or ""),
                source_id=data.get("source_id"),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"tab": row}), 201
    return jsonify({"tabs": db.get_repeater_tabs()})


@app.route("/api/repeater/tabs/<int:tab_id>", methods=["GET", "PATCH", "DELETE"])
def repeater_tab(tab_id: int):
    """Read, update or delete one repeater tab."""
    if flask_request.method == "DELETE":
        if not db.delete_repeater_tab(tab_id):
            return jsonify({"error": "no such tab"}), 404
        return jsonify({"ok": True})
    if flask_request.method == "PATCH":
        data = flask_request.get_json(silent=True) or {}
        try:
            ok = db.update_repeater_tab(tab_id, **{
                k: v for k, v in data.items()
                if k in ("title", "method", "url", "headers", "body", "source_id")
            })
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400
        if not ok:
            return jsonify({"error": "no such tab"}), 404
    row = db.get_repeater_tab(tab_id)
    if row is None:
        return jsonify({"error": "no such tab"}), 404
    return jsonify({"tab": row})


@app.route("/api/repeater/tabs/<int:tab_id>/history", methods=["GET", "POST"])
def repeater_tab_history(tab_id: int):
    """Per-tab send history — the A/B record of what you sent and got back."""
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        rid = db.add_repeater_history(
            tab_id,
            method=str(data.get("method") or "GET").upper(),
            url=str(data.get("url") or ""),
            headers=data.get("headers") or {},
            body=str(data.get("body") or ""),
            status_code=data.get("status_code"),
            response_headers=data.get("response_headers") or {},
            response_body=str(data.get("response_body") or ""),
            error=str(data.get("error") or "") or None,
        )
        if rid is None:
            return jsonify({"error": "no such tab"}), 404
        return jsonify({"id": rid}), 201
    return jsonify({"history": db.get_repeater_history(tab_id)})


# ── Match & replace API ───────────────────────────────────────────────

@app.route("/api/rewrite", methods=["GET", "POST"])
def rewrite_rules():
    """List or add match-and-replace rules applied to traffic in flight.

    Burp's Proxy ▸ Proxy history rules: rewrite a header or parameter as the
    request passes through, so a header you need on 40 requests does not mean
    40 manual repeater round-trips.
    """
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        try:
            rule_id = db.add_rewrite_rule(
                target=str(data.get("target") or ""),
                kind=str(data.get("kind") or "header"),
                match=str(data.get("match") or ""),
                replace=str(data.get("replace") or ""),
                regex=bool(data.get("regex", False)),
                enabled=bool(data.get("enabled", True)),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"id": rule_id, "rules": db.get_rewrite_rules()}), 201
    return jsonify({"rules": db.get_rewrite_rules()})


@app.route("/api/rewrite/<int:rule_id>", methods=["PATCH", "DELETE"])
def rewrite_rule(rule_id: int):
    """Enable/disable or delete a single rewrite rule."""
    if flask_request.method == "DELETE":
        if not db.delete_rewrite_rule(rule_id):
            return jsonify({"error": "no such rule"}), 404
        return jsonify({"ok": True, "rules": db.get_rewrite_rules()})
    data = flask_request.get_json(silent=True) or {}
    ok = db.set_rewrite_rule_enabled(rule_id, bool(data.get("enabled", True)))
    if not ok:
        return jsonify({"error": "no such rule"}), 404
    return jsonify({"ok": True, "rules": db.get_rewrite_rules()})


# ── Wordlists API ─────────────────────────────────────────────────────

@app.route("/api/wordlists")
def wordlists():
    """Bundled wordlists the Intruder can load without an upload.

    Shipped in the package so a fresh install can attack immediately — no
    hunting for a .txt file first.
    """
    from miniproxy import wordlists as wl

    names = flask_request.args.get("name", "").strip()
    if names:
        entries = []
        for name in names.split(","):
            entry = wl.get_wordlist(name.strip())
            if entry is None:
                return jsonify({"error": f"no such wordlist: {name.strip()}"}), 404
            entries.append(entry)
        return jsonify({"wordlists": entries})
    return jsonify({"wordlists": wl.list_wordlists()})


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
        "proxy_host": st.get("host"),
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
    # Off by default (a lab that redirects is usually redirecting to a login
    # page — silently following hides the 302 you are trying to test).
    follow = bool(data.get("follow_redirects", False))

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # requests' own redirect following is used when asked, so the final
    # response and the redirect chain are both reported.
    chain: list[dict[str, Any]] = []
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=raw_headers,
            data=body,
            timeout=15,
            verify=False,
            allow_redirects=follow,
        )
        if follow:
            for hop in resp.history:
                chain.append({
                    "status": hop.status_code,
                    "url": hop.url,
                    "location": hop.headers.get("Location", ""),
                })
        return jsonify({
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:MAX_REPEATER_BODY],
            "final_url": resp.url,
            "followed": follow,
            "redirects": chain,
        })
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


# ── Intruder API ───────────────────────────────────────────────────────

@app.route("/api/intruder/start", methods=["POST"])
def intruder_start():
    """Start an attack, either single-list or pitchfork.

    Single-list: ``{"request_id": 5, "wordlist": ["a", "b"]}`` — one word into
    every ``§placeholder§``.

    Pitchfork: ``{"request_id": 5, "mode": "pitchfork",
    "lists": {"user": [...], "pass": [...]}}`` — a different wordlist per
    position, which is what makes username×password attacks possible at all.

    Either way the attack runs in a daemon thread; poll
    ``/api/intruder/status`` for progress.
    """
    data = flask_request.get_json(silent=True) or {}
    req_id = data.get("request_id")
    if not req_id:
        return jsonify({"error": "request_id is required"}), 400

    mode = str(data.get("mode") or "single").lower()
    if mode == "pitchfork":
        lists = data.get("lists") or {}
        if not isinstance(lists, dict):
            return jsonify({"error": "lists must be an object of name → array"}), 400
        cleaned = {
            str(k): [str(w) for w in v]
            for k, v in lists.items() if isinstance(v, list) and v
        }
        if not cleaned:
            return jsonify({"error": "pitchfork needs at least one non-empty list"}), 400
    else:
        wordlist = data.get("wordlist", [])
        if not wordlist or not isinstance(wordlist, list):
            return jsonify({"error": "wordlist must be a non-empty array"}), 400
        if len(wordlist) > Intruder.MAX_WORDS:
            return jsonify({
                "error": f"wordlist too large (max {Intruder.MAX_WORDS})",
            }), 400
        cleaned = wordlist  # type: ignore[assignment]

    base = db.get_request(int(req_id))
    if base is None:
        return jsonify({"error": "base request not found"}), 404

    total = (len(wordlist) if mode != "pitchfork"
             else _combo_total(cleaned))  # type: ignore[arg-type]

    global _intruder_job
    with _intruder_lock:
        if _intruder_job and _intruder_job.get("running"):
            return jsonify({
                "error": "an attack is already running",
                "job": {k: _intruder_job[k] for k in ("request_id", "progress", "total")},
            }), 409
        if mode == "pitchfork" and total > Intruder.MAX_COMBOS:
            return jsonify({
                "error": f"pitchfork would send {total} requests "
                         f"(max {Intruder.MAX_COMBOS}) — shrink a list",
            }), 400
        _intruder_job = {
            "request_id": int(req_id), "running": True,
            "progress": 0, "total": total, "results": [], "error": None,
            "mode": mode,
        }
    if mode == "pitchfork":
        threading.Thread(
            target=_run_pitchfork_job,
            args=(int(req_id), base, cleaned),  # type: ignore[arg-type]
            daemon=True, name="miniproxy-pitchfork",
        ).start()
    else:
        threading.Thread(
            target=_run_intruder_job, args=(int(req_id), base, list(cleaned)),
            daemon=True, name="miniproxy-intruder",
        ).start()
    return jsonify({"started": True, "total": total, "mode": mode}), 202


def _combo_total(lists: dict[str, list[str]]) -> int:
    total = 1
    for words in lists.values():
        total *= max(len(words), 1)
    return total


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
        # Always present so a client can render "pitchfork" without having to
        # distinguish "absent" from "single".
        "mode": job.get("mode", "single"),
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
                           url_substr=f["url"], ids=f["ids"],
                           host=f["host"], exclude_host=f["exclude_host"],
                           hide_static=f["hide_static"],
                           highlighted_only=f["highlighted_only"],
                           body_substr=f["body_substr"],
                           exclude_body=f["exclude_body"],
                           min_length=f["min_length"])
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
                           url_substr=f["url"], ids=f["ids"],
                           host=f["host"], exclude_host=f["exclude_host"],
                           hide_static=f["hide_static"],
                           highlighted_only=f["highlighted_only"],
                           body_substr=f["body_substr"],
                           exclude_body=f["exclude_body"],
                           min_length=f["min_length"])
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
        "ids": args.get("id", "").strip(),
        "host": args.get("host", "").strip(),
        "exclude_host": args.get("exclude_host", "").strip(),
        "hide_static": _truthy(args.get("hide_static")),
        "highlighted_only": _truthy(args.get("highlighted_only")),
        "body_substr": args.get("body", "").strip(),
        "exclude_body": args.get("exclude_body", "").strip(),
        "min_length": max(args.get("min_length", 0, type=int), 0),
    }


# ── Entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("MINIPROXY_DASHBOARD_PORT", 5000))
    host = os.environ.get("MINIPROXY_DASHBOARD_HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)
