"""MiniProxy Flask dashboard — serves the web UI and API endpoints for Proxy, Log, Repeater, and Intruder."""

import json
import os
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request as flask_request

from db import Database
from intruder import Intruder, IntruderError

app = Flask(__name__)
db = Database()
intruder = Intruder()


# ── CORS (allow external API access) ────────────────────────────────

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response

# Suppress SSL warnings for local repeater/intruder requests
import urllib3  # noqa: E402
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_REPEATER_BODY = 50000


# ── Routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── Proxy API ──────────────────────────────────────────────────────────

@app.route("/api/proxy/status", methods=["GET", "POST"])
def proxy_status():
    if flask_request.method == "POST":
        data = flask_request.get_json(silent=True) or {}
        enabled = data.get("enabled", True)
        db.set_intercept(enabled)
        return jsonify({"intercept_enabled": enabled})
    return jsonify({"intercept_enabled": db.get_intercept()})


# ── Log API ────────────────────────────────────────────────────────────

@app.route("/api/logs")
def get_logs():
    since = flask_request.args.get("since", 0, type=int)
    logs = db.get_logs(since_id=since)
    return jsonify(logs)


@app.route("/api/logs/<int:req_id>")
def get_log_detail(req_id):
    entry = db.get_request(req_id)
    if entry is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(entry)


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

    try:
        results = intruder.run_attack(base, wordlist, int(req_id))
        db.store_intruder_results(results)
        return jsonify({"results": results, "count": len(results)})
    except IntruderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"attack failed: {e}"}), 500


@app.route("/api/intruder/results/<int:req_id>")
def intruder_results(req_id):
    results = db.get_intruder_results(req_id)
    return jsonify(results)


# ── Entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("MINIPROXY_PORT", 5000))
    host = os.environ.get("MINIPROXY_HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)
