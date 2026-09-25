"""MiniProxy intercept-mode addon — pauses requests/responses for manual review.

Writes paused flows to a JSON state file and reads decisions from a shared
decision queue. The consumer reads/writes these files to implement the
in-flight modification workflow: start_intercept() -> view request -> modify
or forward or drop.

Lives here (not in a downstream consumer's vendored copy) so the intercept
capability ships with the addon it extends, rather than forking.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from mitmproxy.http import HTTPFlow

try:
    from miniproxy.addon.db import Database  # packaged import
except ImportError:  # pragma: no cover - mitmdump path-based load
    from db import Database


STATE_FILE = Path(__file__).resolve().parent / "intercept_queue.json"
DECISION_FILE = Path(__file__).resolve().parent / "intercept_decisions.json"

# Request bodies larger than this are truncated before entering the queue
# file. The queue is a hand-rolled JSON file read back with bounded reads:
# unbounded bodies (multi-MB uploads) previously overflowed the single
# 1MB read, produced truncated JSON, and reset the ENTIRE pending queue to
# empty — silently dropping every other paused flow. The full untruncated
# body remains available in the SQLite capture DB.
QUEUE_BODY_CAP = 40_000

# Hard ceiling for reads of the JSON hand-off files. os.read() may return
# fewer bytes than the file holds, so reads loop until EOF up to this cap;
# files at/above the cap are treated as corrupt (same recovery path as
# invalid JSON) instead of silently parsing a truncated prefix.
FILE_READ_CAP = 8 * 1024 * 1024


def _read_fd_json(fd: int) -> Any:
    """Read JSON from an open (already-locked) fd with loop-until-EOF reads.

    Returns the parsed object, ``{}`` for an empty file, or ``None`` when the
    file exceeds FILE_READ_CAP or contains invalid JSON.
    """
    chunks: list[bytes] = []
    total = 0
    while total < FILE_READ_CAP:
        chunk = os.read(fd, 1_000_000)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total >= FILE_READ_CAP:
        return None
    raw = b"".join(chunks)
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


def _consume_decision(flow_id: str) -> dict[str, Any] | None:
    """Atomically pop the decision for *flow_id* from the decision file.

    Takes an exclusive flock before the read-modify-write so a decision can
    never be consumed twice or be interleaved with a concurrent write (the
    proxy_manager side shares this helper through the vendored bundle).
    Corrupt or oversized files are reset to an empty decision map.
    """
    fd = None
    try:
        fd = os.open(str(DECISION_FILE), os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        decisions = _read_fd_json(fd)
        if not isinstance(decisions, dict):
            decisions = {"decisions": {}}
        decisions.setdefault("decisions", {})
        popped = decisions["decisions"].pop(flow_id, None)
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps(decisions).encode())
        fcntl.flock(fd, fcntl.LOCK_UN)
        return popped
    except OSError:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _push_decision(flow_id: str, decision: dict[str, Any]) -> bool:
    """Atomically add a decision to the decision file (locked read-modify-write).

    The manager side of the intercept hand-off imports this helper so both
    ends use identical locking; a plain write_text() here previously raced
    the addon's poll loop and could drop concurrent decisions.
    """
    fd = None
    try:
        fd = os.open(str(DECISION_FILE), os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        decisions = _read_fd_json(fd)
        if not isinstance(decisions, dict):
            decisions = {"decisions": {}}
        decisions.setdefault("decisions", {})[flow_id] = decision
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps(decisions).encode())
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _cap_request_body(request_data: dict[str, Any]) -> dict[str, Any]:
    """Cap a queued request's body at QUEUE_BODY_CAP (mutates + returns it).

    The queue is a hand-rolled JSON file read back with bounded reads:
    unbounded bodies (multi-MB uploads) previously overflowed the single
    1MB read, produced truncated JSON, and reset the ENTIRE pending queue
    to empty — silently dropping every other paused flow. The full
    untruncated body remains available in the SQLite capture DB.
    """
    body = request_data.get("body") or ""
    if len(body) > QUEUE_BODY_CAP:
        request_data["body"] = body[:QUEUE_BODY_CAP]
        request_data["body_truncated"] = True
    return request_data


class InterceptAddon:
    """Mitmproxy addon for interactive request/response interception.

    In intercept mode, every request is paused and written to the queue file.
    The proxy_manager reads the queue, presents it to the user, and writes a
    decision (forward/drop/modify) to the decision file.  This addon polls
    that file for the decision before releasing the flow.

    NOTE: This is inherently a manual review mode — the user must be
    present and attentive to review and decide on each intercepted request.
    """

    def __init__(self) -> None:
        self.db = Database()
        self._init_queue()
        self._init_decisions()
        self._intercept_enabled = self.db.get_config("intercept_enabled", "1") == "1"
        self._rules: list[dict[str, str]] = self._load_rules()
        self._lock = threading.Lock()

    def _init_queue(self) -> None:
        if not STATE_FILE.exists():
            STATE_FILE.write_text(json.dumps({"pending": [], "mode": "capture"}))

    def _init_decisions(self) -> None:
        if not DECISION_FILE.exists():
            DECISION_FILE.write_text(json.dumps({"decisions": {}}))

    def _load_rules(self) -> list[dict[str, str]]:
        """Load intercept rules from SQLite config."""
        rules_json = self.db.get_config("intercept_rules", "[]")
        try:
            rules = json.loads(rules_json)
            return rules if isinstance(rules, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    def _match_rule(self, flow: HTTPFlow, rule: dict[str, str]) -> bool:
        """Check whether a flow matches an intercept rule."""
        import fnmatch

        req = flow.request

        if "host" in rule and rule["host"]:
            host = req.host or ""
            if not fnmatch.fnmatch(host, rule["host"]):
                return False

        if "method" in rule and rule["method"]:
            if req.method.upper() != rule["method"].upper():
                return False

        if "path_contains" in rule and rule["path_contains"]:
            if rule["path_contains"] not in req.path:
                return False

        if "content_type_contains" in rule and rule["content_type_contains"]:
            ct = req.headers.get("content-type", "").lower()
            if rule["content_type_contains"].lower() not in ct:
                return False

        if "request_has_header" in rule and rule["request_has_header"]:
            if rule["request_has_header"] not in req.headers:
                return False

        return True

    def _should_intercept(self, flow: HTTPFlow) -> bool:
        """Determine if this flow should be intercepted."""
        if not self._rules:
            return self._intercept_enabled

        return any(self._match_rule(flow, r) for r in self._rules)

    def _add_pending(self, flow_id: str, request_data: dict[str, Any]) -> None:
        """Append a pending request to the state file with file locking."""
        request_data = _cap_request_body(request_data)

        with self._lock:
            fd = None
            try:
                fd = os.open(str(STATE_FILE), os.O_RDWR | os.O_CREAT)
                fcntl.flock(fd, fcntl.LOCK_EX)
                queue = _read_fd_json(fd)
                if not isinstance(queue, dict):
                    queue = {"pending": [], "mode": "intercept"}

                queue.setdefault("pending", []).append({
                    "id": flow_id,
                    "timestamp": time.time(),
                    "request": request_data,
                })
                os.lseek(fd, 0, os.SEEK_SET)
                os.ftruncate(fd, 0)
                os.write(fd, json.dumps(queue).encode())
            except OSError:
                # Fallback: write without locking
                try:
                    queue = {"pending": [{"id": flow_id, "timestamp": time.time(), "request": request_data}], "mode": "intercept"}
                    STATE_FILE.write_text(json.dumps(queue))
                except Exception:
                    pass
            finally:
                if fd is not None:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                        os.close(fd)
                    except Exception:
                        pass

    async def _wait_for_decision(self, flow_id: str, timeout: float = 120.0) -> dict[str, Any] | None:
        """Async poll for a decision on *flow_id*.

        Uses asyncio.sleep so mitmproxy's event loop is NOT blocked — other
        flows can proceed while this one waits for operator input. Each poll
        atomically pops the decision from the file (lock + read + delete +
        rewrite in one critical section), so two flows can never consume each
        other's decisions.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            decision = _consume_decision(flow_id)
            if decision is not None:
                return decision
            await asyncio.sleep(0.1)
        return None

    async def request(self, flow: HTTPFlow) -> None:
        """Intercept request: pause, queue, and wait for decision (async)."""
        if not self._intercept_enabled:
            return

        req = flow.request
        flow_id = f"{req.method}-{req.host}{req.path}-{time.time():.4f}"

        request_data = {
            "method": req.method,
            "url": req.pretty_url,
            "headers": dict(req.headers),
            "body": req.text or "",
            "host": req.host,
            "path": req.path,
        }

        if not self._should_intercept(flow):
            # Not matched by rules — log and pass through
            req_id = self.db.store_request(
                method=req.method,
                url=req.pretty_url,
                headers=dict(req.headers),
                body=req.text or "",
            )
            flow._miniproxy_id = req_id
            return

        # Log the original request
        req_id = self.db.store_request(
            method=req.method,
            url=req.pretty_url,
            headers=dict(req.headers),
            body=req.text or "",
        )
        flow._miniproxy_id = req_id

        # Pause the flow — this is the correct mitmproxy API for intercepting.
        # Without this, the request is forwarded immediately and time.sleep()
        # only blocks the addon event loop without actually holding the request.
        flow.intercept()

        # Queue for interception
        self._add_pending(flow_id, request_data)

        # Wait for decision (async — does NOT block other flows)
        decision = await self._wait_for_decision(flow_id)

        if decision is None:
            # Timeout — forward as-is
            flow.resume()
            return

        action = decision.get("action", "forward")

        if action == "drop":
            flow.kill()
        elif action == "modify":
            modified = decision.get("modified_request", {})
            if modified.get("method"):
                flow.request.method = modified["method"]
            if modified.get("url"):
                flow.request.url = modified["url"]
            if modified.get("headers"):
                flow.request.headers.clear()
                for k, v in modified["headers"].items():
                    flow.request.headers[k] = v
            if "body" in modified:
                flow.request.text = modified["body"]
            flow.resume()
        else:
            flow.resume()

    def response(self, flow: HTTPFlow) -> None:
        """Log the response."""
        req_id = getattr(flow, '_miniproxy_id', None)
        if req_id is None:
            return

        resp = flow.response
        if resp:
            self.db.update_response(
                req_id=req_id,
                code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text or "",
                content_type=resp.headers.get("content-type", ""),
            )
        if hasattr(flow, '_miniproxy_id'):
            del flow._miniproxy_id


addons = [InterceptAddon()]
