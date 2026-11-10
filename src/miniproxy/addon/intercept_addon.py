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
import uuid
from pathlib import Path
from typing import Any

from mitmproxy.http import HTTPFlow

try:
    from miniproxy.addon.db import (  # packaged import
        Database,
        capture_headers,
        persist_http_request,
        persist_http_response,
        response_body_policy,
        truncate_utf8,
        update_persisted_http_request,
    )
except ImportError:  # pragma: no cover - mitmdump path-based load
    from db import (  # type: ignore
        Database,
        capture_headers,
        persist_http_request,
        persist_http_response,
        response_body_policy,
        truncate_utf8,
        update_persisted_http_request,
    )


def resolve_intercept_state_paths(
    state_dir: str | os.PathLike[str] | None = None,
    *,
    addon_dir: str | os.PathLike[str] | None = None,
) -> tuple[Path, Path]:
    """Resolve queue paths for one capture session.

    New packaged launches use a private directory keyed by the capture DB.
    ``MINIPROXY_INTERCEPT_STATE_DIR`` is the public hand-off for a launcher
    and consumer that need to agree on another location.

    A standalone deployed addon keeps the historical sibling paths *only when
    the launcher already created those files* (the frozen Riciplay contract).
    This makes upgrades compatible without silently sending new package users
    back to writable runtime files inside site-packages.
    """
    if state_dir is None:
        state_dir = os.environ.get("MINIPROXY_INTERCEPT_STATE_DIR")
    source_dir = (Path(addon_dir).expanduser().resolve()
                  if addon_dir is not None else Path(__file__).resolve().parent)
    if state_dir is not None and str(state_dir).strip():
        root = Path(state_dir).expanduser().resolve()
    elif not (source_dir / "__init__.py").exists() and (
        (source_dir / "intercept_queue.json").exists()
        or (source_dir / "intercept_decisions.json").exists()
        or os.environ.get("MINIPROXY_INTERCEPT_LEGACY_FILES") == "1"
    ):
        # Compatibility mode for path-deployed addons. Riciplay creates both
        # files before mitmdump starts and imports _push_decision from this
        # same deployed module.
        root = source_dir
    else:
        db_path = Path(
            os.environ.get("MINIPROXY_DB_PATH")
            or (Path.home() / ".miniproxy" / "proxy.db")
        ).expanduser().resolve()
        root = db_path.with_name(db_path.name + ".intercept")
    return root / "intercept_queue.json", root / "intercept_decisions.json"


STATE_FILE, DECISION_FILE = resolve_intercept_state_paths()

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


def _write_all(fd: int, data: bytes) -> None:
    """Write all bytes to a locked fd (``os.write`` may be short)."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write to intercept state")
        view = view[written:]


def _rewrite_fd_json(fd: int, document: Any) -> None:
    payload = json.dumps(document, separators=(",", ":")).encode("utf-8")
    if len(payload) >= FILE_READ_CAP:
        raise OSError("intercept state exceeds the maximum safe file size")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    _write_all(fd, payload)
    try:
        os.fsync(fd)
    except OSError:
        pass


def _open_private(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Only the dedicated state directory is ours to tighten. The legacy
    # sibling parent also contains deployed source and may be shared with a
    # launcher's other data, so restrict the files themselves there.
    if path.parent != Path(__file__).resolve().parent:
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        pass
    return fd


def _initialize_json(path: Path, document: Any) -> None:
    fd = _open_private(path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        current = _read_fd_json(fd)
        if current == {}:
            _rewrite_fd_json(fd, document)
        # A corrupt existing file is deliberately retained rather than reset:
        # resetting a queue silently discards other paused requests.
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _consume_decision(
    flow_id: str, decision_file: str | os.PathLike[str] | None = None,
) -> dict[str, Any] | None:
    """Atomically pop the decision for *flow_id* from the decision file.

    Takes an exclusive flock before the read-modify-write so a decision can
    never be consumed twice or be interleaved with a concurrent write (the
    proxy_manager side shares this helper through the vendored bundle).
    Corrupt or oversized files are left untouched and reported as unavailable;
    silently resetting them could discard another paused flow's decision.
    """
    fd = None
    try:
        fd = _open_private(Path(decision_file) if decision_file else DECISION_FILE)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        decisions = _read_fd_json(fd)
        if not isinstance(decisions, dict):
            return None
        pending = decisions.get("decisions")
        if not isinstance(pending, dict):
            return None
        popped = pending.pop(flow_id, None)
        if popped is not None:
            _rewrite_fd_json(fd, decisions)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return popped if isinstance(popped, dict) else None
    except OSError:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _push_decision(
    flow_id: str,
    decision: dict[str, Any],
    decision_file: str | os.PathLike[str] | None = None,
) -> bool:
    """Atomically add a decision to the decision file (locked read-modify-write).

    The manager side of the intercept hand-off imports this helper so both
    ends use identical locking; a plain write_text() here previously raced
    the addon's poll loop and could drop concurrent decisions.
    """
    fd = None
    try:
        fd = _open_private(Path(decision_file) if decision_file else DECISION_FILE)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        decisions = _read_fd_json(fd)
        if decisions == {}:
            decisions = {"decisions": {}}
        if not isinstance(decisions, dict):
            return False
        pending = decisions.setdefault("decisions", {})
        if not isinstance(pending, dict):
            return False
        pending[str(flow_id)] = decision
        _rewrite_fd_json(fd, decisions)
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
    body = str(request_data.get("body") or "")
    stored, original_len, truncated = truncate_utf8(body, QUEUE_BODY_CAP)
    request_data["body"] = stored
    request_data["body_len"] = original_len
    if truncated:
        request_data["body_truncated"] = True
    return request_data


def _retire_pending(
    flow_id: str, state_file: str | os.PathLike[str] | None = None,
) -> bool:
    """Atomically remove all queue entries for a flow id.

    Public-at-module-scope for legacy consumers that import addon helpers.
    Existing two-argument decision helper signatures remain unchanged.
    """
    fd = None
    removed = False
    try:
        fd = _open_private(Path(state_file) if state_file else STATE_FILE)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        queue = _read_fd_json(fd)
        if not isinstance(queue, dict):
            return False
        pending = queue.get("pending", [])
        if not isinstance(pending, list):
            return False
        kept = []
        for item in pending:
            if isinstance(item, dict) and item.get("id") == flow_id:
                removed = True
            else:
                kept.append(item)
        if removed:
            queue["pending"] = kept
            _rewrite_fd_json(fd, queue)
        return removed
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass


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
        from miniproxy.scope import load_scope, load_policy
        self.scope, self.scope_mode = load_scope()
        self.allowed_scope = load_policy("MINIPROXY_RULES_SCOPE")
        self.excluded_scope = load_policy("MINIPROXY_EXCLUDE_SCOPE")
        self.state_file, self.decision_file = resolve_intercept_state_paths()
        self._init_queue()
        self._init_decisions()
        # Read the SAME key that set_intercept() writes ('intercept').
        # This used to read an 'intercept_enabled' key that nothing in the
        # codebase ever wrote, so the toggle was a no-op and intercept was
        # permanently on regardless of the stored preference.
        #
        # Default '1' matters: a fresh DB has no row at all, and
        # db.get_intercept() reports False in that case. Defaulting here
        # keeps intercept enabled on a fresh session, which is the
        # long-standing behaviour and what every existing install relies on.
        self._intercept_enabled = self.db.get_config("intercept", "1") == "1"
        self._rules: list[dict[str, str]] = self._load_rules()
        self._lock = threading.Lock()

    def _init_queue(self) -> None:
        _initialize_json(
            getattr(self, "state_file", STATE_FILE),
            {"pending": [], "mode": "intercept"},
        )

    def _init_decisions(self) -> None:
        _initialize_json(
            getattr(self, "decision_file", DECISION_FILE),
            {"decisions": {}},
        )

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
        if not self._intercept_enabled:
            return False
        if not self._rules:
            return True

        return any(self._match_rule(flow, r) for r in self._rules)

    def _add_pending(self, flow_id: str, request_data: dict[str, Any]) -> bool:
        """Append a pending request to the state file with file locking."""
        request_data = _cap_request_body(request_data)

        with self._lock:
            fd = None
            try:
                state_file = getattr(self, "state_file", STATE_FILE)
                fd = _open_private(state_file)
                fcntl.flock(fd, fcntl.LOCK_EX)
                os.lseek(fd, 0, os.SEEK_SET)
                queue = _read_fd_json(fd)
                if queue == {}:
                    queue = {"pending": [], "mode": "intercept"}
                if not isinstance(queue, dict):
                    return False

                pending = queue.setdefault("pending", [])
                if not isinstance(pending, list):
                    return False
                # UUIDs are unique, but replacing any stale duplicate makes
                # retirement deterministic even for a legacy caller-supplied
                # id or a hand-edited queue.
                pending[:] = [
                    item for item in pending
                    if not isinstance(item, dict) or item.get("id") != flow_id
                ]
                pending.append({
                    "id": flow_id,
                    "timestamp": time.time(),
                    "request": request_data,
                })
                _rewrite_fd_json(fd, queue)
                return True
            except OSError:
                # Never fall back to an unlocked rewrite: doing so can discard
                # every other paused flow. The request remains captured and is
                # forwarded after the bounded decision wait.
                return False
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
            decision = _consume_decision(
                flow_id, getattr(self, "decision_file", DECISION_FILE)
            )
            if decision is not None:
                return decision
            await asyncio.sleep(0.1)
        return None

    async def request(self, flow: HTTPFlow) -> None:
        """Intercept request: pause, queue, and wait for decision (async)."""
        from miniproxy.scope import request_in_scope
        def allowed(url):
            return request_in_scope(url, getattr(self, "scope", None),
                                    getattr(self, "allowed_scope", None), getattr(self, "excluded_scope", None))
        if not allowed(flow.request.pretty_url):
            if getattr(self, "scope_mode", "skip") == "block":
                from mitmproxy.http import Response
                flow.response = Response.make(403, b"Out of scope")
            return
        req = flow.request
        # Match capture mode's noise gate. Disabling manual pause must still
        # leave capture on, but an explicitly enabled noise rule means this
        # request is proxied without persistence in either addon.
        if self.db.is_noise(req.pretty_url) is True:
            return
        flow_id = uuid.uuid4().hex

        headers, raw_headers = capture_headers(req.headers)
        try:
            request_body = req.text or ""
        except (ValueError, UnicodeError):
            request_body = ""

        request_data = {
            "method": req.method,
            "url": req.pretty_url,
            "headers": headers,
            "headers_raw": raw_headers,
            "body": request_body,
            "host": req.host,
            "path": req.path,
        }

        if not self._should_intercept(flow):
            # Not matched by rules — log and pass through
            req_id = persist_http_request(self.db, req)
            flow._miniproxy_id = req_id
            flow._miniproxy_t0 = time.monotonic()
            return

        # Log the original request
        req_id = persist_http_request(
            self.db, req, intercept_action="pending"
        )
        flow._miniproxy_id = req_id
        flow._miniproxy_t0 = time.monotonic()
        flow._miniproxy_intercept_id = flow_id

        # Pause the flow — this is the correct mitmproxy API for intercepting.
        # Without this, the request is forwarded immediately and time.sleep()
        # only blocks the addon event loop without actually holding the request.
        flow.intercept()

        # Queue for interception
        queued = self._add_pending(flow_id, request_data)
        if queued is False:
            update_persisted_http_request(
                self.db, req_id, flow.request,
                intercept_action="queue_unavailable_forwarded",
            )
            flow.resume()
            return

        # Wait for decision (async — does NOT block other flows)
        try:
            decision = await self._wait_for_decision(flow_id)

            if decision is None:
                # Timeout policy is forward-as-is for compatibility, but the
                # durable row now says that explicitly rather than looking like
                # an untouched pending request.
                update_persisted_http_request(
                    self.db, req_id, flow.request,
                    intercept_action="timed_out_forwarded",
                )
                flow.resume()
                return

            action = str(decision.get("action") or "forward").lower()

            if action == "drop":
                self.db.mark_request_outcome(
                    req_id, "dropped", intercept_action="dropped",
                    error="intercept_dropped",
                )
                flow.kill()
                return
            if action == "modify":
                modified = decision.get("modified_request", {})
                if not isinstance(modified, dict):
                    self.db.mark_request_outcome(
                        req_id, "dropped", intercept_action="invalid_modify",
                        error="invalid_modified_request",
                    )
                    flow.kill()
                    return
                if modified.get("url") and not allowed(str(modified["url"])):
                    self.db.mark_request_outcome(
                        req_id, "dropped", intercept_action="scope_blocked",
                        error="modified_request_out_of_scope",
                    )
                    flow.kill()
                    return
                if modified.get("method"):
                    flow.request.method = str(modified["method"])
                if modified.get("url"):
                    flow.request.url = str(modified["url"])
                if "headers" in modified:
                    changed_headers = modified.get("headers")
                    if not isinstance(changed_headers, dict):
                        self.db.mark_request_outcome(
                            req_id, "dropped", intercept_action="invalid_modify",
                            error="invalid_modified_headers",
                        )
                        flow.kill()
                        return
                    flow.request.headers.clear()
                    for key, value in changed_headers.items():
                        flow.request.headers[str(key)] = str(value)
                if "body" in modified:
                    flow.request.text = str(modified.get("body") or "")
                # URL + Host can independently affect the effective authority;
                # validate the final object, not only the decision payload.
                route_in_scope = (
                    not modified.get("url") or allowed(flow.request.url)
                )
                if not route_in_scope or not allowed(flow.request.pretty_url):
                    self.db.mark_request_outcome(
                        req_id, "dropped", intercept_action="scope_blocked",
                        error="modified_request_out_of_scope",
                    )
                    flow.kill()
                    return
                update_persisted_http_request(
                    self.db, req_id, flow.request, intercept_action="modified",
                )
                flow.resume()
                return

            update_persisted_http_request(
                self.db, req_id, flow.request, intercept_action="forwarded",
            )
            flow.resume()
        except Exception as exc:
            try:
                self.db.mark_request_outcome(
                    req_id,
                    "error",
                    intercept_action="intercept_error",
                    error=f"intercept_error: {exc}",
                )
            except Exception:
                pass
            try:
                flow.kill()
            except Exception:
                pass
        finally:
            _retire_pending(
                flow_id, getattr(self, "state_file", STATE_FILE)
            )

    def responseheaders(self, flow: HTTPFlow) -> None:
        resp = flow.response
        if resp is None or getattr(flow, "_miniproxy_id", None) is None:
            return
        t0 = getattr(flow, "_miniproxy_t0", None)
        if t0 is not None:
            flow._miniproxy_ttfb = (time.monotonic() - t0) * 1000.0
        content_type = resp.headers.get("content-type", "")
        if not response_body_policy(content_type)[0]:
            flow.response.stream = True

    def response(self, flow: HTTPFlow) -> None:
        """Log the response."""
        req_id = getattr(flow, '_miniproxy_id', None)
        if req_id is None:
            return

        resp = flow.response
        try:
            if resp is None:
                self.db.update_response_error(req_id, "response_missing")
            else:
                t0 = getattr(flow, "_miniproxy_t0", None)
                total = ((time.monotonic() - t0) * 1000.0
                         if t0 is not None else None)
                persist_http_response(
                    self.db,
                    req_id,
                    resp,
                    ttfb_ms=getattr(flow, "_miniproxy_ttfb", None),
                    total_ms=total,
                )
        except Exception:
            try:
                self.db.update_response_error(req_id, "response_persist_failed")
            except Exception:
                pass
        finally:
            if hasattr(flow, '_miniproxy_id'):
                del flow._miniproxy_id

    def error(self, flow: HTTPFlow) -> None:
        """Persist transport failures and retire any stale pending entry."""
        req_id = getattr(flow, "_miniproxy_id", None)
        flow_id = getattr(flow, "_miniproxy_intercept_id", None)
        if flow_id:
            _retire_pending(flow_id, getattr(self, "state_file", STATE_FILE))
        if req_id is None:
            return
        try:
            raw_error = getattr(flow, "error", None) or "flow_error"
            self.db.update_response_error(req_id, str(raw_error)[:200])
        except Exception:
            pass


addons = [InterceptAddon()]
