"""MiniProxy mitmproxy addon — intercepts HTTP(S) traffic and logs to SQLite.

Static assets (JS, CSS, images, fonts, media) are streamed through the proxy
without buffering or body capture. Only API responses (JSON, HTML, XML, text)
have their full bodies captured. This eliminates the per-flow decode+commit
tax for multi-MB JS bundles on heavy React SPAs.

Bundle v4 additions:

* **Timing capture** — every flow records ttfb_ms (request sent → response
  headers) and total_ms (request sent → body complete). Oracles and timing
  side-channels are core bug-bounty material; the numbers also surface
  regressed endpoints on replay.
* **Scope guard** — when MINIPROXY_SCOPE is set (JSON list of hosts, with
  ``*.domain`` wildcards), requests to hosts outside that list are either
  skipped (passed through, NOT captured — default) or blocked outright
  (403 with an explanatory body) per MINIPROXY_SCOPE_MODE. Capture-side
  scope enforcement means the DB only ever holds in-scope traffic and a
  misconfigured browser cannot leak out-of-scope browsing into the session.
"""

import json
import os
import time

from mitmproxy.http import HTTPFlow

try:
    from miniproxy.addon.db import Database  # packaged import
except ImportError:  # pragma: no cover - mitmdump path-based load
    from db import Database

_API_CONTENT_TYPES: set[str] = {
    "application/json",
    "text/html",
    "text/xml",
    "application/xml",
    "text/plain",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
}


def _is_api_content(content_type: str) -> bool:
    ct = (content_type or "").lower().split(";")[0].strip()
    return ct in _API_CONTENT_TYPES


def host_in_scope(host: str, scope_entries: list[str]) -> bool:
    """Wildcard-aware host match for scope enforcement.

    An entry matches when it equals the host, ends the host (``*.domain``
    or bare ``domain`` covering subdomains — bug-bounty scope files use
    both notations interchangeably), or the entry itself is a ``*.``
    wildcard. Empty scope lists match everything (guard disabled).
    """
    if not scope_entries:
        return True
    host = (host or "").lower().strip()
    if not host:
        return False
    # Strip an explicit port for matching purposes.
    if ":" in host:
        host = host.split(":", 1)[0]
    for raw in scope_entries:
        entry = str(raw or "").lower().strip()
        if not entry:
            continue
        if entry.startswith("*."):
            entry = entry[2:]
        if entry.startswith("."):
            entry = entry[1:]
        if not entry:
            continue
        if host == entry or host.endswith("." + entry):
            return True
    return False


def _load_scope() -> tuple[list[str], str]:
    """Read the scope config injected via environment by proxy_manager."""
    raw = os.environ.get("MINIPROXY_SCOPE", "")
    try:
        entries = json.loads(raw) if raw else []
        if not isinstance(entries, list):
            entries = []
    except ValueError:
        entries = []
    entries = [str(e).strip() for e in entries if str(e).strip()]
    mode = os.environ.get("MINIPROXY_SCOPE_MODE", "skip").strip().lower()
    if mode not in ("skip", "block"):
        mode = "skip"
    return entries, mode


_BLOCK_BODY = (
    '{"error": "out_of_scope", '
    '"message": "MiniProxy scope guard: this host is outside the '
    'configured program scope and was blocked."}'
)


class MiniProxyAddon:
    def __init__(self) -> None:
        self.db = Database()
        self.scope, self.scope_mode = _load_scope()
        self._skipped = 0
        self._blocked = 0

    def request(self, flow: HTTPFlow) -> None:
        # Scope guard first: out-of-scope traffic must never reach the DB.
        # (getattr: tests and older embeddings construct the addon without
        # __init__; absent scope = guard disabled = capture everything.)
        scope = getattr(self, "scope", None)
        scope_mode = getattr(self, "scope_mode", "skip")
        if scope and not host_in_scope(flow.request.pretty_host, scope):
            if scope_mode == "block":
                self._blocked = getattr(self, "_blocked", 0) + 1
                from mitmproxy import http as _mp_http

                flow.response = _mp_http.Response.make(
                    403,
                    _BLOCK_BODY,
                    {"content-type": "application/json"},
                )
            else:
                self._skipped = getattr(self, "_skipped", 0) + 1
            return

        # Capture mode ALWAYS records requests. A previous version gated this
        # on a per-DB "intercept" config flag that defaults to absent/False on
        # every fresh session DB — which silently produced proxies that routed
        # traffic but captured nothing (empty flows).
        req = flow.request
        req_id = self.db.store_request(
            method=req.method,
            url=req.pretty_url,
            headers=dict(req.headers),
            body=req.text or "",
        )
        flow._miniproxy_id = req_id
        flow._miniproxy_t0 = time.monotonic()

    def responseheaders(self, flow: HTTPFlow) -> None:
        resp = flow.response
        if resp is None:
            return
        # Time-to-first-byte: request left → response headers arrived. Kept
        # on the flow so the (later) response hook can compute totals even
        # when the body streams for a long time.
        t0 = getattr(flow, "_miniproxy_t0", None)
        if t0 is not None:
            flow._miniproxy_ttfb = (time.monotonic() - t0) * 1000.0
        ct = resp.headers.get("content-type", "")
        if not _is_api_content(ct):
            flow.response.stream = True

    def response(self, flow: HTTPFlow) -> None:
        req_id = getattr(flow, '_miniproxy_id', None)
        if req_id is None:
            return

        t0 = getattr(flow, "_miniproxy_t0", None)
        ttfb = getattr(flow, "_miniproxy_ttfb", None)
        total = (time.monotonic() - t0) * 1000.0 if t0 is not None else None

        resp = flow.response
        try:
            code = resp.status_code
            headers = dict(resp.headers)
            ct = resp.headers.get("content-type", "")

            if _is_api_content(ct):
                self.db.update_response(
                    req_id=req_id,
                    code=code,
                    headers=headers,
                    body=resp.text or "",
                    content_type=ct,
                    ttfb_ms=ttfb,
                    total_ms=total,
                )
            else:
                self.db.update_response_light(
                    req_id=req_id,
                    code=code,
                    headers=headers,
                    content_type=ct,
                    ttfb_ms=ttfb,
                    total_ms=total,
                )
        except Exception:
            # One unreadable response (binary decode, streaming edge case)
            # must not leave the row permanently response-less.
            try:
                self.db.update_response_error(req_id, "response_persist_failed")
            except Exception:
                pass
        finally:
            try:
                del flow._miniproxy_id
            except AttributeError:
                pass

    def error(self, flow: HTTPFlow) -> None:
        """Persist transport failures (client disconnects, TLS errors) so the
        row reports an explicit error instead of a null response code."""
        req_id = getattr(flow, '_miniproxy_id', None)
        if req_id is None:
            return
        try:
            raw_error = getattr(flow, "error", None) or "flow_error"
            self.db.update_response_error(req_id, str(raw_error)[:200])
        except Exception:
            pass

    def done(self) -> None:
        """Log scope-guard counters when the proxy shuts down."""
        scope = getattr(self, "scope", None)
        skipped = getattr(self, "_skipped", 0)
        blocked = getattr(self, "_blocked", 0)
        if scope and (skipped or blocked):
            from mitmproxy import ctx

            ctx.log.info(
                "MiniProxy scope guard: %d out-of-scope request(s) skipped, "
                "%d blocked.",
                skipped,
                blocked,
            )


addons = [MiniProxyAddon()]
