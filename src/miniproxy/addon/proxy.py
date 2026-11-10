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

import re
import time

from mitmproxy.http import HTTPFlow

try:
    from miniproxy.addon.db import (  # packaged import
        Database,
        capture_headers,
        is_captured_content_type,
        persist_http_request,
        persist_http_response,
        _CAPTURED_CONTENT_TYPES,
    )
except ImportError:  # pragma: no cover - mitmdump path-based load
    from db import (  # type: ignore
        Database,
        capture_headers,
        is_captured_content_type,
        persist_http_request,
        persist_http_response,
        _CAPTURED_CONTENT_TYPES,
    )


# Historical downstream import retained; canonical classification also accepts
# structured +json/+xml suffixes and remains owned by db.py.
_API_CONTENT_TYPES = set(_CAPTURED_CONTENT_TYPES)


def _is_api_content(content_type: str) -> bool:
    """Whether this response is buffered under the canonical body policy."""
    return is_captured_content_type(content_type)


def _apply_changed_headers(request, before: dict, after: dict) -> None:
    """Apply only rule-modified fields, preserving URL-derived authority.

    Assigning the complete pre-URL header dictionary after ``request.url``
    would restore a stale Host field.  Conversely assigning the URL after a
    Host-only rewrite silently reset that rewrite.  Deltas make both kinds of
    rule explicit: URL rules update routing first; an explicit Host rule then
    updates the HTTP authority that is actually sent.
    """
    before_ci = {str(k).lower(): str(v) for k, v in before.items()}
    for name, value in after.items():
        if before_ci.get(str(name).lower()) != str(value):
            request.headers[str(name)] = str(value)


def apply_rewrite_rules(db: "Database", headers: dict, url: str,
                        body: str) -> tuple[dict, str, str, int]:
    """Apply enabled match-and-replace rules to a request in flight.

    Burp's Proxy history rules. The point is to avoid a manual repeater
    round-trip for a header you need on every request — forcing a role, pinning
    a version header, rewriting a redirect target.

    Header semantics differ by kind, which matches how people actually want to
    use them:

    * ``exact``   — matches the header **name**, and ``replace`` is its new
      value. "Always send ``X-Forwarded-For: 1``."
    * ``contains``/``regex`` — match inside the header **value**.

    Returns ``(headers, url, body, count)``. Rules are applied in id order and
    each header value is rewritten at most once per request, so two rules
    cannot fight over the same value in an order the user cannot predict.

    CR/LF in a replacement is stripped: this runs before the request leaves,
    so an unescaped newline here would be request splitting.
    """
    rules = db.get_rewrite_rules(enabled_only=True)
    if not rules:
        return headers, url, body, 0
    applied = 0
    for rule in rules:
        needle = str(rule.get("match") or "")
        if not needle:
            continue
        replacement = str(rule.get("replace") or "").replace("\r", "").replace("\n", "")
        kind = rule.get("kind") or "exact"
        target = rule.get("target") or "header"
        if target == "header" and kind == "exact":
            # Match on the name and set the value — the common case.
            for name in list(headers):
                if str(name).lower() == needle.lower():
                    if headers[name] != replacement:
                        headers[name] = replacement
                        applied += 1
            continue
        if kind == "regex":
            try:
                pattern = re.compile(needle)
            except re.error:
                # Validated on insert; skip rather than fail the whole request.
                continue
            hit, sub = pattern.search, pattern.sub
        else:
            hit = sub = None  # type: ignore[assignment]

        if target == "header":
            for name in list(headers):
                value = str(headers[name])
                if kind == "regex":
                    if hit(value):
                        headers[name] = sub(replacement, value)
                        applied += 1
                elif needle in value:
                    headers[name] = value.replace(needle, replacement)
                    applied += 1
        else:
            source = url if target == "query" else body
            if kind == "regex":
                new = sub(replacement, source)
            else:
                new = source.replace(needle, replacement) if needle in source else source
            if new != source:
                if target == "query":
                    url = new
                else:
                    body = new
                applied += 1
    return headers, url, body, applied


def host_in_scope(host: str, scope_entries: list[str]) -> bool:
    """Bare domains are exact; only explicit wildcards admit subdomains."""
    from miniproxy.scope import matches_any_scope
    return not scope_entries or matches_any_scope(host, scope_entries)


def _load_scope() -> tuple[list[str], str]:
    from miniproxy.scope import load_scope
    return load_scope()


_BLOCK_BODY = (
    '{"error": "out_of_scope", '
    '"message": "MiniProxy scope guard: this host is outside the '
    'configured program scope and was blocked."}'
)


class MiniProxyAddon:
    def __init__(self) -> None:
        self.db = Database()
        self.scope, self.scope_mode = _load_scope()
        from miniproxy.scope import load_policy
        self.allowed_scope = load_policy("MINIPROXY_RULES_SCOPE")
        self.excluded_scope = load_policy("MINIPROXY_EXCLUDE_SCOPE")
        self._skipped = 0
        self._blocked = 0

    def request(self, flow: HTTPFlow) -> None:
        # Scope guard first: out-of-scope traffic must never reach the DB.
        # (getattr: tests and older embeddings construct the addon without
        # __init__; absent scope = guard disabled = capture everything.)
        scope = getattr(self, "scope", None)
        scope_mode = getattr(self, "scope_mode", "skip")
        from miniproxy.scope import request_in_scope
        allowed_scope = getattr(self, "allowed_scope", None)
        excluded_scope = getattr(self, "excluded_scope", None)
        # Before any rewrite, mitmproxy's pretty_url is the HTTP effective
        # authority (Host for HTTP/1.1). The connection route may deliberately
        # differ for virtual-host testing or a local resolver. Rewritten flows
        # are checked more strictly below because a rule can change either
        # authority independently.
        if not request_in_scope(
            flow.request.pretty_url, scope, allowed_scope, excluded_scope
        ):
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

        req = flow.request

        # Noise gate: known telemetry/ad hosts (user-enabled rules) never reach
        # the DB. Runs *after* the scope guard and *before* store_request, so a
        # dropped flow is genuinely never written — not written-then-deleted.
        # Traffic is still proxied untouched; this only stops the capture.
        if self.db.is_noise(req.pretty_url):
            self._noise = getattr(self, "_noise", 0) + 1
            return

        # Capture mode ALWAYS records requests. A previous version gated this
        # on a per-DB "intercept" config flag that defaults to absent/False on
        # every fresh session DB — which silently produced proxies that routed
        # traffic but captured nothing (empty flows).
        headers, _ = capture_headers(req.headers)
        original_headers = dict(headers)
        try:
            body = req.text or ""
        except (ValueError, UnicodeError):
            body = ""
        original_body = body
        url = req.pretty_url
        original_url = url

        # Match & replace, applied before the request goes upstream. The
        # rewritten request is what leaves the proxy — this is interception,
        # not post-hoc annotation, so the *upstream* sees the modified values.
        headers, url, body, rewritten = apply_rewrite_rules(
            self.db, headers, url, body
        )
        if rewritten:
            # URL routing changes are applied before explicit header changes.
            # In particular, an explicit Host rewrite must be last or setting
            # request.url will silently replace it with the URL authority.
            if url != original_url:
                req.url = url
            _apply_changed_headers(req, original_headers, headers)
            if body != original_body:
                try:
                    req.text = body
                except (ValueError, UnicodeError):
                    # Binary bodies cannot round-trip through .text; leaving
                    # the original content is better than breaking the request.
                    body = original_body

            # Validate both the actual connection target and the final HTTP
            # authority/Host view.  A Host-only rewrite does not change
            # request.url in mitmproxy, while a URL rewrite does; checking only
            # either representation leaves the other unvalidated.
            final_route = req.url
            final_effective_url = req.pretty_url
            # A pre-existing route/effective-host difference is legitimate
            # for local virtual-host fixtures and custom resolution. Recheck
            # the connection route only when a URL rule changed it; always
            # recheck pretty_url because that reflects an explicit Host rule.
            route_in_scope = (
                url == original_url
                or request_in_scope(
                    final_route, scope, getattr(self, "allowed_scope", None),
                    getattr(self, "excluded_scope", None),
                )
            )
            in_scope = route_in_scope and request_in_scope(
                final_effective_url, scope,
                getattr(self, "allowed_scope", None),
                getattr(self, "excluded_scope", None),
            )
            if not in_scope:
                from mitmproxy import http as _mp_http
                flow.response = _mp_http.Response.make(403, _BLOCK_BODY)
                return
            self._rewrites = getattr(self, "_rewrites", 0) + rewritten
            flow.request = req

        # Capture the final request object, not the helper's intermediate
        # dictionary. This is exactly what mitmproxy will forward.
        req_id = persist_http_request(self.db, req)
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
            if resp is None:
                raise ValueError("response_missing")
            persist_http_response(
                self.db, req_id, resp, ttfb_ms=ttfb, total_ms=total,
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
        """Log scope-guard and noise counters when the proxy shuts down."""
        from mitmproxy import ctx

        scope = getattr(self, "scope", None)
        skipped = getattr(self, "_skipped", 0)
        blocked = getattr(self, "_blocked", 0)
        if scope and (skipped or blocked):
            ctx.log.info(
                "MiniProxy scope guard: %d out-of-scope request(s) skipped, "
                "%d blocked.",
                skipped,
                blocked,
            )
        noise = getattr(self, "_noise", 0)
        if noise:
            ctx.log.info(
                "MiniProxy noise filter: %d request(s) matched an enabled "
                "noise rule and were not captured.",
                noise,
            )


addons = [MiniProxyAddon()]
