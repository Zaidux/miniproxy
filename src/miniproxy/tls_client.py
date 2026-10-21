"""Replay a request with a real browser's TLS fingerprint.

Cloudflare (and Akamai/PerimeterX) bind a clearance cookie to the client that
solved the challenge — not just its IP and User-Agent, but the TLS ClientHello
and HTTP/2 fingerprint. A plain HTTP client therefore gets re-challenged no
matter how complete its headers are, which is what made the Repeater unusable
against bot-managed targets.

``curl_cffi`` replays curl through a patched libcurl that reproduces a real
browser's handshake, so the fingerprint matches when the profile matches the
browser that obtained the clearance.

**Important limit.** The clearance is issued against one specific fingerprint.
If you solved the challenge in Firefox 154 *Android*, no shipped profile matches
it (they are desktop Chrome/Edge/Safari/Firefox versions), and this will not
help. The profile has to match the browser that got the cookie: solve it in
desktop Chrome, then impersonate ``chrome``. When it does not match, Cloudflare
answers with its challenge page — which :func:`looks_like_challenge` detects so
the dashboard can say why rather than showing a bare 403.

``curl_cffi`` is an optional dependency: without it, callers fall back to
``requests`` and the UI says the mode is unavailable.
"""
from __future__ import annotations

from typing import Any

try:  # optional: a compiled wheel, but not present on every platform
    from curl_cffi import requests as _cffi
    from curl_cffi.const import CurlHttpVersion  # noqa: F401  (import check)

    AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when absent
    _cffi = None  # type: ignore[assignment]
    AVAILABLE = False

# A curated set rather than all 54: these are the ones a tester actually has a
# browser open in, and a long list is unusable on a phone. The value is what
# curl_cffi calls the profile.
PROFILES: tuple[str, ...] = (
    "chrome",
    "chrome136",
    "chrome131_android",
    "firefox",
    "firefox147",
    "safari",
    "safari184",
    "edge",
)

# Profiles accepted by curl_cffi but not offered in the UI still work if passed
# explicitly by an API client; unknown ones are rejected before we try to use
# them, so a typo returns a clear error instead of a stack trace.
_DEFAULT = "chrome"


class TlsClientError(RuntimeError):
    """Raised when a browser-fingerprint replay cannot be performed."""


def available() -> bool:
    return AVAILABLE


def normalize_profile(name: str | None) -> str | None:
    """Return a usable profile name, or None for "no impersonation".

    Unknown names raise rather than silently falling back: a silent fallback
    would look like the feature worked while sending a fingerprint the user did
    not choose.
    """
    value = str(name or "").strip().lower()
    if not value or value in ("none", "off", "requests"):
        return None
    if not AVAILABLE:
        raise TlsClientError(
            "browser-fingerprint replay needs the optional `curl_cffi` package "
            "— install it with: pip install \"riciplay-miniproxy[tls]\""
        )
    if value not in PROFILES and value not in _known():
        raise TlsClientError(
            f"unknown TLS profile {value!r}; choose one of: "
            + ", ".join(PROFILES)
        )
    return value


def _known() -> set[str]:
    """Every profile this curl_cffi build advertises."""
    try:
        from curl_cffi.requests.impersonate import BrowserTypeLiteral
        import typing

        return set(typing.get_args(BrowserTypeLiteral))
    except Exception:  # pragma: no cover
        return set(PROFILES)


def looks_like_challenge(status: int, headers: Any, body: str) -> bool:
    """Is this response a bot-management interstitial rather than the app?

    Three independent signals, because they differ per vendor: Cloudflare marks
    the header, its page carries a fixed title, and other vendors return a bare
    403 with no content type.
    """
    if status not in (403, 429, 503):
        return False
    lowered = {str(k).lower(): str(v).lower() for k, v in dict(headers or {}).items()}
    if lowered.get("cf-mitigated") == "challenge":
        return True
    text = (body or "")[:4000].lower()
    return (
        "just a moment" in text
        or "checking your browser" in text
        or "cf-chl" in text
        or "captcha" in text
    )


def send(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str = "",
    *,
    timeout: float = 15,
    follow_redirects: bool = False,
    impersonate: str = _DEFAULT,
) -> dict[str, Any]:
    """Perform one request with a browser TLS fingerprint.

    Returns the same shape the Repeater route already speaks, plus ``challenge``
    so the caller can explain a bot-management block instead of showing a 403
    with a boolean "it failed".
    """
    if not AVAILABLE:
        raise TlsClientError(
            "browser-fingerprint replay is unavailable: `curl_cffi` is not "
            "installed"
        )
    profile = impersonate or _DEFAULT
    try:
        with _cffi.Session(impersonate=profile) as session:
            resp = session.request(
                method=method,
                url=url,
                headers=headers,
                data=body.encode() if isinstance(body, str) else body,
                timeout=timeout,
                verify=False,
                allow_redirects=follow_redirects,
            )
    except Exception as exc:  # curl_cffi raises its own error types
        raise TlsClientError(f"{type(exc).__name__}: {exc}") from exc

    text = resp.text or ""
    chain = [
        {
            "status": hop.status_code,
            "url": str(hop.url),
            "location": hop.headers.get("Location", ""),
        }
        for hop in getattr(resp, "history", []) or []
    ]
    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "body": text,
        "final_url": str(resp.url),
        "followed": bool(follow_redirects),
        "redirects": chain,
        "challenge": looks_like_challenge(resp.status_code, resp.headers, text),
        "tls_profile": profile,
    }
