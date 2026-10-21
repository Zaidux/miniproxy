"""Drive a real browser to replay a request.

Fingerprint emulation (see :mod:`miniproxy.tls_client`) reproduces a browser's
handshake, but bot management does not only look at the handshake: it weighs IP
reputation, solves a JavaScript challenge, and binds the resulting clearance to
the client that solved it. When a target challenges even a genuine browser from
the same address, no amount of header or TLS spoofing helps — the request has to
be *made by* a browser that has passed.

This module runs one browser in a dedicated thread and executes requests inside
a page via ``fetch``. Everything is therefore native: TLS, HTTP/2, UA, cookie
jar, and any JS challenge state. It is the only replay mode that works across
devices, because it uses the device's own browser (or a browser you have already
signed into).

Two ways to attach:

* **Launch** a browser with a persistent profile (``profile_dir``), so a
  challenge solved once stays solved for later replays.
* **Attach** to a browser already running with remote debugging
  (``cdp_url``), including Android Chrome over USB
  (``adb forward tcp:9222 localabstract:chrome_devtools_remote``).

The sync Playwright API must own its thread, hence the worker queue: Flask
handles requests on arbitrary threads, and Playwright refuses to be used across
them.
"""
from __future__ import annotations

import atexit
import os
import queue
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # optional: the same extra that provides TLS replay
    from playwright.sync_api import sync_playwright

    PLAYWRIGHT = True
except Exception:  # pragma: no cover
    sync_playwright = None  # type: ignore[assignment]
    PLAYWRIGHT = False

DEFAULT_CDP_URL = os.environ.get("MINIPROXY_BROWSER_CDP", "")
DEFAULT_PROFILE = Path(os.environ.get(
    "MINIPROXY_BROWSER_PROFILE", Path.home() / ".miniproxy" / "browser-profile"))

# Headers a page's `fetch` is not allowed to set. Passing them is not merely
# ignored — the browser drops them, which would silently change the request, so
# they are stripped deliberately and the caller is told.
_FORBIDDEN = {
    "host", "content-length", "connection", "cookie", "cookie2", "origin",
    "referer", "te", "trailer", "transfer-encoding", "upgrade", "via",
    "accept-encoding", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "user-agent", "keep-alive", "proxy-authorization", "proxy-connection",
}

# Extensions Playwright's bundled build may be called.
_CANDIDATES = ("google-chrome", "google-chrome-stable", "chromium",
               "chromium-browser", "msedge", "microsoft-edge")


class BrowserError(RuntimeError):
    """Raised when the browser bridge cannot perform a request."""


_BROWSER_CACHE: dict[str, str | None] = {}


def find_browser() -> str | None:
    """Locate a Chromium-family binary.

    System browsers are checked **before** Playwright: asking Playwright for
    ``executable_path`` starts (and then stops) a driver, and doing that from
    the caller's thread left the bridge's own instance reporting "Event loop is
    closed". A path lookup should not boot a driver.

    Cached, because this runs on every availability check.
    """
    if "path" in _BROWSER_CACHE:
        return _BROWSER_CACHE["path"]

    explicit = os.environ.get("MINIPROXY_BROWSER_PATH", "").strip()
    if explicit:
        found = explicit if os.path.exists(explicit) else None
        _BROWSER_CACHE["path"] = found
        return found
    for name in _CANDIDATES:
        found = shutil.which(name)
        if found:
            _BROWSER_CACHE["path"] = found
            return found
    if PLAYWRIGHT:
        try:
            with sync_playwright() as pw:
                path = pw.chromium.executable_path
            if path and os.path.exists(path):
                _BROWSER_CACHE["path"] = path
                return path
        except Exception:
            pass
    _BROWSER_CACHE["path"] = None
    return None


def available() -> bool:
    """Can this install drive a browser at all?"""
    if not PLAYWRIGHT:
        return False
    if DEFAULT_CDP_URL:
        return True
    return find_browser() is not None


def settable_headers(headers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Split headers into ones a page may set and ones the browser owns.

    Returning the dropped names lets the caller say what changed; silently
    dropping them would make a replay look faithful when it was not.
    """
    usable: dict[str, str] = {}
    dropped: list[str] = []
    for name, value in dict(headers or {}).items():
        if str(name).strip().lower() in _FORBIDDEN:
            dropped.append(str(name))
        else:
            usable[str(name)] = str(value)
    return usable, dropped


@dataclass
class _Job:
    method: str
    url: str
    headers: dict[str, str]
    body: str
    follow: bool
    timeout: float
    done: threading.Event = field(default_factory=threading.Event)
    result: dict[str, Any] | None = None
    error: BaseException | None = None


class BrowserBridge:
    """A single browser in a dedicated thread, fed by a queue."""

    def __init__(self) -> None:
        self._q: queue.Queue[_Job | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._page_origin = ""
        self._closed = False

    # ── lifecycle ───────────────────────────────────────────────────
    def _ensure(self) -> None:
        with self._lock:
            if self._closed:
                raise BrowserError("browser bridge is closed")
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="miniproxy-browser")
            self._thread.start()

    def close(self) -> None:
        with self._lock:
            self._closed = True
        if self._thread and self._thread.is_alive():
            self._q.put(None)
            self._thread.join(timeout=10)

    # ── worker ──────────────────────────────────────────────────────
    def _run(self) -> None:
        # The `with` must wrap the whole loop. Closing it after `_attach` stops
        # Playwright, and the first request then fails with "Event loop is
        # closed! Is Playwright already stopped?".
        try:
            with sync_playwright() as pw:
                browser, context = self._attach(pw)
                try:
                    while True:
                        job = self._q.get()
                        if job is None:
                            break
                        try:
                            job.result = self._handle(context, job)
                        except BaseException as exc:  # noqa: BLE001
                            job.error = exc
                        finally:
                            job.done.set()
                finally:
                    try:
                        browser.close()
                    except Exception:
                        pass
        except Exception as exc:  # surfaced to every waiting request
            while True:
                job = self._q.get()
                if job is None:
                    return
                job.error = BrowserError(f"could not start the browser: {exc}")
                job.done.set()

    def _attach(self, pw):  # noqa: ANN001 - Playwright types are optional
        if DEFAULT_CDP_URL:
            browser = pw.chromium.connect_over_cdp(DEFAULT_CDP_URL)
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            return browser, context
        path = find_browser()
        if not path:
            raise BrowserError(
                "no Chromium-family browser found; set MINIPROXY_BROWSER_PATH, "
                "or attach to one with MINIPROXY_BROWSER_CDP=http://127.0.0.1:9222"
            )
        DEFAULT_PROFILE.mkdir(parents=True, exist_ok=True)
        # Headed mode when a display exists (or Xvfb is used): a headless UA is
        # itself a detection signal, and some challenges refuse to render in
        # headless. MINIPROXY_BROWSER_HEADLESS=0 opts in.
        headless = os.environ.get("MINIPROXY_BROWSER_HEADLESS", "1") != "0"
        context = pw.chromium.launch_persistent_context(
            user_data_dir=str(DEFAULT_PROFILE),
            executable_path=path,
            headless=headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        if headless:
            # Playwright's headless build advertises "HeadlessChrome", which
            # bot management treats as a bot regardless of the handshake.
            ua = context.pages[0].evaluate("() => navigator.userAgent") if context.pages else ""
            if "HeadlessChrome" in ua:
                context.set_extra_http_headers({
                    "User-Agent": ua.replace("HeadlessChrome", "Chrome"),
                })
        return context.browser or context, context

    # ── request execution ───────────────────────────────────────────
    def _page_for(self, context, url: str):  # noqa: ANN001
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if self._page_origin == origin and context.pages:
            return context.pages[0]
        page = context.pages[0] if context.pages else context.new_page()
        # A page has to be on the target origin for a same-origin fetch — and
        # this navigation is what lets a JS challenge run, if one is pending.
        page.goto(origin + "/", wait_until="domcontentloaded", timeout=45000)
        self._page_origin = origin
        return page

    def _handle(self, context, job: _Job) -> dict[str, Any]:  # noqa: ANN001
        from miniproxy.tls_client import looks_like_challenge

        headers, dropped = settable_headers(job.headers)
        page = self._page_for(context, job.url)
        payload = {
            "method": job.method.upper(),
            "url": job.url,
            "headers": headers,
            "body": None if job.method.upper() in ("GET", "HEAD") else job.body,
            "follow": bool(job.follow),
        }
        raw = page.evaluate(
            """async ({method, url, headers, body, follow}) => {
                const r = await fetch(url, {
                    method, headers,
                    body: body === null ? undefined : body,
                    credentials: 'include',
                    redirect: follow ? 'follow' : 'manual',
                });
                let text = '';
                try { text = await r.text(); } catch (e) { text = ''; }
                const out = {};
                r.headers.forEach((v, k) => { out[k] = v; });
                return {status: r.status, headers: out, body: text,
                        final_url: r.url, type: r.type};
            }""",
            payload,
        )
        body = raw.get("body") or ""
        return {
            "status_code": raw.get("status", 0),
            "headers": raw.get("headers") or {},
            "body": body,
            "final_url": raw.get("final_url") or job.url,
            "followed": bool(job.follow),
            "redirects": [],
            "challenge": looks_like_challenge(
                raw.get("status", 0), raw.get("headers") or {}, body),
            "tls_profile": None,
            "browser": True,
            # A page cannot set these; say so instead of pretending.
            "dropped_headers": dropped,
        }

    # ── public API ──────────────────────────────────────────────────
    def send(self, method: str, url: str, headers: dict[str, str], body: str,
             *, follow: bool = False, timeout: float = 45) -> dict[str, Any]:
        self._ensure()
        job = _Job(method=method, url=url, headers=headers, body=body,
                   follow=follow, timeout=timeout)
        self._q.put(job)
        if not job.done.wait(timeout=timeout + 15):
            raise BrowserError("the browser did not answer in time")
        if job.error is not None:
            raise BrowserError(str(job.error))
        assert job.result is not None
        return job.result


_BRIDGE: BrowserBridge | None = None
_BRIDGE_LOCK = threading.Lock()


def bridge() -> BrowserBridge:
    global _BRIDGE
    with _BRIDGE_LOCK:
        if _BRIDGE is None:
            _BRIDGE = BrowserBridge()
            atexit.register(_BRIDGE.close)
        return _BRIDGE


def send(method: str, url: str, headers: dict[str, str], body: str = "",
         *, follow: bool = False, timeout: float = 45) -> dict[str, Any]:
    if not PLAYWRIGHT:
        raise BrowserError(
            "browser replay needs Playwright — install with: "
            "pip install \"riciplay-miniproxy[tls]\"")
    if not available():
        raise BrowserError(
            "no Chromium-family browser found. Set MINIPROXY_BROWSER_PATH to "
            "one, or attach with MINIPROXY_BROWSER_CDP=http://127.0.0.1:9222")
    return bridge().send(method, url, headers, body, follow=follow, timeout=timeout)
