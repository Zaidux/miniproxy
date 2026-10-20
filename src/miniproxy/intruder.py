"""Intruder — fuzzing engine that replaces §placeholders§ with wordlist entries and sends requests."""

import json
import re
from typing import Any

import requests


# `§` is the documented marker, but it is painful to type on a phone keyboard
# and cannot be typed into a browser address bar at all. `{{name}}` is accepted
# as an alias and normalised before anything looks for markers, so both forms
# behave identically everywhere (dashboard, API, stored captures).
_ALIAS_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


def normalize_markers(text: str) -> str:
    """Rewrite ``{{name}}`` aliases as ``§name§``."""
    return _ALIAS_RE.sub(lambda m: "§" + m.group(1) + "§", str(text or ""))


def normalize_multipart_body(body: str, content_type: str = "") -> str:
    """Restore CRLF line endings for a ``multipart/*`` body.

    Multipart parts are delimited by ``CRLF--boundary``, and RFC 7578 requires
    CRLF even when a client sends embedded text. An HTML ``<textarea>``
    normalises CRLF to LF, so a captured upload loaded into the Repeater (or
    substituted into by the Intruder) arrives LF-only and the server cannot
    find the closing boundary — it reports the *last* field as missing.

    Done server-side rather than only in the browser because the API is a
    supported way to replay a request, and a client-side fix leaves anything
    that does not go through the modal still broken.
    """
    text = str(body or "")
    if "multipart/" not in str(content_type or "").lower():
        return text
    # Collapse then re-expand, so an already-correct body is unchanged.
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


class IntruderError(Exception):
    """Raised when the intruder encounters a fatal error."""


class Intruder:
    """Replaces §...§ placeholders in a request with words from a wordlist and logs every response."""

    MAX_WORDS = 1000
    MAX_RESPONSE_BODY = 100_000

    def __init__(self) -> None:
        self._session = requests.Session()
        # Suppress SSL warnings — this is for local lab use only
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def find_placeholders(text: str) -> list[str]:
        """Return list of unique placeholder names found in text (content between §)."""
        matches: set[str] = set()
        for m in re.finditer(r"§([^§]+)§", normalize_markers(text)):
            matches.add(m.group(1))
        return sorted(matches)

    @staticmethod
    def positions_of(text: str) -> dict[str, int]:
        """How many times each placeholder name occurs."""
        counts: dict[str, int] = {}
        for m in re.finditer(r"§([^§]+)§", normalize_markers(text)):
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
        return counts

    @staticmethod
    def replace_placeholders(text: str, payload: str,
                            payloads: dict[str, str] | None = None) -> str:
        """Substitute payloads into ``§placeholder§`` markers.

        With ``payloads`` (name → value) each named position gets its own
        value, which is what makes pitchfork attacks possible: usernames from
        one list, passwords from another. Without it, every position receives
        the single ``payload`` — the original behaviour, kept for the
        single-list case.
        """
        # Strip CR/LF from payloads so a wordlist entry can never break
        # the request out of its header / URL / body boundaries (HTTP request
        # smuggling primitives live exactly in this mistake).
        #
        # Backslashes are NOT escaped. The replacement is a *function*, and
        # re.sub returns a function's value verbatim — so a literal "\g<0>" in
        # a wordlist is sent as those characters instead of being silently
        # swallowed as a group reference. (The previous string-replacement form
        # had to escape them; doing so now would double-escape every backslash
        # and corrupt ordinary payloads like "DOMAIN\user".)
        def clean(value: str) -> str:
            return str(value).replace("\r", "").replace("\n", "")

        shared = clean(payload)
        by_name = {k: clean(v) for k, v in (payloads or {}).items()}

        def _sub(match: "re.Match[str]") -> str:
            name = match.group(1)
            return by_name.get(name, shared)

        return re.sub(r"§([^§]+)§", _sub, normalize_markers(text))

    def run_attack(
        self,
        base_request: dict[str, Any],
        wordlist: list[str],
        target_id: int,
    ) -> list[dict[str, Any]]:
        """Iterate wordlist, fuzz the base request, send, and return results.

        Parameters
        ----------
        base_request : dict
            Must have keys: method, url, headers, body.
        wordlist : list[str]
            Words to substitute into §placeholders§.
        target_id : int
            The request id these results belong to (for DB storage).

        Returns
        -------
        list[dict]
            Each entry contains payload, response_code, response_body,
            response_headers, method, url, headers, body.
        """
        if len(wordlist) > self.MAX_WORDS:
            raise IntruderError(f"Wordlist too large (max {self.MAX_WORDS} words)")
        return self.run_items(base_request, self.build_items_single(wordlist),
                              target_id)

    # ── Work items ────────────────────────────────────────────────────
    # An attack is a flat list of items, each describing one request. The
    # dashboard persists that list with the job, so a run can be stopped after
    # any item and continued from exactly there — by the browser reattaching,
    # or by the dashboard after a restart.

    def build_items_single(self, wordlist: list[str]) -> list[dict[str, Any]]:
        return [{"word": w, "payloads": None, "label": w} for w in wordlist]

    def build_items_pitchfork(
        self, lists: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        from itertools import product

        usable = {k: v for k, v in lists.items() if v}
        if not usable:
            raise IntruderError("pitchfork needs at least one wordlist")
        combos = 1
        for size in (len(v) for v in usable.values()):
            combos *= size
        if combos > self.MAX_COMBOS:
            raise IntruderError(
                f"pitchfork would send {combos} requests "
                f"(max {self.MAX_COMBOS}) — shrink a list"
            )
        names = list(usable)
        items = []
        for combo in product(*(usable[n] for n in names)):
            payloads = dict(zip(names, combo))
            items.append({
                "word": "",
                "payloads": payloads,
                "label": " | ".join(f"{n}={v}" for n, v in payloads.items()),
            })
        return items

    def run_items(self, base_request: dict[str, Any],
                  items: list[dict[str, Any]],
                  target_id: int) -> list[dict[str, Any]]:
        """Send one request per item. Never raises for a single bad item."""
        results: list[dict[str, Any]] = []
        for item in items:
            modified = self._apply_payload(
                base_request, item.get("word") or "", item.get("payloads"))
            outcome = self._send(modified)
            outcome["payload"] = item.get("label") or item.get("word") or ""
            if item.get("payloads"):
                outcome["payloads"] = item["payloads"]
            outcome["request_id"] = target_id
            results.append(outcome)
        return results

    MAX_COMBOS = 10_000

    def run_pitchfork(self, base_request: dict[str, Any],
                      lists: dict[str, list[str]],
                      target_id: int) -> list[dict[str, Any]]:
        """Fuzz several positions with *different* wordlists at once.

        This is what most authentication labs need: ``§user§`` from one list
        crossed with ``§pass§`` from another. The old engine substituted one
        word into every position, so a username×password attack was impossible
        — you could only confirm that "admin" paired with "admin" works.

        ``lists`` maps a placeholder name to its wordlist. A position with no
        entry is substituted with an **empty string**, not left as literal
        text — this docstring used to claim the opposite, which is how the
        behaviour stayed wrong for so long. Configure every marker you care
        about: a pitchfork of ``?user=§user§&pass=§pass§`` with only ``user``
        configured sends ``?user=admin&pass=``.
        """
        return self.run_items(base_request,
                              self.build_items_pitchfork(lists), target_id)

    def _apply_payload(
        self, base: dict[str, Any], payload: str,
        payloads: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Create a copy of the base request with the §placeholders§ replaced."""
        url = self.replace_placeholders(base.get("url", ""), payload, payloads)
        body = self.replace_placeholders(base.get("body", ""), payload, payloads)
        raw_headers = base.get("headers", {})
        if isinstance(raw_headers, str):
            raw_headers = json.loads(raw_headers)
        new_headers = {}
        for k, v in dict(raw_headers).items():
            # A captured Content-Length describes the *captured* body; the
            # payload changes its length, so sending the old value truncates
            # the request (the server reads N bytes and stops mid-part). The
            # HTTP client recomputes it when absent.
            if str(k).strip().lower() in ("content-length", "transfer-encoding"):
                continue
            new_headers[self.replace_placeholders(k, payload, payloads)] = (
                self.replace_placeholders(v, payload, payloads)
            )
        # Multipart framing needs CRLF, and the substituted payload may have
        # changed the body length — recompute both from the headers that are
        # actually going out.
        body = normalize_multipart_body(
            body, new_headers.get("Content-Type")
            or new_headers.get("content-type") or "")
        return {
            "method": base.get("method", "GET"),
            "url": url,
            "headers": new_headers,
            "body": body,
        }

    def _send(self, modified: dict[str, Any]) -> dict[str, Any]:
        """Execute the modified request and return the response summary.

        This must never raise. One unusable wordlist entry used to abort the
        whole run and discard every response already collected: a payload with
        a non-Latin-1 character in a *header* value raises
        ``UnicodeEncodeError`` (headers are encoded latin-1; URLs and bodies
        are fine), which is not a ``requests.RequestException``. A single bad
        word now costs one row instead of the run.
        """
        try:
            resp = self._session.request(
                method=modified.get("method", "GET"),
                url=modified.get("url", ""),
                headers=modified.get("headers", {}),
                data=modified.get("body", ""),
                timeout=10,
                verify=False,
                allow_redirects=False,
            )
            return {
                "response_code": resp.status_code,
                "response_body": resp.text[:self.MAX_RESPONSE_BODY],
                "response_headers": dict(resp.headers),
                "method": modified["method"],
                "url": modified["url"],
                "headers": modified["headers"],
                "body": modified["body"],
            }
        except Exception as exc:  # noqa: BLE001 - a failed row must not end the run
            if isinstance(exc, UnicodeEncodeError):
                # Name the real cause: the payload cannot go in a header.
                detail = (
                    "payload cannot be sent in a header — headers are "
                    f"Latin-1, and {exc.object!r} is not: {exc}"
                )
            else:
                detail = f"{type(exc).__name__}: {exc}"
            return {
                "response_code": 0,
                "response_body": detail,
                "response_headers": {},
                "method": modified["method"],
                "url": modified["url"],
                "headers": modified["headers"],
                "body": modified["body"],
                "error": detail,
            }
