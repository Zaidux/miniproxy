"""Intruder — fuzzing engine that replaces §placeholders§ with wordlist entries and sends requests."""

import json
import re
from typing import Any

import requests


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
        for m in re.finditer(r"§([^§]+)§", text):
            matches.add(m.group(1))
        return sorted(matches)

    @staticmethod
    def positions_of(text: str) -> dict[str, int]:
        """How many times each placeholder name occurs."""
        counts: dict[str, int] = {}
        for m in re.finditer(r"§([^§]+)§", text):
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

        return re.sub(r"§([^§]+)§", _sub, text)

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

        results: list[dict[str, Any]] = []
        for word in wordlist:
            modified = self._apply_payload(base_request, word)
            outcome = self._send(modified)
            outcome["payload"] = word
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
        entry keeps its literal ``§name§`` text in the request, so the result
        rows say exactly what was sent.
        """
        from itertools import product

        usable = {k: v for k, v in lists.items() if v}
        if not usable:
            raise IntruderError("pitchfork needs at least one wordlist")

        sizes = [len(v) for v in usable.values()]
        combos = 1
        for size in sizes:
            combos *= size
        if combos > self.MAX_COMBOS:
            raise IntruderError(
                f"pitchfork would send {combos} requests "
                f"(max {self.MAX_COMBOS}) — shrink a list"
            )

        names = list(usable)
        results: list[dict[str, Any]] = []
        for combo in product(*(usable[n] for n in names)):
            payloads = dict(zip(names, combo))
            modified = self._apply_payload(base_request, "", payloads)
            outcome = self._send(modified)
            # A readable label beats "a×b" — this string is what the results
            # table groups and searches by.
            outcome["payload"] = " | ".join(
                f"{n}={v}" for n, v in payloads.items()
            )
            outcome["payloads"] = payloads
            outcome["request_id"] = target_id
            results.append(outcome)
        return results

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
            new_headers[self.replace_placeholders(k, payload, payloads)] = (
                self.replace_placeholders(v, payload, payloads)
            )
        return {
            "method": base.get("method", "GET"),
            "url": url,
            "headers": new_headers,
            "body": body,
        }

    def _send(self, modified: dict[str, Any]) -> dict[str, Any]:
        """Execute the modified request and return the response summary."""
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
        except requests.RequestException as exc:
            return {
                "response_code": 0,
                "response_body": str(exc),
                "response_headers": {},
                "method": modified["method"],
                "url": modified["url"],
                "headers": modified["headers"],
                "body": modified["body"],
            }
