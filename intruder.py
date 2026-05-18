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
    def replace_placeholders(text: str, payload: str) -> str:
        """Replace every §...§ in text with the given payload."""
        return re.sub(r"§[^§]+§", payload, text)

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

    def _apply_payload(
        self, base: dict[str, Any], payload: str
    ) -> dict[str, Any]:
        """Create a copy of the base request with all §placeholders§ replaced."""
        url = self.replace_placeholders(base.get("url", ""), payload)
        body = self.replace_placeholders(base.get("body", ""), payload)
        raw_headers = base.get("headers", {})
        if isinstance(raw_headers, str):
            raw_headers = json.loads(raw_headers)
        new_headers = {}
        for k, v in dict(raw_headers).items():
            new_headers[self.replace_placeholders(k, payload)] = (
                self.replace_placeholders(v, payload)
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
