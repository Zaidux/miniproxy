"""Unit tests for the Intruder fuzzing engine (intruder.py)."""
from __future__ import annotations

import pytest

from miniproxy.intruder import Intruder, IntruderError


class TestPlaceholders:
    def test_find_unique_sorted(self):
        text = "§b§ and §a§ and §b§ again"
        assert Intruder.find_placeholders(text) == ["a", "b"]

    def test_find_none(self):
        assert Intruder.find_placeholders("no placeholders here") == []

    def test_replace_all_positions(self):
        out = Intruder.replace_placeholders("GET §u§ HTTP/1.1\nHost: §h§", "X")
        assert out == "GET X HTTP/1.1\nHost: X"


class TestPayloadSanitization:
    def test_crlf_is_stripped(self):
        out = Intruder.replace_placeholders("id=§p§", "1\r\nX-Injected: yes")
        assert "\r" not in out and "\n" not in out
        assert out == "id=1X-Injected: yes"

    def test_bare_cr_and_lf(self):
        assert "\r" not in Intruder.replace_placeholders("q=§p§", "a\rb")
        assert "\n" not in Intruder.replace_placeholders("q=§p§", "a\nb")

    def test_backslash_group_references_are_neutralized(self):
        # re.sub replacement templates would crash (or rewrite) on these
        assert Intruder.replace_placeholders("q=§p§", r"\g<0>") == r"q=\g<0>"
        assert Intruder.replace_placeholders("q=§p§", r"\1") == r"q=\1"

    def test_literal_backslashes_pass_through(self):
        assert Intruder.replace_placeholders("q=§p§", r"a\b") == r"q=a\b"
        assert Intruder.replace_placeholders("§p§&§p§", "x\\y") == "x\\y&x\\y"


class TestAttack:
    def test_wordlist_cap(self):
        with pytest.raises(IntruderError):
            Intruder().run_attack({"method": "GET", "url": "https://x", "headers": {}, "body": ""},
                                  ["w"] * 1001, target_id=1)

    def test_apply_payload_copies_base(self):
        base = {"method": "POST", "url": "https://x.test/?id=§p§",
                "headers": {"X-Trace": "§p§"}, "body": '{"v": "§p§"}'}
        out = Intruder()._apply_payload(base, "zz")
        assert out["url"] == "https://x.test/?id=zz"
        assert out["headers"] == {"X-Trace": "zz"}
        assert out["body"] == '{"v": "zz"}'
        assert base["url"] == "https://x.test/?id=§p§"  # untouched

    def test_headers_string_is_accepted(self):
        out = Intruder()._apply_payload(
            {"method": "GET", "url": "§p§", "headers": '{"A": "§p§"}', "body": ""}, "h")
        assert out["url"] == "h" and out["headers"] == {"A": "h"}

    def test_send_error_is_captured_not_raised(self):
        out = Intruder()._send({"method": "GET", "url": "http://127.0.0.1:1/x",
                                "headers": {}, "body": ""})
        assert out["response_code"] == 0
        assert out["response_body"]  # the exception text


class TestOneBadPayloadDoesNotKillTheRun:
    """A single unusable payload must cost one row, not the whole attack.

    Headers are encoded Latin-1, so a word containing e.g. "€" raises
    UnicodeEncodeError — which is not a requests.RequestException, so it used
    to escape `_send`, abort the run, and discard every response already
    collected. The same character is harmless in the URL or body, which made it
    hard to diagnose.
    """

    def _serve(self, handler_fn):
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                handler_fn(self)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        return srv, srv.server_address[1]

    def test_non_latin1_header_payload_is_one_failed_row(self):
        def ok(h):
            h.send_response(200)
            h.send_header("Content-Length", "2")
            h.end_headers()
            h.wfile.write(b"ok")

        srv, port = self._serve(ok)
        try:
            base = {"method": "GET", "url": f"http://127.0.0.1:{port}/",
                    "headers": {"X-Test": "§v§"}, "body": ""}
            results = Intruder().run_attack(base, ["admin", "€", "test"], 1)
        finally:
            srv.shutdown()

        assert len(results) == 3, "the run aborted instead of recording all three"
        codes = [r["response_code"] for r in results]
        assert codes == [200, 0, 200], codes
        # The failure explains itself rather than showing a bare code.
        assert "Latin-1" in results[1]["response_body"], results[1]["response_body"]

    def test_non_latin1_in_url_or_body_still_succeeds(self):
        def ok(h):
            h.send_response(200)
            h.send_header("Content-Length", "2")
            h.end_headers()
            h.wfile.write(b"ok")

        srv, port = self._serve(ok)
        try:
            for where, value in (("url", "http://127.0.0.1:%d/?v=§v§" % port),
                                 ("body", "§v§")):
                base = {"method": "GET", "url": f"http://127.0.0.1:{port}/",
                        "headers": {}, "body": ""}
                base[where] = value
                out = Intruder().run_attack(base, ["€"], 1)
                assert out[0]["response_code"] == 200, (where, out[0])
        finally:
            srv.shutdown()

    def test_send_never_raises(self, monkeypatch):
        """Even an unexpected exception becomes a row, not a dead run."""
        i = Intruder()

        def boom(**kw):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(i._session, "request", boom)
        out = i._send({"method": "GET", "url": "http://x/", "headers": {},
                       "body": ""})
        assert out["response_code"] == 0
        assert "kaboom" in out["response_body"]
