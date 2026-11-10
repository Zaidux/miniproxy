"""Real loopback browser → owned MiniProxy → SQLite release contract.

No third-party URLs, persistent operator state, or Playwright browser download.
The adjacent ricibrowser dependency is selected by the certification environment.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from miniproxy import server
from miniproxy.addon.db import Database


def test_browser_generated_api_capture_and_owned_shutdown(tmp_path):
    pytest.importorskip("ricibrowser")
    from ricibrowser import Engine, EngineConfig, EngineType
    from ricibrowser.chrome_launcher import find_chrome
    if not find_chrome():
        pytest.skip("Chrome unavailable")
    from miniproxy.runtime import resolve_mitmdump
    try:
        resolve_mitmdump()
    except RuntimeError as exc:
        pytest.skip(str(exc))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            if self.path.startswith("/api"):
                payload = b'{"detail":"browser fixture response"}'
                content_type = "application/problem+json"
            else:
                payload = b"<html><title>fixture</title><body>Loading<script>fetch('/api?debug=&preview').then(r=>r.json()).then(j=>{document.body.dataset.ready='yes';document.body.innerText=j.detail})</script></body></html>"
                content_type = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Set-Cookie", "a=1; Path=/")
            self.send_header("Set-Cookie", "b=2; Path=/")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    db_path = tmp_path / "capture.db"
    started = None

    async def browse(port):
        # Chrome normally bypasses loopback destinations even with proxy-server.
        # Explicit <-loopback> makes this local fixture exercise the real proxy.
        engine = Engine(EngineConfig(fast_engine=EngineType.CDP_CHROME,
            proxy_url=f"http://127.0.0.1:{port}", extra_chrome_args=["--proxy-bypass-list=<-loopback>"],
            cookie_jar_path=str(tmp_path / "browser.json"), nav_timeout=10, url_stability_timeout=0))
        try:
            session = await engine.create_session()
            await session.navigate(f"http://127.0.0.1:{httpd.server_port}/")
            assert await session.wait_for_selector("body[data-ready='yes']", timeout=5)
            assert await session.evaluate("document.body.innerText") == "browser fixture response"
            await session.close()
        finally:
            await engine.close()

    try:
        started = server.start(port="auto", db_path=str(db_path), dashboard=False,
                               scope_hosts=["127.0.0.1"], out_of_scope="block")
        assert started["status"] == "started", started
        assert server.status()["db"] == str(db_path)
        asyncio.run(browse(started["port"]))
        database = Database(db_path)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            rows = database.get_logs(limit=50)
            api = next((row for row in rows if "/api?" in row["url"] and row.get("response_code")), None)
            if api is not None:
                break
            time.sleep(0.1)
        assert api is not None, rows
        assert api["response_code"] == 200
        assert json.loads(api["response_body"])["detail"] == "browser fixture response"
    finally:
        if started and started.get("status") == "started":
            stopped = server.stop()
            assert stopped["status"] in ("stopped", "not_running"), stopped
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
