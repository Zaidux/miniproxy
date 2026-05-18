"""MiniProxy mitmproxy addon — intercepts HTTP(S) traffic and logs to SQLite."""

from mitmproxy.http import HTTPFlow
from db import Database


class MiniProxyAddon:
    def __init__(self) -> None:
        self.db = Database()

    def request(self, flow: HTTPFlow) -> None:
        """Called when a request is received. Log it if intercept is on."""
        if not self.db.get_intercept():
            return

        req = flow.request
        req_id = self.db.store_request(
            method=req.method,
            url=req.pretty_url,
            headers=dict(req.headers),
            body=req.text or "",
        )
        flow._miniproxy_id = req_id

    def response(self, flow: HTTPFlow) -> None:
        """Called when a response is received. Update the logged request."""
        req_id = getattr(flow, '_miniproxy_id', None)
        if req_id is None:
            return

        resp = flow.response
        self.db.update_response(
            req_id=req_id,
            code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text or "",
            content_type=resp.headers.get("content-type", ""),
        )
        del flow._miniproxy_id


addons = [MiniProxyAddon()]
