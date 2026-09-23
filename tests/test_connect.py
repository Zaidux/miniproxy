"""Tests for the remote-browser connect flow: PAC, CA, QR, /connect page,
/api/connect/info, pairing — plus the qrcode renderer and connect helpers."""
from __future__ import annotations

import pytest


# ── Dashboard endpoints ─────────────────────────────────────────────────


class TestPacEndpoint:
    def test_pac_contains_running_proxy(self, app_client, monkeypatch):
        client, _, appmod = app_client
        monkeypatch.setattr(appmod.proxy_server, "status",
                            lambda: {"status": "running", "pid": 1, "port": 9099})
        r = client.get("/proxy.pac")
        assert r.status_code == 200
        assert "PROXY " in r.get_data(as_text=True)
        assert "FindProxyForURL" in r.get_data(as_text=True)
        assert "DIRECT" in r.get_data(as_text=True)
        assert "x-ns-proxy-autoconfig" in r.headers["Content-Type"]

    def test_pac_direct_for_localhost(self, app_client):
        client, _, _ = app_client
        body = client.get("/proxy.pac").get_data(as_text=True)
        assert "shExpMatch(host, 'localhost')" in body

    def test_pac_honors_explicit_override(self, app_client):
        client, _, _ = app_client
        body = client.get("/proxy.pac?proxy_host=10.1.2.3&port=9999").get_data(as_text=True)
        assert "PROXY 10.1.2.3:9999" in body


class TestCaEndpoint:
    def test_ca_404_when_missing(self, app_client, tmp_path, monkeypatch):
        client, _, _ = app_client
        monkeypatch.setenv("MINIPROXY_CA_CERT", str(tmp_path / "nope.pem"))
        r = client.get("/ca.crt")
        assert r.status_code == 404
        assert "mitmdump" in r.get_json()["error"]

    def test_ca_serves_pem(self, app_client, tmp_path, monkeypatch):
        client, _, _ = app_client
        pem = tmp_path / "ca.pem"
        pem.write_bytes(b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n")
        monkeypatch.setenv("MINIPROXY_CA_CERT", str(pem))
        r = client.get("/ca.crt")
        assert r.status_code == 200
        assert r.data.startswith(b"-----BEGIN CERTIFICATE-----")
        assert "attachment" in r.headers["Content-Disposition"]


class TestConnectPage:
    def test_connect_page_renders(self, app_client):
        client, _, _ = app_client
        r = client.get("/connect")
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert "Connect a browser" in html
        assert "PAC" in html and "ca.crt" in html

    def test_connect_info(self, app_client, tmp_path, monkeypatch):
        client, _, _ = app_client
        pem = tmp_path / "ca.pem"
        pem.write_text("dummy")
        monkeypatch.setenv("MINIPROXY_CA_CERT", str(pem))
        r = client.get("/api/connect/info", headers={"Host": "192.168.1.5:5000"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["proxy"]["address"] == "192.168.1.5:8080"
        assert data["pac_url"].endswith("/proxy.pac")
        assert data["ca_url"].endswith("/ca.crt")
        assert data["ca_available"] is True
        assert data["connect_url"].endswith("/connect")
        assert any(h["host"] == "192.168.1.5" for h in data["hosts"])
        assert "curl -x" in data["curl"]["plain"]

    def test_connect_info_respects_running_proxy_port(self, app_client, monkeypatch):
        client, _, appmod = app_client
        monkeypatch.setattr(appmod.proxy_server, "status",
                            lambda: {"status": "running", "pid": 1, "port": 9150})
        data = client.get("/api/connect/info").get_json()
        assert data["proxy"]["port"] == 9150


class TestConnectQr:
    def test_qr_svg(self, app_client):
        client, _, _ = app_client
        r = client.get("/connect/qr.svg", headers={"Host": "192.168.1.5:5000"})
        assert r.status_code == 200
        svg = r.get_data(as_text=True)
        assert svg.startswith("<svg") and "<rect" in svg

    def test_qr_rejects_overlong_urls(self, app_client):
        # Overlong hosts never reach the handler as JSON: Werkzeug itself
        # 400s requests whose Host header is malformed/oversized. Verify the
        # guard at the unit level instead — an overlong URL must raise.
        client, _, _ = app_client
        r = client.get("/connect/qr.svg", headers={"Host": "a" * 200 + ":5000"})
        assert r.status_code == 400  # Werkzeug-level rejection

    def test_qr_guard_rejects_overlong_payload_directly(self):
        from miniproxy import qrcode

        with pytest.raises(ValueError, match="too long"):
            qrcode.qr_svg("http://" + "a" * 80 + ":5000/connect")


class TestPairing:
    def test_pair_roundtrip(self, app_client):
        client, db, _ = app_client
        assert client.get("/api/connect/pair").get_json() == {"paired": False}
        r = client.post("/api/connect/pair", json={"name": "iphone-safari"})
        assert r.status_code == 200 and r.get_json() == {"paired": True, "name": "iphone-safari"}
        again = client.get("/api/connect/pair").get_json()
        assert again["paired"] is True and again["name"] == "iphone-safari"

    def test_pair_sanitizes_names(self, app_client):
        client, _, _ = app_client
        r = client.post("/api/connect/pair", json={"name": "<script>alert(1)</script>"})
        assert r.get_json()["name"] == "scriptalert1script"

    def test_pair_requires_token_when_set(self, app_client, monkeypatch):
        client, _, appmod = app_client
        monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", "sekret")
        assert client.post("/api/connect/pair", json={"name": "x"}).status_code == 401
        r = client.post("/api/connect/pair?token=sekret", json={"name": "x"})
        assert r.status_code == 200


# ── connect helpers module ──────────────────────────────────────────────


class TestConnectHelpers:
    def test_candidate_hosts_drops_placeholders(self):
        from miniproxy.connect import candidate_hosts

        hosts = candidate_hosts("0.0.0.0:8080")
        assert all(h["host"] not in ("0.0.0.0", "::", "*") for h in hosts)
        assert hosts[-1]["host"] == "127.0.0.1"

    def test_candidate_hosts_request_header_wins(self):
        from miniproxy.connect import candidate_hosts

        hosts = candidate_hosts("tunnel.example.com:5000")
        assert hosts[0]["host"] == "tunnel.example.com"

    def test_candidate_hosts_can_exclude_loopback(self):
        from miniproxy.connect import candidate_hosts

        for h in candidate_hosts(include_loopback=False):
            assert h["host"] not in ("127.0.0.1", "localhost", "::1")

    def test_resolve_proxy_target_precedence(self):
        from miniproxy.connect import resolve_proxy_target

        assert resolve_proxy_target("h1", 1111, "hdr") == ("h1", 1111)
        assert resolve_proxy_target(None, 2222, "hdr.example")[0] in ("hdr.example",)
        assert resolve_proxy_target(None, None, None, running_port=9333)[1] == 9333
        assert resolve_proxy_target(None, None, None)[1] == 8080

    def test_pac_body_escapes_nothing_but_contains_target(self):
        from miniproxy.connect import pac_body

        body = pac_body("10.0.0.9", 8080)
        assert "PROXY 10.0.0.9:8080; DIRECT" in body

    def test_ca_cert_path_env_override(self, monkeypatch, tmp_path):
        from miniproxy.connect import ca_cert_path

        monkeypatch.setenv("MINIPROXY_CA_CERT", str(tmp_path / "x.pem"))
        assert ca_cert_path() == tmp_path / "x.pem"


# ── qrcode renderer ────────────────────────────────────────────────────


class TestQrcode:
    def test_svg_is_square_with_quiet_zone(self):
        from miniproxy.qrcode import qr_svg

        svg = qr_svg("http://127.0.0.1:5000/connect")
        assert svg.startswith("<svg")
        assert svg.count("<rect") > 50  # finder patterns + data modules

    def test_terminal_render_is_ansi_inverted(self):
        from miniproxy.qrcode import qr_terminal

        out = qr_terminal("http://127.0.0.1:5000/connect")
        assert "\x1b[7m" in out and "█" in out

    def test_overlong_payload_raises(self):
        from miniproxy.qrcode import qr_svg

        with pytest.raises(ValueError):
            qr_svg("x" * 200)

    def test_deterministic(self):
        from miniproxy.qrcode import qr_svg

        assert qr_svg("http://a.b/c") == qr_svg("http://a.b/c")
