"""TLS MITM capture fidelity on operator-owned loopback infrastructure."""
from __future__ import annotations
import json
import os
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from miniproxy import server
from miniproxy.addon.db import Database


def test_tls_json_headers_and_ca_health(tmp_path):
    from miniproxy.runtime import resolve_mitmdump
    try:
        resolve_mitmdump()
    except RuntimeError as exc:
        pytest.skip(str(exc))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "fixture.pem", tmp_path / "fixture.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key_path, 0o600)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            body = b'{"tls_fixture":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.api+json")
            self.send_header("Set-Cookie", "first=1; Path=/")
            self.send_header("Set-Cookie", "second=2; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    db_path, confdir = tmp_path / "capture.db", tmp_path / "ca"
    started = None
    try:
        started = server.start(port="auto", dashboard=False, db_path=str(db_path),
            scope_hosts=["127.0.0.1"], out_of_scope="block",
            extra_args=["--set", "ssl_insecure=true", "--set", f"confdir={confdir}"])
        assert started["status"] == "started", started
        ca = confdir / "mitmproxy-ca-cert.pem"
        assert ca.is_file()
        assert server.health()["ca_certificate_path"] == str(ca)
        client_context = ssl.create_default_context(cafile=str(ca))
        with socket.create_connection(("127.0.0.1", started["port"]), timeout=10) as connection:
            authority = f"127.0.0.1:{httpd.server_port}"
            connection.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            received = b""
            while b"\r\n\r\n" not in received:
                chunk = connection.recv(4096)
                assert chunk, "Proxy closed before CONNECT response"
                received += chunk
                assert len(received) < 65536, "Unbounded CONNECT response"
            assert received.startswith(b"HTTP/1.1 200"), received
            with client_context.wrap_socket(connection, server_hostname="127.0.0.1") as tls:
                tls.settimeout(10)
                tls.sendall(f"GET /api?blank=&flag HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode())
                response = b""
                while chunk := tls.recv(65536):
                    response += chunk
        assert b'"tls_fixture":true' in response
        db = Database(db_path)
        deadline = time.monotonic() + 5
        row = None
        while time.monotonic() < deadline:
            row = next((r for r in db.get_logs(limit=10) if r.get("response_code") == 200), None)
            if row: break
            time.sleep(0.1)
        assert row is not None
        assert row["url"].startswith("https://127.0.0.1:")
        assert json.loads(row["response_body"]) == {"tls_fixture": True}
        raw = json.loads(row["response_headers_raw"])
        assert len([header for header in raw if header[0].lower() == "set-cookie"]) == 2
    finally:
        if started and started.get("status") == "started":
            result = server.stop()
            assert result["status"] in ("stopped", "not_running"), result
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
