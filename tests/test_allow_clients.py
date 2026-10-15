"""Client-IP allowlist for the proxy port.

The proxy runs with ``block_global=false`` so a remote browser can use it.
That makes it an open relay unless the operator restricts who may connect, so
these tests pin the allowlist plumbing down.
"""
from __future__ import annotations

from miniproxy.server import _allow_hosts_args


class TestAllowHostsArgs:
    def test_absent_allowlist_emits_nothing(self):
        """No allowlist keeps the current (open) behaviour — the CLI warns."""
        assert _allow_hosts_args(None) == []
        assert _allow_hosts_args([]) == []

    def test_single_ip(self):
        assert _allow_hosts_args(["203.0.113.7"]) == [
            "--set", "allow_hosts=203.0.113.7",
        ]

    def test_multiple_ips_are_one_comma_list(self):
        """mitmproxy parses allow_hosts as one comma-separated value, so the
        IPs must not be emitted as repeated flags."""
        assert _allow_hosts_args(["203.0.113.7", "198.51.100.4"]) == [
            "--set", "allow_hosts=203.0.113.7,198.51.100.4",
        ]

    def test_blank_entries_are_dropped(self):
        assert _allow_hosts_args([" 203.0.113.7 ", "", "   "]) == [
            "--set", "allow_hosts=203.0.113.7",
        ]

    def test_bare_string_is_not_iterated_per_character(self):
        """A single IP arriving as a str must not become 1,2,3,... entries."""
        assert _allow_hosts_args("203.0.113.9") == [
            "--set", "allow_hosts=203.0.113.9",
        ]


class TestProxyHost:
    def test_default_is_loopback(self):
        """The proxy must not be published to the internet by default."""
        import inspect

        from miniproxy.server import start

        sig = inspect.signature(start)
        assert sig.parameters["proxy_host"].default == "127.0.0.1"

    def test_cli_default_is_loopback(self):
        from miniproxy.__main__ import build_parser

        assert build_parser().parse_args(["start"]).proxy_host == "127.0.0.1"

    def test_cli_accepts_public_bind(self):
        from miniproxy.__main__ import build_parser

        args = build_parser().parse_args(["start", "--proxy-host", "0.0.0.0"])
        assert args.proxy_host == "0.0.0.0"

    def test_flag_available_on_web_alias(self):
        from miniproxy.__main__ import build_parser

        args = build_parser().parse_args(["web", "--proxy-host", "0.0.0.0"])
        assert args.proxy_host == "0.0.0.0"


class TestPacRespectsBindHost:
    """A loopback-only proxy must not be advertised at the server's public IP.

    Advertising 104.2.3.4:8082 would hand devices a PAC that cannot connect,
    because the port is no longer listening on the public interface.
    """

    def test_loopback_bind_forces_loopback_pac(self):
        from miniproxy.connect import resolve_proxy_target

        host, port = resolve_proxy_target(
            "", None, "104.238.174.55", running_port=8082, bind_host="127.0.0.1",
        )
        assert host == "127.0.0.1"
        assert port == 8082

    def test_public_bind_uses_request_host(self):
        from miniproxy.connect import resolve_proxy_target

        host, _ = resolve_proxy_target("", None, "104.238.174.55", bind_host="0.0.0.0")
        assert host == "104.238.174.55"

    def test_lan_bind_is_used_directly(self):
        from miniproxy.connect import resolve_proxy_target

        host, _ = resolve_proxy_target("", None, "10.0.0.5", bind_host="10.0.0.9")
        assert host == "10.0.0.9"

    def test_explicit_override_still_wins(self):
        from miniproxy.connect import resolve_proxy_target

        host, _ = resolve_proxy_target(
            "proxy.internal", None, "104.238.174.55", bind_host="127.0.0.1",
        )
        assert host == "proxy.internal"


class TestAllowClientFlag:
    def test_repeatable_on_start(self):
        from miniproxy.__main__ import build_parser

        args = build_parser().parse_args(
            ["start", "--allow-client", "1.2.3.4", "--allow-client", "5.6.7.8"]
        )
        assert args.allow_client == ["1.2.3.4", "5.6.7.8"]

    def test_repeatable_on_web_alias(self):
        """Regression: the alias copies options by hand and used to drop
        action='append', collapsing the value to a bare string."""
        from miniproxy.__main__ import build_parser

        args = build_parser().parse_args(
            ["web", "--allow-client", "1.2.3.4", "--allow-client", "5.6.7.8"]
        )
        assert args.allow_client == ["1.2.3.4", "5.6.7.8"]

    def test_defaults_to_unrestricted(self):
        from miniproxy.__main__ import build_parser

        assert build_parser().parse_args(["start"]).allow_client is None