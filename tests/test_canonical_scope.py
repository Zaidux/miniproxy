"""Both proxy modes enforce exactly the CLI's canonical URL scope."""
from types import SimpleNamespace
from unittest.mock import Mock
import asyncio

import pytest

from miniproxy.scope import matches_any_scope, scope_contains, load_scope
from miniproxy.addon.proxy import MiniProxyAddon
from miniproxy.addon.intercept_addon import InterceptAddon


@pytest.mark.parametrize("url,entry,allowed", [
    ("https://api.acme.test/", "acme.test", False),
    ("https://api.acme.test/", "*.acme.test", True),
    ("https://acme.test.evil.test/", "*.acme.test", False),
    ("https://evil.test/?next=acme.test", "acme.test", False),
    ("https://acme.test/api/v1", "https://acme.test/api", True),
    ("https://acme.test/admin", "https://acme.test/api", False),
    ("https://acme.test/api/%2e%2e/admin", "https://acme.test/api", False),
    ("http://acme.test/api", "https://acme.test/api", False),
    ("https://acme.test:444/api", "https://acme.test/api", False),
    ("https://[::1]:444/api", "https://[::1]:444", True),
])
def test_canonical_url_constraints(url, entry, allowed):
    assert matches_any_scope(url, [entry]) is allowed


def test_wildcard_scope_is_not_subset_of_bare_domain():
    assert not scope_contains("*.acme.test", "acme.test")


def test_invalid_environment_scope_never_disables_guard(monkeypatch):
    monkeypatch.setenv("MINIPROXY_SCOPE", "not-json")
    entries, _ = load_scope()
    assert entries and not matches_any_scope("https://acme.test", entries)


def test_modified_intercept_url_cannot_escape_scope():
    addon = InterceptAddon.__new__(InterceptAddon)
    addon.db = Mock()
    addon.scope = ["acme.test"]
    addon.scope_mode = "skip"
    addon._intercept_enabled = True
    addon._rules = []
    addon._add_pending = Mock()
    async def decision(*args):
        return {"action": "modify", "modified_request": {"url": "https://evil.test"}}
    addon._wait_for_decision = decision
    flow = SimpleNamespace(request=SimpleNamespace(method="GET", host="acme.test", path="/",
        pretty_url="https://acme.test/", headers={}, text=""), intercept=Mock(), kill=Mock(), resume=Mock())
    asyncio.run(addon.request(flow))
    flow.kill.assert_called_once()
    flow.resume.assert_not_called()


def test_capture_rewrite_url_cannot_escape_scope():
    addon = MiniProxyAddon.__new__(MiniProxyAddon)
    addon.db = Mock()
    addon.db.is_noise.return_value = False
    addon.db.get_rewrite_rules.return_value = [{"match": "acme.test", "replace": "evil.test", "kind": "contains", "target": "query"}]
    addon.scope = ["acme.test"]
    addon.scope_mode = "skip"
    flow = SimpleNamespace(request=SimpleNamespace(method="GET", pretty_url="https://acme.test/", headers={}, text=""), response=None)
    addon.request(flow)
    assert flow.response.status_code == 403
    addon.db.store_request.assert_not_called()


@pytest.mark.parametrize("intercept", [False, True])
@pytest.mark.parametrize("url", ["https://evil.test/", "https://api.acme.test/api", "https://acme.test/admin", "https://acme.test/api/private"])
def test_out_of_scope_flow_is_never_stored_paused_or_rewritten(url, intercept):
    addon = (InterceptAddon if intercept else MiniProxyAddon).__new__(InterceptAddon if intercept else MiniProxyAddon)
    addon.db = Mock()
    addon.scope = ["https://acme.test/api"]
    addon.scope_mode = "skip"
    addon.allowed_scope = ["https://acme.test/api"]
    addon.excluded_scope = ["https://acme.test/api/private"]
    addon._intercept_enabled = True
    addon._rules = []
    flow = SimpleNamespace(request=SimpleNamespace(pretty_url=url), intercept=Mock(), response=None)
    if intercept:
        asyncio.run(addon.request(flow))
    else:
        addon.request(flow)
    addon.db.store_request.assert_not_called()
    addon.db.get_rewrite_rules.assert_not_called()
    flow.intercept.assert_not_called()
