"""Tests for the persistent device registry: db methods, API endpoints,
token gating, and upsert semantics."""
from __future__ import annotations

import pytest


class TestDeviceRegistryDb:
    def test_register_and_list(self, db):
        db.register_device("pixel-chrome", "10.0.0.5", "Mozilla/5.0 (Android)")
        db.register_device("ipad-safari", "10.0.0.6", "Mobile Safari")
        devs = db.get_devices()
        assert [d["name"] for d in devs] == ["ipad-safari", "pixel-chrome"]  # newest first
        assert devs[1]["ip"] == "10.0.0.5"
        assert "Android" in devs[1]["user_agent"]
        assert devs[1]["first_seen"] and devs[1]["last_seen"]

    def test_upsert_on_same_name_and_ip(self, db):
        first = db.register_device("pixel-chrome", "10.0.0.5")
        again = db.register_device("pixel-chrome", "10.0.0.5")
        assert first == again
        assert len(db.get_devices()) == 1

    def test_same_name_different_ip_is_separate(self, db):
        db.register_device("pixel-chrome", "10.0.0.5")
        db.register_device("pixel-chrome", "10.0.0.9")
        assert len(db.get_devices()) == 2

    def test_upsert_with_null_ip_returns_real_id(self, db):
        """Regression: on the DO UPDATE path SQLite's lastrowid is stale, so
        the id must be re-fetched; also NULL-IP rows must upsert on (name,
        NULL) rather than colliding."""
        first = db.register_device("mystery-box", None)
        again = db.register_device("mystery-box", None)
        assert first == again
        assert len(db.get_devices()) == 1

    def test_upsert_refreshes_last_seen(self, db):
        db.register_device("pixel-chrome", "10.0.0.5")
        db.register_device("pixel-chrome", "10.0.0.5", "new-agent")
        (dev,) = db.get_devices()
        assert dev["user_agent"] == "new-agent"
        assert dev["first_seen"] == dev["last_seen"] or dev["last_seen"] >= dev["first_seen"]

    def test_remove_and_clear(self, db):
        db.register_device("a", "1.1.1.1")
        did = db.register_device("b", "2.2.2.2")
        assert db.remove_device(did) is True
        assert db.remove_device(did) is False  # already gone
        assert db.remove_device(424242) is False
        assert len(db.get_devices()) == 1
        assert db.clear_devices() == 1
        assert db.get_devices() == []


class TestDevicesApi:
    def test_save_lists_and_deletes(self, app_client):
        client, _, _ = app_client
        r = client.post("/api/connect/devices", json={"name": "pixel-chrome"})
        assert r.status_code == 201
        body = r.get_json()
        assert body["saved"] is True and body["name"] == "pixel-chrome"
        device_id = body["id"]

        listing = client.get("/api/connect/devices").get_json()
        assert listing["devices"][0]["name"] == "pixel-chrome"
        assert listing["devices"][0]["ip"]  # caller IP recorded
        assert listing["devices"][0]["user_agent"]  # caller UA recorded

        assert client.delete(f"/api/connect/devices/{device_id}").status_code == 200
        assert client.get("/api/connect/devices").get_json()["devices"] == []

    def test_delete_unknown_returns_404(self, app_client):
        client, _, _ = app_client
        assert client.delete("/api/connect/devices/999").status_code == 404

    def test_save_sanitizes_names(self, app_client):
        client, _, _ = app_client
        r = client.post("/api/connect/devices", json={"name": "<img src=x>"})
        assert r.get_json()["name"] == "img srcx"

    def test_pair_registers_device_too(self, app_client):
        client, db, _ = app_client
        client.post("/api/connect/pair", json={"name": "work-laptop"})
        devs = db.get_devices()
        assert len(devs) == 1 and devs[0]["name"] == "work-laptop"

    def test_devices_require_token_when_set(self, app_client, monkeypatch):
        client, _, appmod = app_client
        monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", "sekret")
        assert client.post("/api/connect/devices", json={"name": "x"}).status_code == 401
        assert client.delete("/api/connect/devices/1").status_code == 401
        # reads stay open
        assert client.get("/api/connect/devices").status_code == 200
        # token unlocks writes
        r = client.post("/api/connect/devices?token=sekret", json={"name": "x"})
        assert r.status_code == 201

    def test_registry_survives_reopen(self, app_client, db_path):
        client, _, _ = app_client
        client.post("/api/connect/devices", json={"name": "durable-phone"})
        # Reopen the same DB file — a new Database instance sees the device.
        from miniproxy.addon.db import Database

        devs = Database(db_path).get_devices()
        assert len(devs) == 1 and devs[0]["name"] == "durable-phone"
