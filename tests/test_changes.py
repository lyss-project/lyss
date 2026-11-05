# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Rescan on change: Wazuh change alerts -> rescans, ignoring LYSS's own sessions (synthetic data)."""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from lyss import changes, inventory, scan, vault
from lyss.web import app as webapp
from test_web import PASSWORD, csrf_of

NOW = datetime(2026, 11, 5, 18, 0, tzinfo=timezone.utc)


def alert(host, minutes_ago, group="config_changed", rule="4721"):
    ts = (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    return {"timestamp": ts, "location": host,
            "rule": {"id": rule, "groups": ["syslog", group], "description": "Cisco IOS: Router configuration changed"}}


@pytest.fixture
def fleet(data_dir, monkeypatch):
    for device_id, host, vendor in (("core-1", "192.0.2.1", "cisco_ios"), ("acc-1", "192.0.2.11", "cisco_sb")):
        inventory.save_device({"id": device_id, "host": host, "port": "22", "vendor": vendor, "username": "ro",
                               "via_jump": False}, "Sw1tch-Pass!")
    settings = inventory.load_settings()
    settings["change_watch"] = {"enabled": True, "url": "https://wazuh.example", "username": "lyss-reader",
                                "secret": vault.protect("Reader-Pass!"), "verify_tls": True, "interval_minutes": 5}
    inventory.save_settings(settings)
    started = []
    monkeypatch.setattr(scan, "start", lambda ids, trigger="manual": started.append((ids, trigger)) or "job")
    monkeypatch.setattr(changes, "_last_poll", None)
    changes._pending.clear()
    return started


def wazuh(alerts, seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"hits": {"hits": [{"_source": a} for a in alerts]}})
    return httpx.MockTransport(handler)


def scanned(device_id, minutes_ago):
    """LYSS's last collection of a device, stored like scan results (local time)."""
    when = (NOW - timedelta(minutes=minutes_ago)).astimezone().replace(tzinfo=None)
    inventory.save_result(device_id, {"device": device_id, "scanned_at": when.isoformat(timespec="seconds"),
                                      "summary": {}, "findings": []})


def test_a_change_triggers_a_rescan_of_that_switch_only(fleet, monkeypatch):
    seen = []
    monkeypatch.setattr(changes, "_transport", wazuh([alert("192.0.2.1", 2)], seen))
    scanned("core-1", 60)
    assert changes.tick(NOW) == ["core-1"]
    assert fleet == [(["core-1"], "change")]
    # the query: read-only search through the dashboard, the watched groups, the managed switches only
    request = seen[0]
    assert request.url.path == "/api/console/proxy" and request.url.params["path"] == "wazuh-alerts-*/_search"
    assert request.headers["osd-xsrf"] == "true" and request.headers["authorization"].startswith("Basic ")
    body = json.loads(request.content)
    terms = {k: sorted(v) for f in body["query"]["bool"]["filter"] if "terms" in f for k, v in f["terms"].items()}
    assert terms == {"location": ["192.0.2.1", "192.0.2.11"], "rule.groups": sorted(changes.GROUPS)}
    assert inventory.load_settings()["change_watch"]["last_checked"] == alert("192.0.2.1", 2)["timestamp"]


def test_lyss_own_sessions_do_not_trigger_a_rescan(fleet, monkeypatch):
    # the switch was collected 1 minute ago: the session-end alert 2 minutes ago is LYSS's own session
    monkeypatch.setattr(changes, "_transport", wazuh([alert("192.0.2.11", 2, "lyss_admin_session_end", "100872")], []))
    scanned("acc-1", 1)
    assert changes.tick(NOW) == [] and fleet == []


def test_unknown_addresses_are_ignored_and_polling_waits_for_the_interval(fleet, monkeypatch):
    seen = []
    monkeypatch.setattr(changes, "_transport", wazuh([alert("198.51.100.7", 1)], seen))
    assert changes.tick(NOW) == []
    assert changes.tick(NOW + timedelta(minutes=1)) == [] and len(seen) == 1  # interval not reached
    changes.tick(NOW + timedelta(minutes=6))
    assert len(seen) == 2


def test_a_busy_scanner_keeps_the_switch_pending(fleet, monkeypatch):
    monkeypatch.setattr(changes, "_transport", wazuh([alert("192.0.2.1", 2)], []))
    monkeypatch.setattr(scan, "start", lambda ids, trigger="manual": None)  # a scan is running
    assert changes.tick(NOW) == [] and changes._pending == {"core-1"}
    monkeypatch.setattr(changes, "_transport", wazuh([], []))
    monkeypatch.setattr(scan, "start", lambda ids, trigger="manual": "job")
    assert changes.tick(NOW + timedelta(minutes=1)) == ["core-1"]  # retried at once, not after the interval


def test_disabled_does_nothing(fleet, monkeypatch):
    settings = inventory.load_settings()
    settings["change_watch"]["enabled"] = False
    inventory.save_settings(settings)
    monkeypatch.setattr(changes, "_transport", wazuh([alert("192.0.2.1", 2)], []))
    assert changes.tick(NOW) == []


@pytest.mark.parametrize("value", ["2026-11-05T18:36:15.757+0000", "2026-11-05T18:36:15.757Z",
                                   "2026-11-05T18:36:15.757+00:00"])
def test_wazuh_timestamps(value):
    assert changes._parse(value) == datetime(2026, 11, 5, 18, 36, 15, 757000, tzinfo=timezone.utc)


def test_settings_form(data_dir, monkeypatch):
    webapp._sessions.clear()
    webapp._failures.update(count=0, locked_until=0)
    client = TestClient(webapp.app, base_url="http://127.0.0.1:8765")
    client.post("/setup", data={"password": PASSWORD, "confirm": PASSWORD})
    csrf = csrf_of(client.get("/settings").text)
    r = client.post("/settings/changes", data={"csrf": csrf, "enabled": "on", "url": "https://wazuh.example",
                                               "username": "lyss-reader", "password": "Reader-Pass!",
                                               "interval": "5", "verify_tls": "on"})
    assert r.status_code == 200 and "Reader-Pass!" not in r.text
    assert "Reader-Pass!" not in json.dumps(inventory.load_settings())
    monkeypatch.setattr(changes, "_transport", wazuh([], []))
    r = client.post("/settings/changes/test", data={"csrf": csrf})
    assert r.status_code == 200 and "connected to https://wazuh.example" in r.text
    for bad in ({"url": "http://wazuh.example"}, {"url": "javascript:alert(1)"}, {"interval": "0"},
                {"username": "a b"}):
        data = {"csrf": csrf, "enabled": "on", "url": "https://wazuh.example", "username": "lyss-reader",
                "interval": "5", **bad}
        assert client.post("/settings/changes", data=data).status_code == 400, bad
