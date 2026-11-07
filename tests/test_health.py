# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Health of LYSS itself: last scan record, "scheduled scans stopped" detection, external
heartbeat after scheduled scans, /health endpoint, dashboard warning. Fictitious data."""

from datetime import datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from lyss import health, inventory

NOW = datetime(2026, 11, 10, 9, 0, 0)


def job(trigger="schedule", errors=0, switches=3):
    items = {f"sw{i}": {"status": "error" if i < errors else "done", "message": ""} for i in range(switches)}
    return {"trigger": trigger, "items": items}


def schedule(days=range(7), enabled=True):
    inventory.save_settings({**inventory.load_settings(),
                             "schedule": {"enabled": enabled, "time": "02:30", "days": list(days)}})


def test_unscheduled_never_ok_stale(data_dir):
    assert health.status(NOW)["status"] == "unscheduled"
    schedule()
    assert health.status(NOW)["status"] == "never"
    health.record(job(), now=NOW - timedelta(hours=7))
    s = health.status(NOW)
    assert s["status"] == "ok" and s["expected_every_hours"] == 26 and s["switches"] == 3
    health.record(job(), now=NOW - timedelta(hours=27))
    assert health.status(NOW)["status"] == "stale"


def test_manual_scans_do_not_hide_stopped_schedules(data_dir):
    schedule()
    health.record(job(), now=NOW - timedelta(days=3))
    health.record(job(trigger="manual"), now=NOW - timedelta(hours=1))
    s = health.status(NOW)
    assert s["status"] == "stale" and s["last_scan"].startswith("2026-11-10T08")


def test_weekly_schedule_allows_the_longest_gap(data_dir):
    schedule(days=[0, 4])                       # Monday and Friday: longest gap 4 days
    assert health.expected_gap(inventory.load_settings()["schedule"]) == timedelta(days=4, hours=2)
    health.record(job(), now=NOW - timedelta(days=3))
    assert health.status(NOW)["status"] == "ok"


def test_heartbeat_only_after_scheduled_scans_and_never_echoes_the_url(data_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(health.httpx, "get", lambda url, **kw: calls.append(url) or httpx.Response(200))
    assert health.heartbeat(job()) is None                         # not configured
    inventory.save_settings({**inventory.load_settings(), "heartbeat": {"url": "https://hc.example/ping/SECRET"}})
    assert health.heartbeat(job(trigger="manual")) is None
    notice = health.heartbeat(job())
    assert calls == ["https://hc.example/ping/SECRET"] and "SECRET" not in notice and "sent" in notice
    monkeypatch.setattr(health.httpx, "get", lambda url, **kw: (_ for _ in ()).throw(httpx.ConnectError("down")))
    assert "failed" in health.heartbeat(job()) and "SECRET" not in health.heartbeat(job())


def test_scan_job_records_health_and_pings(data_dir, monkeypatch):
    from lyss import scan
    monkeypatch.setattr(scan.collector, "collect_many", lambda devices, jump, update: None)
    monkeypatch.setattr(scan.discovery, "from_neighbors", lambda: 0)
    monkeypatch.setattr(health, "heartbeat", lambda j: "Heartbeat sent to the external monitor.")
    job_id = scan.start([], trigger="schedule")
    for _ in range(100):
        if scan.current_job()["finished"]:
            break
        import time
        time.sleep(0.05)
    assert job_id and health.load()["last_scheduled_scan"]["trigger"] == "schedule"
    assert "Heartbeat sent to the external monitor." in scan.current_job()["notices"]


@pytest.fixture
def client(data_dir):
    from lyss.web import app as webapp
    return TestClient(webapp.app, base_url="http://127.0.0.1:8765")


def test_health_endpoint_is_public_minimal_and_503_when_stale(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "unscheduled"
    schedule()
    health.record(job(), now=datetime.now() - timedelta(days=2))
    r = client.get("/health")
    body = r.json()
    assert r.status_code == 503 and body["status"] == "stale"
    assert set(body) == {"status", "last_scan", "last_scheduled_scan", "hours_since_scheduled",
                         "expected_every_hours", "errors", "version"}
