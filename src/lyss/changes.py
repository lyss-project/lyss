# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Rescan on change: when the SIEM reports that a switch configuration changed, or that an
administrator session on it ended, LYSS rescans that switch right away instead of waiting for the
next scheduled scan.

Source: the Wazuh dashboard (HTTPS, port 443), queried every few minutes with a read-only account
(integrations/wazuh/reader-account.sh creates one that can only see these alerts). LYSS only
connects out; nothing connects to the LYSS machine. Matching alerts:
  - rule group "config_changed"          (Cisco IOS %SYS-5-CONFIG_I: Wazuh rule 4721)
  - rule group "lyss_admin_session_end"  (Cisco Business session closed: LYSS rule 100872)
whose "location" (the syslog source address) is the address of a managed switch.

LYSS's own SSH sessions produce such alerts too: an alert dated before the end of the last LYSS
collection of that switch plus QUIET_MINUTES is ignored, so a scan never triggers another one.

Settings "change_watch": {"enabled", "url", "username", "secret" (vault), "verify_tls",
"interval_minutes", "last_checked" (ISO time of the last alert seen)}.
"""

import json
from datetime import datetime, timedelta, timezone

import httpx

from . import inventory, scan, vault

GROUPS = ["config_changed", "lyss_admin_session_end"]
QUIET_MINUTES = 3
DEFAULT_INTERVAL = 5
LOOKBACK = timedelta(hours=1)  # first run: only recent alerts
_transport = None              # tests inject an httpx.MockTransport here
_pending: set[str] = set()     # switches waiting for a rescan (a scan was already running)
_last_poll: datetime | None = None


def settings() -> dict:
    return inventory.load_settings().get("change_watch", {})


def _client(cfg: dict) -> httpx.Client:
    return httpx.Client(base_url=cfg["url"].rstrip("/"), timeout=30, verify=cfg.get("verify_tls", True),
                        auth=(cfg["username"], vault.unprotect(cfg["secret"])),
                        headers={"osd-xsrf": "true", "Content-Type": "application/json"}, transport=_transport)


def query(cfg: dict, hosts: list[str], since: datetime) -> list[dict]:
    """Alerts of the watched groups from the given switch addresses, after `since` (oldest first)."""
    body = {"size": 500, "sort": [{"timestamp": {"order": "asc"}}],
            "_source": ["timestamp", "location", "rule.id", "rule.groups", "rule.description"],
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gt": since.astimezone(timezone.utc).isoformat()}}},
                {"terms": {"rule.groups": GROUPS}},
                {"terms": {"location": hosts}}]}}}
    with _client(cfg) as http:
        r = http.post("/api/console/proxy", params={"path": "wazuh-alerts-*/_search", "method": "POST"},
                      content=json.dumps(body))
        r.raise_for_status()
        return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def test_connection(cfg: dict | None = None) -> str:
    cfg = cfg or settings()
    alerts = query(cfg, ["192.0.2.255"], datetime.now(timezone.utc) - timedelta(minutes=5))
    return f"connected to {cfg['url']} ({len(alerts)} alert)"


def _parse(ts: str) -> datetime:
    ts = ts.replace("Z", "+00:00")
    if len(ts) > 5 and ts[-5] in "+-" and ts[-3] != ":":   # +0000 -> +00:00
        ts = ts[:-2] + ":" + ts[-2:]
    return datetime.fromisoformat(ts)


def _last_collection(device_id: str) -> datetime | None:
    result = inventory.load_result(device_id) or {}
    if not result.get("scanned_at"):
        return None
    return datetime.fromisoformat(result["scanned_at"]).astimezone()  # stored as local time


def changed_devices(alerts: list[dict], devices: list[dict]) -> dict[str, str]:
    """{device id: reason} for alerts not explained by LYSS's own last collection."""
    by_host = {d["host"]: d for d in devices}
    out: dict[str, str] = {}
    for a in alerts:
        device = by_host.get(a.get("location"))
        if not device:
            continue
        when = _parse(a["timestamp"])
        last = _last_collection(device["id"])
        if last and when <= last + timedelta(minutes=QUIET_MINUTES):
            continue  # LYSS's own session (or a change already covered by the last scan)
        out[device["id"]] = f"{a['rule'].get('description', 'change')} ({when:%Y-%m-%d %H:%M} UTC)"
    return out


def tick(now: datetime | None = None) -> list[str]:
    """Poll the SIEM if due, start a rescan of changed switches. Returns the ids rescanned."""
    global _last_poll
    cfg = settings()
    if not cfg.get("enabled") or not cfg.get("url") or not cfg.get("secret"):
        return []
    now = now or datetime.now(timezone.utc)
    interval = timedelta(minutes=int(cfg.get("interval_minutes") or DEFAULT_INTERVAL))
    if _last_poll and now - _last_poll < interval and not _pending:
        return []
    _last_poll = now
    devices = inventory.load_devices()
    since = _parse(cfg["last_checked"]) if cfg.get("last_checked") else now - LOOKBACK
    alerts = query(cfg, [d["host"] for d in devices], since)
    _pending.update(changed_devices(alerts, devices))
    if alerts:
        settings_all = inventory.load_settings()
        settings_all.setdefault("change_watch", {})["last_checked"] = alerts[-1]["timestamp"]
        inventory.save_settings(settings_all)
    if not _pending:
        return []
    ids = sorted(_pending)
    if scan.start(ids, trigger="change") is None:
        return []  # a scan is running: retry at the next tick
    _pending.clear()
    return ids
