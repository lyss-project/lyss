# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Health of LYSS itself.

- Every finished scan is recorded (time, trigger, switches, collection errors) in health.json.
- status(): "ok", "stale" (scheduled scans enabled but none finished within the expected gap),
  "never" (scheduled scans enabled, none finished yet) or "unscheduled". Shown on the dashboard
  and served by GET /health for monitoring tools.
- heartbeat(): after each scheduled scan, an optional HTTP GET to a URL of an external
  "dead man's switch" monitor (e.g. Healthchecks.io, Uptime Kuma push monitor). That monitor
  alerts when the calls stop, which is the only alarm that still works when the LYSS PC itself
  is off or LYSS is not running.
"""

from datetime import datetime, timedelta

import httpx

from . import inventory

HEARTBEAT_TIMEOUT = 10  # seconds


def _file():
    return inventory.PRIVATE / "health.json"


def load() -> dict:
    return inventory._read(_file(), {})


def record(job: dict, now: datetime | None = None) -> dict:
    """Remember a finished scan job (called by scan.start when the job ends)."""
    now = (now or datetime.now()).replace(microsecond=0)
    items = job.get("items", {})
    entry = {"finished": now.isoformat(), "trigger": job.get("trigger", "manual"), "switches": len(items),
             "errors": sum(1 for i in items.values() if i.get("status") == "error")}
    data = load()
    data["last_scan"] = entry
    if entry["trigger"] == "schedule":
        data["last_scheduled_scan"] = entry
    inventory._write(_file(), data)
    return entry


def expected_gap(schedule: dict) -> timedelta | None:
    """Longest normal time between two scheduled scans, plus a 2-hour margin (None if disabled)."""
    if not schedule.get("enabled"):
        return None
    days = sorted(set(schedule.get("days", range(7)))) or list(range(7))
    gaps = [(days[(i + 1) % len(days)] - d) % 7 or 7 for i, d in enumerate(days)]
    return timedelta(days=max(gaps), hours=2)


def status(now: datetime | None = None) -> dict:
    now = now or datetime.now()
    data = load()
    gap = expected_gap(inventory.load_settings().get("schedule", {}))
    last, scheduled = data.get("last_scan"), data.get("last_scheduled_scan")
    out = {"status": "unscheduled", "last_scan": (last or {}).get("finished"),
           "last_scheduled_scan": (scheduled or {}).get("finished"),
           "switches": (last or {}).get("switches", 0), "errors": (last or {}).get("errors", 0),
           "expected_every_hours": round(gap.total_seconds() / 3600) if gap else None}
    if gap is None:
        return out
    if not scheduled:
        out["status"] = "never"
        return out
    age = now - datetime.fromisoformat(scheduled["finished"])
    out["hours_since_scheduled"] = round(age.total_seconds() / 3600, 1)
    out["status"] = "stale" if age > gap else "ok"
    return out


def valid_url(url: str) -> bool:
    return url.startswith(("https://", "http://")) and len(url) <= 500 and not any(c.isspace() for c in url)


def heartbeat(job: dict) -> str | None:
    """Ping the external monitor after a scheduled scan; returns a notice, or None if not configured.
    The URL is never echoed (it usually carries the monitor's secret token)."""
    url = (inventory.load_settings().get("heartbeat") or {}).get("url", "")
    if not url or job.get("trigger") != "schedule":
        return None
    if not valid_url(url):
        return "Heartbeat not sent: the URL in Settings is not a valid http(s) URL."
    try:
        r = httpx.get(url, timeout=HEARTBEAT_TIMEOUT, follow_redirects=True)
        return "Heartbeat sent to the external monitor." if r.status_code < 400 else \
            f"Heartbeat failed: the monitor answered HTTP {r.status_code}."
    except httpx.HTTPError as exc:
        return f"Heartbeat failed: {type(exc).__name__}."
