# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Scheduled scans while the web interface runs.

Settings "schedule": {"enabled": bool, "time": "HH:MM", "days": [0..6] (Monday = 0)}.
A run missed while LYSS was stopped is caught up if LYSS starts within CATCH_UP of it.
Without the web interface, schedule `python -m lyss collect --scheduled` with cron or the
Windows Task Scheduler instead (same effect: an automatic backup + audit).
"""

import threading
import time
from datetime import datetime, timedelta

from . import inventory, scan

CATCH_UP = timedelta(hours=6)
_started = False


def due_time(schedule: dict, now: datetime) -> datetime | None:
    """The most recent scheduled moment at or before now, or None."""
    if not schedule.get("enabled"):
        return None
    hour, minute = (int(x) for x in schedule.get("time", "02:30").split(":"))
    days = set(schedule.get("days", range(7)))
    for back in range(8):
        day = now - timedelta(days=back)
        moment = day.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if moment <= now and moment.weekday() in days:
            return moment
    return None


def should_run(schedule: dict, now: datetime) -> datetime | None:
    moment = due_time(schedule, now)
    if moment is None or now - moment > CATCH_UP:
        return None
    last = schedule.get("last_run")
    if last and datetime.fromisoformat(last) >= moment:
        return None
    return moment


def tick(now: datetime | None = None) -> bool:
    """Start the scheduled scan if it is due. Returns True when a scan was started."""
    now = now or datetime.now()
    settings = inventory.load_settings()
    schedule = settings.get("schedule", {})
    moment = should_run(schedule, now)
    if moment is None:
        return False
    ids = [d["id"] for d in inventory.load_devices()]
    if not ids or scan.start(ids, trigger="schedule") is None:
        return False  # nothing to scan, or a scan is already running (retry next tick)
    settings = inventory.load_settings()
    settings.setdefault("schedule", {})["last_run"] = now.replace(microsecond=0).isoformat()
    inventory.save_settings(settings)
    return True


def start_background(interval: int = 30) -> None:
    global _started
    if _started:
        return
    _started = True

    def loop():
        from . import changes  # late import: changes imports scan too
        while True:
            try:
                tick()
            except Exception:
                pass  # never let the scheduler thread die
            try:
                changes.tick()  # rescan on change (disabled unless configured)
            except Exception:
                pass  # SIEM unreachable: retried at the next interval
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True, name="lyss-scheduler").start()
