# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Scan jobs: collect devices, archive their configuration, audit them, keep the history,
then notify (e-mail alerts, CISO Assistant evidence) when those integrations are enabled.
One job at a time."""

import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime

from . import collector, discovery, health, history, inventory, notify
from .config import parse
from .engine import audit, conformance, extract_facts, load_adapter, load_spec

MAX_LEVEL = 2           # Level 3 (Advanced) only when enabled in Settings > Assessment
TRIGGERS = ("manual", "schedule", "cli", "change")  # change: rescan after a SIEM change alert (changes.py)
_lock = threading.Lock()
_job: dict | None = None


def current_job() -> dict | None:
    with _lock:
        return None if _job is None else {**_job, "items": {k: dict(v) for k, v in _job["items"].items()}}


def audit_device(device: dict, trigger: str = "manual", archive: bool = True) -> dict:
    """Audit the last collected configuration/state of a device and store the result.
    archive=True records the configuration as a backup version (done once per collection)."""
    cfg_path, state_path = collector.config_paths(device)
    config = cfg_path.read_text(encoding="utf-8", errors="replace")
    state = state_path.read_text(encoding="utf-8", errors="replace") if state_path.exists() else ""
    if archive:
        history.archive_config(device["id"], config, trigger)
    context = {"backup": history.backup_status(device["id"])}
    max_level = 3 if inventory.load_settings().get("level3") else MAX_LEVEL
    findings = audit(config, device["vendor"], max_level, state, context)
    facts = extract_facts(parse(config, state), load_adapter(device["vendor"]))
    result = {
        "device": device["id"],
        "vendor": device["vendor"],
        "model": facts.get("model", ""),
        "firmware": facts.get("version", ""),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "trigger": trigger,
        "spec_version": load_spec()["spec_version"],
        "summary": conformance(findings),
        "findings": [asdict(f) for f in findings],
    }
    previous = (history.load_scans(device["id"], 1) or [None])[-1]
    inventory.save_result(device["id"], result)
    history.record_scan(device["id"], result, trigger)
    result["changes"] = history.changes(previous, history.load_scans(device["id"], 1)[-1])
    return result


def start(device_ids: list[str], trigger: str = "manual") -> str | None:
    """Start a scan in the background. Returns the job id, or None if one is already running."""
    global _job
    if trigger not in TRIGGERS:
        raise ValueError(f"unknown trigger {trigger}")
    devices = [d for d in inventory.load_devices() if d["id"] in device_ids]
    from . import firmware, remediate  # late import: both import scan
    if remediate.running() or firmware.running():
        return None  # never collect while fixes or a firmware upgrade are in progress
    with _lock:
        if _job and not _job["finished"]:
            return None
        _job = {
            "id": uuid.uuid4().hex[:8],
            "trigger": trigger,
            "started": time.time(),
            "finished": None,
            "items": {d["id"]: {"status": "queued", "message": ""} for d in devices},
        }
        job_id = _job["id"]

    def update(device_id, status, message):
        with _lock:
            _job["items"][device_id] = {"status": status, "message": message}

    def run():
        collector.collect_many(devices, inventory.load_settings().get("jump", {}), update)
        changes = {}
        for device in devices:
            if _job["items"][device["id"]]["status"] != "collected":
                continue
            device = inventory.get_device(device["id"]) or device  # platform may have been auto-detected
            try:
                result = audit_device(device, trigger)
                changes[device["id"]] = result["changes"]
                level = result["summary"]["achieved_level"]
                update(device["id"], "done", f"{_job['items'][device['id']]['message']}, level {level}")
            except Exception as exc:
                update(device["id"], "error", f"audit failed: {exc}"[:300])
        # every scan also looks for neighbouring switches that are not managed yet
        try:
            discovered = discovery.from_neighbors()
        except Exception:
            discovered = 0
        with _lock:
            _job["discovered"] = discovered
        # integrations (disabled unless configured in Settings); their errors never break a scan
        notices = notify.after_scan(current_job(), changes, discovered)
        # LYSS's own health: last finished scan, and the external heartbeat after scheduled scans
        try:
            health.record(current_job())
            ping = health.heartbeat(current_job())
            if ping:
                notices.append(ping)
        except Exception as exc:
            notices.append(f"Health record failed: {type(exc).__name__}")
        with _lock:
            _job["notices"] = notices
            _job["finished"] = time.time()

    threading.Thread(target=run, daemon=True).start()
    return job_id
