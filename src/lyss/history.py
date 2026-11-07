# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Configuration archive, backup attestations and scan history.

- Every collection archives the running-config (a new version only when it changed) with the
  trigger that produced it ("schedule", "manual", "cli"): evidence for LYSS-BKP-001.
- Administrators can attest an external backup system (e.g. Oxidized, RANCID) per device; an
  attestation expires after ATTESTATION_DAYS and must then be renewed.
- Every audit appends a summary line to the device history: trends and regression alerts.
- Archived configurations are encrypted at rest (sealed.py). Settings > Data protection can limit
  how long versions and scan history are kept (retention_days, 0 = no time limit); the version
  that is the current backup is never removed.
"""

import difflib
import hashlib
import json
import os
from datetime import datetime, timedelta

from . import inventory, locks, sealed
from .engine import redact_lines

KEEP_INDEX = 200          # collections remembered per device
ATTESTATION_DAYS = 90
AUTOMATIC = {"schedule"}  # triggers that count as automatic backups


def _dir(device_id: str):
    if not inventory.valid_id(device_id):
        raise ValueError(f"invalid device id {device_id!r}")
    return inventory.PRIVATE / "history" / device_id


def _now() -> datetime:
    return datetime.now().replace(microsecond=0)


def retention_days() -> int:
    try:
        return max(0, int(inventory.load_settings().get("retention_days") or 0))
    except (TypeError, ValueError):
        return 0


def _cutoff(now: datetime) -> str | None:
    days = retention_days()
    return (now - timedelta(days=days)).isoformat() if days else None


# ---------------- configuration archive ----------------

def load_index(device_id: str) -> list[dict]:
    return inventory._read(_dir(device_id) / "configs.json", [])


KEEP_VERSIONS = 3   # distinct versions always kept, whatever their age (e.g. the good configuration
                    # of a switch that was offline for longer than the retention, then reset)


def archive_config(device_id: str, config: str, trigger: str) -> dict:
    """Record a collected configuration. The file is only written when its content changed.
    Locked per switch across processes (web interface and "lyss collect --scheduled")."""
    folder = _dir(device_id) / "configs"
    folder.mkdir(parents=True, exist_ok=True)
    with locks.file_lock(_dir(device_id) / "configs.json"):
        digest = hashlib.sha256(config.encode("utf-8")).hexdigest()
        old_index = load_index(device_id)
        last = old_index[-1] if old_index else None
        changed = last is None or last["sha256"] != digest
        now = _now()
        name = f"{now:%Y%m%d-%H%M%S}.cfg" if changed else last["file"]
        if changed or not (folder / name).exists():   # also rewrites a version file that went missing
            sealed.write_text(folder / name, config)
        entry = {"ts": now.isoformat(), "sha256": digest, "file": name, "changed": changed or last is None,
                 "trigger": trigger}
        index = (old_index + [entry])[-KEEP_INDEX:]
        cutoff = _cutoff(now)
        if cutoff:
            recent_versions = {e["file"] for e in index if e["changed"]}
            recent_versions = set(sorted(recent_versions)[-KEEP_VERSIONS:]) | {entry["file"]}
            index = [e for e in index if e["ts"] >= cutoff or e is entry
                     or (e["changed"] and e["file"] in recent_versions)]
        if not any(e["changed"] and e["file"] == entry["file"] for e in index):
            # the current version was archived long ago: keep its "changed" entry so it stays listed
            first = next((e for e in old_index if e["changed"] and e["file"] == entry["file"]), None)
            if first:
                index.insert(0, first)
        keep = {e["file"] for e in index}
        inventory._write(_dir(device_id) / "configs.json", index)
        # only files this run dropped from the index: never a version written by another process
        for dropped in {e["file"] for e in old_index} - keep:
            (folder / dropped).unlink(missing_ok=True)
    return entry


def versions(device_id: str) -> list[dict]:
    """Distinct stored configuration versions, newest first."""
    return [e for e in reversed(load_index(device_id)) if e["changed"]]


def read_version(device_id: str, file: str | None = None) -> str:
    """Full text of a stored version (default: the newest), decrypted. Not redacted: for the
    administrator's own use (restore), never sent to the browser."""
    names = [v["file"] for v in versions(device_id)]
    name = file or (names[0] if names else None)
    if name is None or name not in names:
        raise FileNotFoundError(file or f"no stored configuration for {device_id}")
    return sealed.read_text(_dir(device_id) / "configs" / name)


def config_diff(device_id: str, new_file: str, old_file: str | None = None) -> list[str]:
    """Redacted unified diff between a stored version and the previous one (or old_file)."""
    vs = [v["file"] for v in reversed(versions(device_id))]  # oldest first
    if new_file not in vs:
        raise FileNotFoundError(new_file)
    if old_file is None:
        i = vs.index(new_file)
        old_file = vs[i - 1] if i else None
    folder = _dir(device_id) / "configs"
    new = sealed.read_text(folder / new_file).splitlines()
    old = sealed.read_text(folder / old_file).splitlines() if old_file else []
    diff = difflib.unified_diff(old, new, old_file or "(none)", new_file, lineterm="", n=2)
    return redact_lines(list(diff))


# ---------------- backup attestations ----------------

def _attestations_file():
    return inventory.PRIVATE / "attestations.json"


def attest(device_id: str, reference: str) -> dict:
    data = inventory._read(_attestations_file(), {})
    now = _now()
    data[device_id] = {"reference": reference.strip()[:200], "date": now.isoformat(),
                       "expires": (now + timedelta(days=ATTESTATION_DAYS)).isoformat()}
    inventory._write(_attestations_file(), data)
    return data[device_id]


def revoke_attestation(device_id: str) -> None:
    data = inventory._read(_attestations_file(), {})
    data.pop(device_id, None)
    inventory._write(_attestations_file(), data)


def backup_status(device_id: str) -> dict:
    """Evidence for LYSS-BKP-001: last collection, last automatic one, valid attestation."""
    index = load_index(device_id)
    automatic = [e for e in index if e["trigger"] in AUTOMATIC]
    att = inventory._read(_attestations_file(), {}).get(device_id)
    if att and att["expires"] < _now().isoformat():
        att = {**att, "expired": True}
    return {
        "last": index[-1]["ts"] if index else None,
        "last_automatic": automatic[-1]["ts"] if automatic else None,
        "versions": sum(1 for e in index if e["changed"]),
        "attestation": att,
    }


# ---------------- scan history ----------------

def record_scan(device_id: str, result: dict, trigger: str) -> None:
    line = {
        "ts": result["scanned_at"], "trigger": trigger,
        "level": result["summary"]["achieved_level"],
        "pass": result["summary"]["pass"], "fail": result["summary"]["fail"],
        "unknown": result["summary"]["unknown"],
        "verdicts": {f["control_id"]: f["verdict"] for f in result["findings"]},
    }
    path = _dir(device_id) / "scans.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")
    cutoff = _cutoff(_now())
    if cutoff:   # retention: drop scan lines older than the limit (the newest one is always kept)
        with locks.file_lock(path):
            lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

            def recent(l: str) -> bool:
                try:
                    return json.loads(l)["ts"] >= cutoff
                except (ValueError, KeyError, TypeError):
                    return False   # a torn line is dropped, never fatal for later scans
            kept = [l for l in lines[:-1] if recent(l)] + lines[-1:]
            if len(kept) < len(lines):
                tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
                tmp.write_text("\n".join(kept) + "\n", encoding="utf-8")
                locks.replace(tmp, path)


def load_scans(device_id: str, limit: int = 90) -> list[dict]:
    path = _dir(device_id) / "scans.jsonl"
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue   # a torn line (crash during a write) is skipped
    return out


def changes(previous: dict | None, current: dict) -> dict:
    """Controls that started failing (regressions) or got fixed between two scans."""
    if not previous:
        return {"new_fail": [], "fixed": []}
    before, after = previous["verdicts"], current["verdicts"]
    return {
        "new_fail": sorted(c for c, v in after.items() if v == "fail" and before.get(c) != "fail"),
        "fixed": sorted(c for c, v in after.items() if v == "pass" and before.get(c) == "fail"),
    }


def fleet_trend(device_ids: list[str], limit: int = 30) -> list[dict]:
    """Total failed controls per day across the fleet (last scan of each device that day)."""
    per_day: dict[str, dict[str, int]] = {}
    for device_id in device_ids:
        for scan in load_scans(device_id, 400):
            per_day.setdefault(scan["ts"][:10], {})[device_id] = scan["fail"]
    days = sorted(per_day)[-limit:]
    return [{"day": d, "fail": sum(per_day[d].values()), "devices": len(per_day[d])} for d in days]
