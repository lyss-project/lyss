# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""SIEM events: scan results as JSON events for Wazuh, Graylog, Elastic, Splunk or any syslog server.

After each scan LYSS can emit, per switch:
  scan               summary: level achieved, pass / fail / unknown counts
  finding            one per failed control (verdict, evidence line, ISO 27001 / NIST mappings)
  regression, fixed  controls that started failing / passing since the previous scan
  collection_error   the switch could not be collected
and once per scan:
  discovered         new switches seen on the network but not managed yet

Every event is one JSON object {"lyss": {...}} (fields lyss.event, lyss.device, lyss.control...).
Two outputs, usable together:
  - syslog over UDP or TCP (RFC 3164 header, program "lyss", JSON message): Wazuh decodes it with
    its built-in JSON decoder; integrations/wazuh/ has ready rules;
  - a JSON-lines file (one event per line) for a local agent: Wazuh <localfile> with
    <log_format>json</log_format>, Filebeat, Fluent Bit...
Evidence lines are already redacted by the engine (no password hashes, keys or communities).
Disabled until configured in Settings.
"""

import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from . import PROJECT_NAME, __version__, inventory

FACILITY = 16  # local0
SEVERITY = {"collection_error": 3, "regression": 4, "finding": 4, "discovered": 5,
            "scan": 6, "fixed": 6}
MAX_EVIDENCE = 300  # characters of the first evidence line kept in a finding event


def settings() -> dict:
    return inventory.load_settings().get("siem", {})


def build(job: dict, changes: dict, discovered: int, cfg: dict | None = None) -> list[dict]:
    """The events of a finished scan job (see the module docstring)."""
    from . import sites  # late import: sites imports the inventory too
    cfg = cfg or settings()
    all_sites = sites.load()
    devices = {d["id"]: d for d in inventory.load_devices()}
    findings_mode = cfg.get("findings", "all")  # all | changes
    events = []
    for device_id, item in job.get("items", {}).items():
        device = devices.get(device_id, {"id": device_id})
        base = {"device": device_id, "host": device.get("host", ""), "site": sites.of(device, all_sites) or ""}
        if item.get("status") == "error":
            events.append({**base, "event": "collection_error", "message": item.get("message", "")[:300]})
            continue
        if item.get("status") != "done":
            continue
        result = inventory.load_result(device_id) or {"vendor": device.get("vendor", "")}
        events += result_events(base, result, changes.get(device_id, {}), findings_mode, job.get("trigger", ""))
    if discovered:
        events.append({"event": "discovered", "count": discovered})
    return wrap(events)


def result_events(base: dict, result: dict, change: dict, findings_mode: str = "all", trigger: str = "") -> list[dict]:
    """scan + finding (+ regression / fixed) events of one assessed device. base: device, host, site."""
    summary = result.get("summary", {})
    out = [{**base, "event": "scan", "vendor": result.get("vendor", ""), "model": result.get("model", ""),
            "firmware": result.get("firmware", ""), "level": summary.get("achieved_level", 0),
            "pass": summary.get("pass", 0), "fail": summary.get("fail", 0), "unknown": summary.get("unknown", 0),
            "trigger": trigger, "spec_version": result.get("spec_version", "")}]
    if result.get("source"):
        out[0]["source"] = result["source"]
    titles = {f["control_id"]: f for f in result.get("findings", [])}
    if findings_mode == "all":
        out += [{**base, **_control(f), "event": "finding", "verdict": "fail",
                 "evidence": (f.get("evidence") or [""])[0][:MAX_EVIDENCE]}
                for f in result.get("findings", []) if f["verdict"] == "fail"]
    for kind, key in (("regression", "new_fail"), ("fixed", "fixed")):
        out += [{**base, **_control(titles.get(c, {"control_id": c})), "event": kind} for c in change.get(key, [])]
    return out


def wrap(events: list[dict]) -> list[dict]:
    """Final form {"lyss": {...}} with the time and the LYSS version."""
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return [{"lyss": {**e, "time": stamp, "version": __version__}} for e in events]


def _control(f: dict) -> dict:
    maps = f.get("mappings") or {}
    return {"control": f["control_id"], "control_level": f.get("level", 0), "title": f.get("title", ""),
            "iso27001": ",".join(maps.get("iso27001_2022", [])), "nist": ",".join(maps.get("nist_800_53r5", []))}


def syslog_line(event: dict, hostname: str | None = None) -> str:
    """RFC 3164 line: <PRI>Mmm dd hh:mm:ss host lyss: {json}"""
    pri = FACILITY * 8 + SEVERITY.get(event["lyss"]["event"], 6)
    now = time.localtime()
    stamp = time.strftime("%b ", now) + f"{now.tm_mday:2d}" + time.strftime(" %H:%M:%S", now)
    host = (hostname or socket.gethostname()).split(".")[0] or "-"
    return f"<{pri}>{stamp} {host} {PROJECT_NAME.lower()}: " + json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def send(events: list[dict], cfg: dict | None = None) -> int:
    """Send events to the configured outputs. Returns the number of events sent."""
    cfg = cfg or settings()
    if not events:
        return 0
    if cfg.get("host"):
        port = int(cfg.get("port") or 514)
        lines = [syslog_line(e) for e in events]
        if cfg.get("protocol", "udp") == "tcp":
            with socket.create_connection((cfg["host"], port), timeout=10) as s:
                s.sendall("".join(line + "\n" for line in lines).encode("utf-8"))
        else:
            with socket.socket(socket.AF_INET6 if ":" in cfg["host"] else socket.AF_INET, socket.SOCK_DGRAM) as s:
                for line in lines:
                    s.sendto(line.encode("utf-8")[:8000], (cfg["host"], port))
    if cfg.get("file"):
        path = Path(cfg["file"])
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")
    return len(events)


def test_event() -> dict:
    return {"lyss": {"event": "test", "message": f"Test event from {PROJECT_NAME} {__version__}",
                     "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "version": __version__}}
