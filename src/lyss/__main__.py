# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Command line.

  python -m lyss audit --vendor <adapter> <file-or-folder>   assess saved configurations
  python -m lyss collect [--only id ...]                     collect + audit inventory devices
  python -m lyss oxidized --url http://oxidized:8888         assess the configs backed up by Oxidized
  python -m lyss import-legacy <inventory.csv> <cred-dir>    import devices + PowerShell cred files
  python -m lyss ui [--port 8765]                            start the local web interface
  python -m lyss sim [--lab demo] [--base-port 2201]         simulated switches over SSH (127.0.0.1)
  python -m lyss demo [--port 8766] [--reset]                web interface on the simulated demo lab
"""

import argparse
import csv
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import PROJECT_LONG_NAME, PROJECT_NAME, __version__
from .engine import audit, conformance, load_spec

ICONS = {"pass": "PASS", "fail": "FAIL", "unknown": "????", "not_applicable": "n/a "}


def print_text(name: str, findings, summary) -> None:
    print(f"\n=== {name}  ->  {PROJECT_NAME} Level {summary['achieved_level']} "
          f"(pass {summary['pass']}, fail {summary['fail']}, unknown {summary['unknown']})")
    for f in findings:
        print(f"  [{ICONS[f.verdict]}] {f.control_id}  {f.title}")
        for e in f.evidence[:3]:
            print(f"           evidence: {e}")
        if f.note:
            print(f"           note: {f.note}")
        if f.remediation:
            for line in f.remediation.splitlines():
                print(f"           fix> {line}")


def cmd_audit(args) -> int:
    # a device = <name>.cfg (configuration) + optional <name>.state.txt (collected device state)
    files = sorted(args.path.glob("*.cfg")) if args.path.is_dir() else [args.path]
    results = []
    for path in files:
        state_file = path.with_name(path.stem + ".state.txt")
        state_text = state_file.read_text(encoding="utf-8", errors="replace") if state_file.exists() else ""
        findings = audit(path.read_text(encoding="utf-8", errors="replace"), args.vendor, args.level, state_text)
        summary = conformance(findings)
        if args.json:
            results.append({"device": path.name, "vendor": args.vendor,
                            "summary": summary, "findings": [asdict(f) for f in findings]})
        else:
            print_text(path.name, findings, summary)

    if args.json:
        json.dump({"tool": PROJECT_NAME, "version": __version__,
                   "spec_version": load_spec()["spec_version"], "results": results},
                  sys.stdout, indent=2, ensure_ascii=False)
    return 0


def cmd_collect(args) -> int:
    from . import inventory, scan

    ids = args.only or [d["id"] for d in inventory.load_devices()]
    started = time.monotonic()
    # --scheduled: run by cron / Task Scheduler, counts as an automatic backup (LYSS-BKP-001)
    if not scan.start(ids, trigger="schedule" if args.scheduled else "cli"):
        print("a scan is already running")
        return 1
    shown = {}
    while True:
        job = scan.current_job()
        for device_id, item in job["items"].items():
            if shown.get(device_id) != item["status"] and item["status"] in ("done", "error"):
                print(f"{device_id:18} {item['status']:6} {item['message']}")
            shown[device_id] = item["status"]
        if job["finished"]:
            break
        time.sleep(0.5)
    for notice in job.get("notices", []):
        print(notice)
    print(f"total {time.monotonic() - started:.0f}s")
    return 1 if any(i["status"] == "error" for i in job["items"].values()) else 0


def cmd_oxidized(args) -> int:
    """Assess the configurations backed up by Oxidized (REST API), without connecting to the switches."""
    import os

    from . import events, oxidized
    password = os.environ.get("LYSS_OXIDIZED_PASSWORD", "")  # never on the command line
    with oxidized.client(args.url, args.user or "", password, not args.insecure) as http:
        results, skipped = oxidized.assess_all(http, args.level, args.only)
    if args.json:
        json.dump({"tool": PROJECT_NAME, "version": __version__, "source": "oxidized",
                   "spec_version": load_spec()["spec_version"], "results": results, "skipped": skipped},
                  sys.stdout, indent=2, ensure_ascii=False)
    else:
        from .engine import Finding
        for r in results:
            print_text(f"{r['device']} ({r['host']}, {r['vendor']}, from Oxidized)",
                       [Finding(**f) for f in r["findings"]], r["summary"])
        for s in skipped:
            print(f"\n--- {s['device']}: skipped, {s['reason']}")
        print(f"\n{len(results)} switch(es) assessed from Oxidized, {len(skipped)} skipped.")
    if args.events:
        cfg = events.settings()
        if not (cfg.get("host") or cfg.get("file")):
            print("SIEM events: configure a syslog server or an events file in Settings first.", file=sys.stderr)
            return 2
        sent = events.send(events.wrap([e for r in results for e in events.result_events(
            {"device": r["device"], "host": r["host"], "site": r["group"]}, r, {}, cfg.get("findings", "all"),
            "oxidized")]), cfg)
        print(f"{sent} event(s) sent to the SIEM.", file=sys.stderr)
    return 0


def cmd_import_legacy(args) -> int:
    """Devices from a CSV (name,vendor,ip,cred) + PowerShell Export-Clixml credential files.
    The DPAPI-protected password is copied as-is: it is never decrypted during the import."""
    from . import inventory, vault

    devices = inventory.load_devices()
    for row in csv.DictReader(args.csv.open(encoding="utf-8")):
        user, protected = vault.read_ps_credential(args.cred_dir / row["cred"])
        record = {"id": row["name"], "host": row["ip"], "port": 22, "vendor": row["vendor"],
                  "username": user, "via_jump": args.via_jump, "secret": protected}
        devices = [d for d in devices if d["id"] != record["id"]] + [record]
        print(f"imported {row['name']}")
    inventory._write(inventory.DEVICES_FILE, sorted(devices, key=lambda d: d["id"]))
    return 0


def cmd_ui(args) -> int:
    import os

    import uvicorn

    from . import scheduler
    from .web.app import app
    if args.host not in ("127.0.0.1", "localhost", "::1") and os.environ.get("LYSS_ALLOW_REMOTE") != "1":
        # inside a container the UI must listen on all interfaces; publish the port on 127.0.0.1
        # only, or put an HTTPS reverse proxy in front: the UI itself speaks plain HTTP
        print("Refusing to listen on a non-local address without LYSS_ALLOW_REMOTE=1.")
        return 2
    scheduler.start_background()
    print(f"{PROJECT_LONG_NAME} UI on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", server_header=False)
    return 0


def cmd_sim(args) -> int:
    import tempfile

    from .sim import Simulator, load_lab
    lab = load_lab(args.lab)
    keys = args.keys_dir or Path(tempfile.gettempdir()) / "lyss-sim-keys" / lab.name
    sim = Simulator(lab, base_port=args.base_port, keys_dir=keys)
    try:
        sim.start()
    except OSError as exc:
        print(f"Cannot open the simulator ports from {args.base_port}: {exc}")
        return 2
    print(f"{PROJECT_NAME} simulator - lab '{lab.name}' ({lab.organization}, fictitious devices)")
    for d in sim.describe():
        print(f"  {d['id']:<12} {d['platform']:<12} {d['hostname']:<14} {d['model']:<16} 127.0.0.1:{d['port']}")
    print(f"  SSH login: {lab.credentials['username']} / {lab.credentials['password']}   (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sim.stop()
    return 0


def cmd_demo(args) -> int:
    from .sim import demo
    try:
        return demo.run(args.lab, args.data_dir, args.port, args.base_port, args.reset, args.open)
    except ValueError as exc:
        print(exc)
        return 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="lyss", description=f"{PROJECT_LONG_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="assess saved configuration files")
    a.add_argument("--vendor", required=True, help="adapter name, e.g. cisco_ios, cisco_sb, hp_procurve, mikrotik, sonic")
    a.add_argument("--level", type=int, default=1, help="highest level to assess (default 1)")
    a.add_argument("--json", action="store_true", help="output JSON instead of text")
    a.add_argument("path", type=Path)
    a.set_defaults(func=cmd_audit)

    c = sub.add_parser("collect", help="collect and audit inventory devices (read-only)")
    c.add_argument("--only", nargs="*", help="device ids (default: all)")
    c.add_argument("--scheduled", action="store_true",
                   help="run from cron / Task Scheduler: counts as an automatic configuration backup")
    c.set_defaults(func=cmd_collect)

    o = sub.add_parser("oxidized", help="assess the configurations backed up by Oxidized (no SSH to the switches)")
    o.add_argument("--url", required=True, help="Oxidized REST API, e.g. http://oxidized:8888")
    o.add_argument("--user", help="HTTP basic auth user (password in LYSS_OXIDIZED_PASSWORD)")
    o.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    o.add_argument("--level", type=int, default=2, help="highest level to assess (default 2)")
    o.add_argument("--only", nargs="*", help="node names (default: all supported nodes)")
    o.add_argument("--json", action="store_true", help="output JSON instead of text")
    o.add_argument("--events", action="store_true", help="also send SIEM events (Settings > SIEM events)")
    o.set_defaults(func=cmd_oxidized)

    i = sub.add_parser("import-legacy", help="import devices from CSV + PowerShell cred files")
    i.add_argument("csv", type=Path)
    i.add_argument("cred_dir", type=Path)
    i.add_argument("--via-jump", action="store_true", help="reach these devices through the jump host")
    i.set_defaults(func=cmd_import_legacy)

    u = sub.add_parser("ui", help="start the local web interface")
    u.add_argument("--port", type=int, default=8765)
    u.add_argument("--host", default="127.0.0.1", help="listen address (non-local needs LYSS_ALLOW_REMOTE=1)")
    u.set_defaults(func=cmd_ui)

    s = sub.add_parser("sim", help="run simulated switches (fictitious lab) over SSH on 127.0.0.1")
    s.add_argument("--lab", default="demo", help="lab name or folder (default: demo)")
    s.add_argument("--base-port", type=int, default=2201, help="SSH port of the first switch (default 2201)")
    s.add_argument("--keys-dir", type=Path, help="where the simulated host keys are kept")
    s.set_defaults(func=cmd_sim)

    d = sub.add_parser("demo", help="web interface on the simulated demo lab (separate data directory)")
    d.add_argument("--lab", default="demo")
    d.add_argument("--port", type=int, default=8766, help="web interface port (default 8766)")
    d.add_argument("--base-port", type=int, default=2201, help="SSH port of the first simulated switch")
    d.add_argument("--data-dir", type=Path, help="demo data directory (default: <temp>/lyss-demo)")
    d.add_argument("--reset", action="store_true", help="start again from an empty demo directory")
    d.add_argument("--open", action="store_true", help="open the browser")
    d.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
