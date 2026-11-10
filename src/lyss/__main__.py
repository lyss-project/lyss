# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Command line.

  python -m lyss audit --vendor <adapter> <file-or-folder>   assess saved configurations (offline)
  python -m lyss collect [--only id ...]                     collect + audit inventory devices
  python -m lyss oxidized --url http://oxidized:8888         assess the configs backed up by Oxidized
  python -m lyss data status|seal|unseal|config <device>     encryption at rest, stored configurations
  python -m lyss probe <ip> ... | --targets-file F             management reachability test from this PC
  python -m lyss reachability import|list|targets            use probe results in the assessment
  python -m lyss import-legacy <inventory.csv> <cred-dir>    import devices + PowerShell cred files
  python -m lyss ui [--port 8765]                            start the local web interface
  python -m lyss sim [--lab demo] [--base-port 2201]         simulated switches over SSH (127.0.0.1)
  python -m lyss demo [--port 8766] [--reset]                web interface on the simulated demo lab
"""

import argparse
import csv
import fnmatch
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import PROJECT_LONG_NAME, PROJECT_NAME, __version__, ci
from .engine import ADAPTER_DIR, audit, conformance, detect_vendor, load_spec

def yaml_error():
    import yaml
    return yaml.YAMLError


ICONS = {"pass": "PASS", "fail": "FAIL", "unknown": "????", "not_applicable": "n/a "}


def print_text(name: str, findings, summary, accepted: dict | None = None) -> None:
    accepted = accepted or {}
    print(f"\n=== {name}  ->  {PROJECT_NAME} Level {summary['achieved_level']} "
          f"(pass {summary['pass']}, fail {summary['fail']}, unknown {summary['unknown']})")
    for f in findings:
        print(f"  [{ICONS[f.verdict]}] {f.control_id}  {f.title}")
        if f.control_id in accepted:
            a = accepted[f.control_id]
            print(f"           accepted risk until {a['expires']} ({a['approved_by']}): {a['reason']}")
        for e in f.evidence[:3]:
            print(f"           evidence: {e}")
        if f.note:
            print(f"           note: {f.note}")
        if f.remediation:
            for line in f.remediation.splitlines():
                print(f"           fix> {line}")


CONFIG_SUFFIXES = (".cfg", ".conf", ".txt", ".rsc", ".json")


def config_files(path: Path, pattern: str | None = None, recursive: bool = False) -> list[Path]:
    """A file, or the saved configurations in a folder (Cisco/HP .cfg/.txt, RouterOS .rsc exports,
    SONiC .json); <name>.state.txt files hold optional device state, not configurations.
    pattern: a file name pattern instead of the suffixes ("*" for Oxidized git output, whose
    files have no suffix). Hidden files and folders (.git, ...) are always skipped."""
    if not path.is_dir():
        return [path]
    root = path.resolve()
    found = path.rglob("*") if recursive else path.iterdir()
    picked = []
    for p in found:
        if p.is_symlink() or not p.is_file() or p.name.endswith(".state.txt"):
            continue   # never follow a link: it could lead outside the audited folder (CI: a pull request)
        if any(part.startswith(".") for part in p.relative_to(path).parts):
            continue
        if not p.resolve().is_relative_to(root):
            continue
        if fnmatch.fnmatch(p.name, pattern) if pattern else p.suffix.lower() in CONFIG_SUFFIXES:
            picked.append(p)
    return sorted(picked, key=lambda p: p.as_posix())   # same order on every OS


MAX_CONFIG_BYTES = 20 * 1024 * 1024
MIN_CONFIG_LINES = 5     # with --require-level: fewer configuration lines is not a switch configuration


def _readable(path: Path) -> str:
    """Why a file is not read ("" if it can be): links, special files and very large files."""
    import stat
    if path.is_symlink():
        return "symbolic link, not followed"
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    if st.st_size > MAX_CONFIG_BYTES:
        return f"larger than {MAX_CONFIG_BYTES // (1024 * 1024)} MB"
    return ""


def _report_path(path: Path, root: Path | None) -> str:
    """The file's path for SARIF / Code Quality: relative to the repository root (default: the
    current folder), with "/" separators; just the file name if it is outside that root."""
    base = (root or Path.cwd()).resolve()
    try:
        return path.resolve().relative_to(base).as_posix()
    except ValueError:
        return path.name


def cmd_audit(args) -> int:
    # offline: a device = a saved configuration + optional <name>.state.txt (device state sections)
    if not args.path.exists():
        print(f"{args.path}: no such file or folder", file=sys.stderr)
        return 2
    absolute = args.path.absolute()
    if any(p.is_symlink() for p in (absolute, *absolute.parents)):
        # in CI, a pull request could turn the audited folder (or a folder above it) into a link
        print(f"{args.path}: goes through a symbolic link, not followed: give the real path", file=sys.stderr)
        return 2
    acceptances, used = [], set()
    if args.accepted_risks:
        from . import accepted
        try:
            acceptances = accepted.load(args.accepted_risks)
        except (OSError, ValueError, yaml_error()) as e:
            print(f"accepted risks: {e}", file=sys.stderr)
            return 2
    files = config_files(args.path, args.pattern, args.recursive)
    results, problems = [], []
    status = 0
    for path in files:
        name = path.relative_to(args.path).as_posix() if args.path.is_dir() else path.name
        refused = _readable(path)
        if refused:
            print(f"{name}: {refused}: skipped", file=sys.stderr)
            problems.append(f"{name}: {refused}")
            status = 2
            continue
        state_file = path.with_name(path.stem + ".state.txt")
        state_text = (state_file.read_text(encoding="utf-8", errors="replace")
                      if state_file.exists() and not _readable(state_file) else "")
        text = path.read_text(encoding="utf-8", errors="replace")
        vendor = detect_vendor(text) if args.vendor == "auto" else args.vendor
        if vendor is None:
            if args.skip_unrecognised:
                print(f"{name}: platform not recognised, skipped", file=sys.stderr)
            else:
                print(f"{name}: platform not recognised, give it with --vendor", file=sys.stderr)
                problems.append(f"{name}: platform not recognised")
                status = 2
            continue
        from .config import parse, state_problems, structure_problems
        repeated = state_problems(state_text)
        if repeated:
            # a hand-made state file in which a section appears twice: text inside one command's
            # output may imitate a header; refused rather than read with a guess
            print(f"{name}: device state with repeated sections ({', '.join(repeated[:3])}): "
                  "save each command once", file=sys.stderr)
            problems.append(f"{name}: device state with repeated sections")
            status = 2
            continue
        if args.require_level and len(parse(text, "", vendor).lines) < MIN_CONFIG_LINES:
            # the CI gate never vouches for an (almost) empty file
            print(f"{name}: too short to be a switch configuration", file=sys.stderr)
            problems.append(f"{name}: too short to be a switch configuration")
            status = 2
            continue
        odd = structure_problems(text, vendor)
        if odd:
            # not a configuration printed by the device: a line outside its block could hide a failure
            print(f"{name}: not as the switch prints it, {len(odd)} block command(s) not indented "
                  f"(e.g. {odd[0]!r}): use the device's own output", file=sys.stderr)
            problems.append(f"{name}: block commands not indented, e.g. {odd[0]!r}")
            status = 2
            continue
        findings = audit(text, vendor, args.level, state_text)
        summary = conformance(findings)
        rows = [asdict(f) for f in findings]
        for row in rows:
            if row["verdict"] == "fail":
                row["line"] = ci.locate(text, row["evidence"])   # SARIF / Code Quality: where to show it
        if acceptances:
            from . import accepted
            for note in accepted.apply(name, rows, acceptances, used):
                print(note, file=sys.stderr)
                problems.append(note)
        results.append({"device": name, "vendor": vendor, "file": _report_path(path, args.report_root),
                        "summary": summary, "findings": rows})
        if not args.json:
            print_text(f"{name} ({vendor})" if args.vendor == "auto" else name, findings, summary,
                       {r["control_id"]: r["accepted"] for r in rows if r.get("accepted")})

    if acceptances:
        from . import accepted
        for note in accepted.unused(acceptances, used):
            print(note, file=sys.stderr)
            problems.append(note)
    spec_version = load_spec()["spec_version"]
    document = {"tool": PROJECT_NAME, "version": __version__, "spec_version": spec_version, "results": results}
    if args.json:
        json.dump(document, sys.stdout, indent=2, ensure_ascii=False)
    if args.json_file:
        args.json_file.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.sarif:
        args.sarif.write_text(json.dumps(ci.sarif(results, load_spec(), lambda r: r["file"]), indent=2,
                                         ensure_ascii=False), encoding="utf-8")
    if args.codequality:
        args.codequality.write_text(json.dumps(ci.codequality(results, lambda r: r["file"]), indent=2,
                                               ensure_ascii=False), encoding="utf-8")
    bad = ci.failing(results, args.require_level)
    if args.require_level and not results:
        problems.append("no switch configuration found")
        status = 2
    if args.summary:   # appended: GITHUB_STEP_SUMMARY is shared by every step of the job
        with args.summary.open("a", encoding="utf-8") as out:
            out.write(ci.summary_markdown(results, spec_version, args.level, args.require_level, problems))
    if bad:
        print(f"{len(bad)} configuration(s) with a failed control up to Level {args.require_level}: "
              + ", ".join(r["device"] for r in bad[:10]) + (" ..." if len(bad) > 10 else ""), file=sys.stderr)
        status = max(status, 1)
    return status


REFERENCES = (("iso27001_2022", "ISO/IEC 27001:2022", str), ("nist_800_53r5", "NIST SP 800-53 r5", str),
              ("cis_v8", "CIS Controls v8", str), ("nis2_art21", "NIS2 Art.", lambda v: f"21(2)({v})"))


def cmd_explain(args) -> int:
    """A control of the specification, offline: requirement, rationale, test procedure, references,
    and with --vendor what the adapter checks and how to fix it."""
    import textwrap

    from .engine import load_adapter
    spec = load_spec()
    controls = spec["controls"]
    if not args.control:
        for c in controls:
            print(f"{c['id']:15} L{c['level']}  {c['title']}")
        return 0
    wanted = args.control.strip().upper()
    wanted = wanted if wanted.startswith("LYSS-") else f"LYSS-{wanted}"
    control = next((c for c in controls if c["id"] == wanted), None)
    if control is None:
        print(f"{args.control}: no such control (lyss explain lists them all)", file=sys.stderr)
        return 2

    def para(label: str, text) -> None:
        if text:
            print(f"\n{label}")
            print(textwrap.fill(" ".join(str(text).split()), width=100, initial_indent="  ", subsequent_indent="  "))

    print(f"{control['id']}  Level {control['level']}  {control['title']}")
    para("Requirement", control.get("statement"))
    para("Rationale", control.get("rationale"))
    para("Test procedure", control.get("test_procedure"))
    para("Evidence", ", ".join(control.get("evidence") or []))
    mappings = control.get("mappings") or {}
    refs = [f"{name} {', '.join(fmt(v) for v in mappings[key])}" for key, name, fmt in REFERENCES if mappings.get(key)]
    para("References (informative)", "; ".join(refs))   # ASCII only: Windows consoles
    if args.vendor:
        check = load_adapter(args.vendor)["checks"].get(control["id"]) or {}
        para(f"On {args.vendor}", check.get("note") or "(no platform note)")
        if check.get("remediation"):
            print("\nFix")
            for line in check["remediation"].rstrip().splitlines():
                print(f"  {line}")
    print(f"\nSpecification {spec['spec_version']}. Full text: docs/LYSS-Specification.md, https://lyss.dev")
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


def cmd_data(args) -> int:
    """Encryption at rest of collected configurations, device state and results."""
    from . import history, inventory, sealed
    if args.action == "status":
        s = sealed.status()
        backend = "Windows DPAPI (this Windows user)" if s["backend"] == "dpapi" else "AES-256-GCM (master key)"
        print(f"encryption at rest: {'on' if s['enabled'] else 'off'} · {backend} · "
              f"{s['sealed']} encrypted file(s), {s['plain']} plain · data directory {inventory.PRIVATE}")
        days = history.retention_days()
        print(f"retention: {f'{days} days' if days else 'no time limit'} (configuration versions and scan history)")
        return 0
    if args.action == "seal":
        settings = inventory.load_settings()
        settings["encrypt_data"] = True
        inventory.save_settings(settings)
        print(f"{sealed.seal_existing()} file(s) encrypted; new files will be encrypted.")
        return 0
    if args.action == "unseal":
        if not args.yes:
            print("This writes every configuration and result back as PLAIN TEXT and turns encryption off.\n"
                  "Run again with --yes to confirm.", file=sys.stderr)
            return 2
        settings = inventory.load_settings()
        settings["encrypt_data"] = False
        inventory.save_settings(settings)
        print(f"{sealed.unseal_all()} file(s) decrypted; encryption is off for new files.")
        return 0
    # config: print a stored configuration (restore), or list the versions
    if not args.device or not inventory.get_device(args.device):
        print("give the id of a switch of the inventory", file=sys.stderr)
        return 2
    if args.list:
        for v in history.versions(args.device):
            print(f"{v['file']}  {v['ts'].replace('T', ' ')}  {v['trigger']}")
        return 0
    try:
        sys.stdout.write(history.read_version(args.device, args.version))
    except FileNotFoundError as exc:
        print(f"no such stored version: {exc}", file=sys.stderr)
        return 2
    return 0


def _read_list(path: Path) -> str:
    """A text file written by any shell: UTF-8 with or without BOM, or UTF-16 (Windows PowerShell 5.1 ">")."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def cmd_probe(args) -> int:
    """Management reachability probe, to run on a PC of the network to test (no LYSS data needed)."""
    from . import reachability
    targets = list(args.targets)
    if args.targets_file:
        try:
            targets += [l.split("#")[0].strip() for l in _read_list(args.targets_file).splitlines()]
        except (OSError, UnicodeDecodeError) as exc:
            print(f"cannot read {args.targets_file}: {exc}", file=sys.stderr)
            return 2
    targets = [t for t in targets if t]
    if not targets:
        print("give switch addresses, or --targets-file (one address per line)", file=sys.stderr)
        return 2
    ports = [int(p) for p in args.ports.split(",")] if args.ports else None
    try:
        report = reachability.probe(targets, ports, args.timeout, args.workers)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    opened = [r for r in report["results"] if r["state"] == "open"]
    for r in opened:
        print(f"OPEN   {r['target']:<40} TCP {r['port']:<5} {r['service']}")
    print(f"{len(report['results'])} test(s), {len(opened)} open, on {len({r['target'] for r in report['results']})} switch(es)")
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"written {args.out}: import it in LYSS (Reachability page, or lyss reachability import)")
    return 0


def cmd_reachability(args) -> int:
    from . import inventory, reachability
    if args.action == "targets":
        # the switch addresses only (no name, no credential): to copy to the PC that will probe;
        # switches added by host name are left out (the probe takes addresses only)
        hosts = [d["host"] for d in inventory.load_devices() if inventory.strict_ip(d.get("host", ""))]
        if args.out:
            args.out.write_text("\n".join(hosts) + "\n", encoding="utf-8")
            print(f"written {args.out}: {len(hosts)} address(es)")
        else:
            print("\n".join(hosts))
        return 0
    if args.action == "delete":
        if not args.file or not reachability.delete(str(args.file)):
            print("give the id of an import (lyss reachability list)", file=sys.stderr)
            return 2
        print("deleted; the next scan takes it into account")
        return 0
    if args.action == "list":
        for imp in reachability.load():
            s = reachability.summary(imp)
            print(f"{imp['id']}  {imp['date'][:16].replace('T', ' ')}  {imp['label']!r:30} "
                  f"{'authorised' if imp['authorized'] else 'NOT authorised'}  {s['open']} open port(s) on "
                  f"{s['open_switches']}/{s['targets']} switch(es)")
        return 0
    if not args.file:
        print("give the file written by lyss probe", file=sys.stderr)
        return 2
    try:
        if args.file.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("file too large")
        entry = reachability.import_report(json.loads(_read_list(args.file)), args.label or "", args.authorized)
    except (ValueError, OSError, UnicodeDecodeError, RecursionError) as exc:
        print(f"not imported: {exc}", file=sys.stderr)
        return 2
    s = reachability.summary(entry)
    print(f"imported {entry['id']}: {s['open']} open port(s) on {s['open_switches']} switch(es); "
          "the next scan (or a re-assessment) takes it into account")
    return 0


def cmd_import_legacy(args) -> int:
    """Devices from a CSV (name,vendor,ip,cred) + PowerShell Export-Clixml credential files.
    The DPAPI-protected password is copied as-is: it is never decrypted during the import."""
    from . import inventory, vault

    devices = inventory.load_devices()
    vendors = sorted(p.stem for p in ADAPTER_DIR.glob("*.yaml"))
    for row in csv.DictReader(args.csv.open(encoding="utf-8")):
        # ids and platforms become file names: same checks as the web form
        errors = [e for e in inventory.validate_device(
            {"id": row.get("name", ""), "host": row.get("ip", ""), "vendor": row.get("vendor", ""),
             "port": 22, "username": "x"}, vendors) if not e.startswith("Credential")]
        cred = Path(row.get("cred", "")).name
        if errors or not cred:
            print(f"skipped {row.get('name', '')!r}: {' '.join(errors) or 'no credential file'}", file=sys.stderr)
            continue
        user, protected = vault.read_ps_credential(args.cred_dir / cred)
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
    from . import inventory
    from .web import app as webapp
    if webapp.remote_mode() and inventory.load_settings().get("admin") is None:
        # whoever reaches the port first must not be able to claim the instance
        print(f"First start: setup token {webapp.SETUP_TOKEN} (asked when creating the administrator)")
    if webapp.remote_mode():
        print("Answers to the host names: " + ", ".join(sorted(webapp.allowed_hosts()))
              + " (add yours with LYSS_ALLOWED_HOSTS)")
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
    import os
    if os.name == "posix":
        os.umask(0o077)   # data files (settings with the admin hash, inventory, logs): owner only
    for stream in (sys.stdout, sys.stderr):
        try:   # a file name or evidence the console code page cannot show must not crash the audit
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(prog="lyss", description=f"{PROJECT_LONG_NAME} {__version__}")
    parser.add_argument("--version", action="version", version=f"{PROJECT_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="assess saved configuration files, offline (no connection to any device)")
    vendors = sorted(p.stem for p in ADAPTER_DIR.glob("*.yaml"))
    a.add_argument("--vendor", default="auto", choices=["auto", *vendors], metavar="VENDOR",
                   help=f"adapter name: {', '.join(vendors)}, "
                        "or auto (default: recognise each file from its format)")
    a.add_argument("--level", type=int, default=1, choices=(1, 2, 3), help="highest level to assess: 1, 2 or 3 (default 1)")
    a.add_argument("--json", action="store_true", help="output JSON instead of text")
    a.add_argument("--json-file", type=Path, help="also write the JSON results to this file")
    a.add_argument("--pattern", help='file name pattern in a folder, e.g. "*" for Oxidized git output '
                                     "(default: .cfg .conf .txt .rsc .json)")
    a.add_argument("--recursive", action="store_true", help="also look in subfolders (hidden ones are skipped)")
    a.add_argument("--skip-unrecognised", action="store_true",
                   help="skip files whose platform is not recognised instead of failing")
    a.add_argument("--require-level", type=int, choices=(1, 2, 3), metavar="LEVEL",
                   help="exit code 1 if any control of level 1..LEVEL fails (for CI; unknown verdicts, "
                        "such as backups a file cannot show, do not fail)")
    a.add_argument("--accepted-risks", type=Path, metavar="FILE",
                   help="YAML file of accepted risks (control, switches, reason, approved_by, expires): "
                        "shown next to the failure, never a pass; --require-level ignores them until they expire")
    a.add_argument("--sarif", type=Path, metavar="FILE",
                   help="also write failed controls as SARIF 2.1.0 (GitHub code scanning)")
    a.add_argument("--codequality", type=Path, metavar="FILE",
                   help="also write failed controls as a GitLab Code Quality report (merge request widget)")
    a.add_argument("--report-root", type=Path, metavar="DIR",
                   help="repository root that SARIF / Code Quality paths are relative to (default: current folder)")
    a.add_argument("--summary", type=Path, help="append a markdown summary to this file (CI job summary)")
    a.add_argument("path", type=Path)
    a.set_defaults(func=cmd_audit)

    ex = sub.add_parser("explain", help="explain a control (offline): requirement, test procedure, references, fix")
    ex.add_argument("control", nargs="?", help="control ID, e.g. LYSS-MGMT-001 or MGMT-001 (none: list all)")
    ex.add_argument("--vendor", choices=vendors, metavar="VENDOR", help="also show what this adapter checks and the fix")
    ex.set_defaults(func=cmd_explain)

    c = sub.add_parser("collect", help="collect and audit inventory devices (read-only)")
    c.add_argument("--only", nargs="*", help="device ids (default: all)")
    c.add_argument("--scheduled", action="store_true",
                   help="run from cron / Task Scheduler: counts as an automatic configuration backup")
    c.set_defaults(func=cmd_collect)

    o = sub.add_parser("oxidized", help="assess the configurations backed up by Oxidized (no SSH to the switches)")
    o.add_argument("--url", required=True, help="Oxidized REST API, e.g. http://oxidized:8888")
    o.add_argument("--user", help="HTTP basic auth user (password in LYSS_OXIDIZED_PASSWORD)")
    o.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    o.add_argument("--level", type=int, default=2, help="highest level to assess: 1, 2 or 3 (default 2)")
    o.add_argument("--only", nargs="*", help="node names (default: all supported nodes)")
    o.add_argument("--json", action="store_true", help="output JSON instead of text")
    o.add_argument("--events", action="store_true", help="also send SIEM events (Settings > SIEM events)")
    o.set_defaults(func=cmd_oxidized)

    dt = sub.add_parser("data", help="encryption at rest of configurations and results; print a stored configuration")
    dt.add_argument("action", choices=("status", "seal", "unseal", "config"),
                    help="status; seal: encrypt existing files; unseal: back to plain text (needs --yes); "
                         "config: print a stored configuration of DEVICE (for a restore)")
    dt.add_argument("device", nargs="?", help="switch id (config)")
    dt.add_argument("--version", help="stored version file name (config; default: the newest)")
    dt.add_argument("--list", action="store_true", help="list the stored versions (config)")
    dt.add_argument("--yes", action="store_true", help="confirm unseal")
    dt.set_defaults(func=cmd_data)

    pr = sub.add_parser("probe", help="test from this PC which switch management ports answer (TCP connect only)")
    pr.add_argument("targets", nargs="*", help="switch IP addresses")
    pr.add_argument("--targets-file", type=Path, help="file with one IP address per line (lyss reachability targets)")
    pr.add_argument("--ports", help="comma-separated TCP ports (default: the management ports of every platform)")
    pr.add_argument("--timeout", type=float, default=2.0, help="seconds per connection (default 2)")
    pr.add_argument("--workers", type=int, default=32, help="parallel connections (default 32, max 64)")
    pr.add_argument("--out", type=Path, default=Path("lyss-reachability.json"), help="result file")
    pr.set_defaults(func=cmd_probe)

    rc = sub.add_parser("reachability", help="probe results: import a file, list imports, or print the switch addresses")
    rc.add_argument("action", choices=("import", "list", "targets", "delete"))
    rc.add_argument("file", nargs="?", type=Path, help="file written by lyss probe (import), or an import id (delete)")
    rc.add_argument("--out", type=Path, help="targets: write the addresses to this file (UTF-8)")
    rc.add_argument("--label", help='where the probe ran, e.g. "User VLAN 20, 2nd floor"')
    rc.add_argument("--authorized", action="store_true",
                    help="that network is allowed to reach switch management (default: it is not)")
    rc.set_defaults(func=cmd_reachability)

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
