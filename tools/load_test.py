# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Load test: a full LYSS scan (read-only SSH collection + audit) of N simulated switches.

The switches are clones of the demo lab (Cisco IOS, Cisco Business, HPE Aruba, MikroTik, SONiC,
Arista; some legacy switches that only speak SHA-1 SSH), with fictitious names and addresses.
LYSS and the simulator run in the same Python process on the same machine, so the figures are
a lower bound for a real network, where the switches do their own work.

  python tools/load_test.py --switches 250 [--workers 8] [--level 3]
"""

import argparse
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
DEMO = ROOT / "src" / "lyss" / "sim" / "labs" / "demo"
# fictitious addresses: the three IPv4 documentation ranges (RFC 5737)
NETS = ("192.0.2", "198.51.100", "203.0.113")


def build_lab(n: int, folder: Path) -> list[str]:
    demo = yaml.safe_load((DEMO / "lab.yaml").read_text(encoding="utf-8"))
    templates = list(demo["switches"].items())
    switches = {}
    for i in range(n):
        tid, spec = templates[i % len(templates)]
        new_id = f"load-{i + 1:04d}"
        spec = dict(spec)
        old_names = {tid, tid.upper(), spec.get("hostname", "")} - {""}
        spec["mac"] = f"02:00:00:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:{i & 255:02x}"   # locally administered
        spec["mgmt_ip"] = f"{NETS[i // 254 % 3]}.{i % 254 + 1}"
        if "hostname" in spec:
            spec["hostname"] = new_id
        switches[new_id] = spec
        for ext in (".cfg", ".state"):
            src = DEMO / f"{tid}{ext}"
            if src.exists():
                text = src.read_text(encoding="utf-8")
                for name in sorted(old_names, key=len, reverse=True):
                    text = re.sub(re.escape(name), new_id if name.islower() else new_id.upper(), text)
                (folder / f"{new_id}{ext}").write_text(text, encoding="utf-8")
    lab = {"name": f"load-{n}", "organization": "Load test (fictitious)", "credentials": demo["credentials"],
           "switches": switches, "links": []}
    (folder / "lab.yaml").write_text(yaml.safe_dump(lab, sort_keys=False), encoding="utf-8")
    return list(switches)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--switches", type=int, default=250)
    parser.add_argument("--workers", type=int, default=8, help="parallel SSH collections (LYSS default 8)")
    parser.add_argument("--level", type=int, default=2, choices=(2, 3))
    args = parser.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="lyss-load-"))
    import os
    os.environ["LYSS_DATA_DIR"] = str(work / "data")
    from lyss import collector, inventory, scan
    from lyss.sim import Simulator, load_lab
    inventory.configure(work / "data")
    try:
        lab_dir = work / "lab"
        lab_dir.mkdir()
        build_lab(args.switches, lab_dir)
        lab = load_lab(str(lab_dir))
        sim = Simulator(lab, base_port=0).start()
        try:
            creds = lab.credentials
            sim.pin_host_keys()
            for sw in lab.switches.values():
                inventory.save_device({"id": sw.id, "host": "127.0.0.1", "port": sw.port, "vendor": sw.platform,
                                       "username": creds["username"], "via_jump": False}, creds["password"])
            inventory.save_settings({**inventory.load_settings(), "level3": args.level == 3})
            devices = inventory.load_devices()
            status = {}
            t0 = time.monotonic()
            collector.collect_many(devices, {}, lambda d, s, m: status.__setitem__(d, (s, m)), workers=args.workers)
            t_collect = time.monotonic() - t0
            ok = [d for d in devices if status.get(d["id"], ("",))[0] == "collected"]
            t1 = time.monotonic()
            levels = {}
            for d in ok:
                r = scan.audit_device(d, "schedule")   # a scheduled scan also counts as the automatic backup
                levels[r["summary"]["achieved_level"]] = levels.get(r["summary"]["achieved_level"], 0) + 1
            t_audit = time.monotonic() - t1
            failed = {d: m for d, (s, m) in status.items() if s != "collected"}
            legacy = sum(1 for sw in lab.switches.values() if sw.legacy_ssh)
            platforms = {}
            for sw in lab.switches.values():
                platforms[sw.platform] = platforms.get(sw.platform, 0) + 1
            print(f"switches          : {len(devices)} ({legacy} legacy SHA-1 only) {platforms}")
            print(f"workers           : {args.workers}")
            print(f"collected         : {len(ok)}/{len(devices)} in {t_collect:.1f} s "
                  f"({t_collect / max(len(ok), 1):.2f} s per switch, {len(ok) / t_collect * 60:.0f} switches/min)")
            print(f"audited (L1-L{args.level}) : {len(ok)} in {t_audit:.1f} s ({t_audit / max(len(ok), 1) * 1000:.0f} ms per switch)")
            print(f"levels            : {dict(sorted(levels.items()))}")
            if failed:
                print(f"failed            : {len(failed)}, e.g. {next(iter(failed.items()))}")
            return 0 if not failed else 1
        finally:
            sim.stop()
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
