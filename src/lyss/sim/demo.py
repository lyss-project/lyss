# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""`python -m lyss demo`: the LYSS web interface on its OWN data directory, filled with the
simulated demo lab, so that demonstrations, screenshots and reports only ever show fictitious
data. The real data directory (private/ or LYSS_DATA_DIR) is never read or written."""

import os
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

from .. import inventory
from .lab import Lab, load_lab
from .server import Simulator

MARKER = ".lyss-demo"
PROFILE_NAME = "Demo switches"


def default_dir() -> Path:
    return Path(tempfile.gettempdir()) / "lyss-demo"


def _real_dirs() -> list[Path]:
    dirs = [inventory.default_data_dir(), inventory.PRIVATE]
    if os.environ.get("LYSS_DATA_DIR"):
        dirs.append(Path(os.environ["LYSS_DATA_DIR"]))
    return [d.resolve() for d in dirs]


def check_dir(path: Path, real_dirs: list[Path]) -> Path:
    """The demo directory must be separate from every real data directory, and either new,
    empty, or an earlier demo directory (marker file)."""
    p = path.resolve()
    for real in real_dirs:
        if p == real or real in p.parents or p in real.parents:
            raise ValueError(f"refusing to use {p}: it overlaps the real LYSS data directory {real}")
    if p.exists() and any(p.iterdir()) and not (p / MARKER).exists():
        raise ValueError(f"refusing to use {p}: not empty and not a LYSS demo directory")
    return p


def prepare(data_dir: Path, lab: Lab, sim: Simulator, reset: bool = False) -> str | None:
    """Point LYSS at data_dir and fill it on first use: admin account, organisation, demo
    credential profile, the simulated switches, schedule and remediation settings.
    Returns the new admin password (None when the directory was already prepared)."""
    if reset and (data_dir / MARKER).exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / MARKER).write_text("LYSS demo data directory: fictitious data only, safe to delete.\n",
                                   encoding="utf-8")
    inventory.configure(data_dir)
    os.environ["LYSS_DATA_DIR"] = str(data_dir)

    password = None
    settings = inventory.load_settings()
    if settings.get("admin") is None:
        password = secrets.token_urlsafe(12)
        settings["admin"] = inventory.hash_password(password)
    settings["organization"] = lab.organization
    settings.setdefault("schedule", {"enabled": True, "time": "02:30", "days": list(range(7))})
    settings.setdefault("remediation", {"enabled": True, "syslog": "192.0.2.60", "ntp": ["192.0.2.123"],
                                        "banner": "Authorized access only. Activity is logged."})
    inventory.save_settings(settings)

    sim.pin_host_keys()
    profile_id = inventory.save_profile(PROFILE_NAME, lab.credentials["username"], lab.credentials["password"])
    for sw in lab.switches.values():
        # the SSH ports may differ from one start to the next (--base-port)
        inventory.save_device({"id": sw.id, "host": sim.host, "port": sw.port, "vendor": sw.platform,
                               "username": "", "profile": profile_id, "via_jump": False}, None)
    return password


def initial_scan(timeout: float = 180) -> dict | None:
    """Collect and audit every simulated switch once, as a scheduled scan (the simulated
    'nightly' scan gives LYSS-BKP-001 its automatic-backup evidence)."""
    from .. import scan
    ids = [d["id"] for d in inventory.load_devices()]
    if not ids or scan.start(ids, trigger="schedule") is None:
        return None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = scan.current_job()
        if job and job["finished"]:
            return job
        time.sleep(0.3)
    return scan.current_job()


def run(lab_name: str = "demo", data_dir: Path | None = None, ui_port: int = 8766,
        base_port: int = 2201, reset: bool = False, open_browser: bool = False) -> int:
    try:
        sys.stdout.reconfigure(line_buffering=True)  # the admin password must show up at once
    except (AttributeError, ValueError):
        pass
    data_dir = check_dir(Path(data_dir or default_dir()), _real_dirs())
    lab = load_lab(lab_name)
    sim = Simulator(lab, base_port=base_port, keys_dir=data_dir / "sim-keys")
    if reset and (data_dir / MARKER).exists():
        shutil.rmtree(data_dir)
    try:
        sim.start()
    except OSError as exc:
        print(f"Cannot open the simulator ports from {base_port}: {exc}. Try --base-port 2301.")
        return 2
    password = prepare(data_dir, lab, sim)

    print(f"LYSS demo - '{lab.organization}' (fictitious network, {len(lab.switches)} simulated switches)")
    print(f"  data directory : {data_dir}")
    for d in sim.describe():
        print(f"  {d['id']:<12} {d['platform']:<12} {d['model']:<16} 127.0.0.1:{d['port']}")
    print("  first scan ...", end=" ", flush=True)
    job = initial_scan()
    if job:
        levels = []
        for device_id, item in job["items"].items():
            result = inventory.load_result(device_id) or {}
            levels.append(f"{device_id} L{(result.get('summary') or {}).get('achieved_level', '?')}"
                          if item["status"] == "done" else f"{device_id} {item['status']} ({item['message'][:120]})")
        print(", ".join(levels))
    else:
        print("skipped")

    import uvicorn

    from .. import scheduler
    from ..web.app import app
    url = f"http://127.0.0.1:{ui_port}"
    print(f"\n  web interface  : {url}")
    if password:
        print(f"  admin password : {password}   (shown once; --reset starts over)")
    else:
        print("  admin password : the one printed at the first start (--reset starts over)")
    print("  Ctrl+C to stop.")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    scheduler.start_background()
    try:
        uvicorn.run(app, host="127.0.0.1", port=ui_port, log_level="warning", server_header=False)
    finally:
        sim.stop()
    return 0
