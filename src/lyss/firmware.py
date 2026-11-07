# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Firmware upgrade of Cisco Catalyst 1000 switches (classic IOS 15.2(7)E), in two separate steps.

Staging (no reboot, can run during the day):
  checks (version, boot variable, free flash) -> write memory -> temporary SCP server ->
  copy the image tar to flash -> verify /md5 on the switch -> archive download-sw /safe /no-set-boot
  (installs the new image next to the old one, boot variable unchanged) -> delete the tar ->
  SCP server off -> write memory -> boot variable checked unchanged.
Activation (maintenance window, explicit confirmation):
  boot system <new image> -> write memory -> reload -> wait for SSH -> check the version -> scan.
The old image stays in flash: going back is "boot system <old image>" + reload.

Commands follow Cisco's Catalyst 1000 documentation (release notes 15.2(7)Ex, configuration guide
"Working with the Cisco IOS File System...", tech note 217008). The image is downloaded by the
administrator from cisco.com (account required) and checked against the hash published there.
"""

import hashlib
import json
import re
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from . import collector, inventory

IMAGE_NAME = re.compile(r"^c1000-universalk9-tar\.(\d{3})-(\d+)\.(E\d+[a-z]?)\.tar\Z")
MODELS = re.compile(r"^(NAL-)?C1000(FE)?-")
MAX_IMAGE = 200 * 1024 * 1024
_lock = threading.Lock()
_job: dict | None = None


# ---------------- images ----------------

def _dir() -> Path:
    return inventory.PRIVATE / "firmware"


def image_version(name: str) -> str:
    """"c1000-universalk9-tar.152-7.E14.tar" -> "15.2(7)E14"."""
    m = IMAGE_NAME.match(name)
    train, minor, rel = m.groups()
    return f"{train[:2]}.{train[2:]}({minor}){rel}"


def bin_path(name: str) -> str:
    """Where archive download-sw extracts the image of a tar (Cisco tech note 217008)."""
    base = name.replace("-tar.", "-mz.").removesuffix(".tar")
    return f"flash:/{base}/{base}.bin"


def save_image(name: str, data: bytes, expected_hash: str) -> dict:
    """Store an image after checking its name and the MD5 / SHA-512 published by the vendor."""
    if not IMAGE_NAME.match(name):
        raise ValueError("file name must be the original Cisco name, e.g. c1000-universalk9-tar.152-7.E14.tar")
    if not 0 < len(data) <= MAX_IMAGE:
        raise ValueError("unexpected file size")
    md5, sha512 = hashlib.md5(data).hexdigest(), hashlib.sha512(data).hexdigest()
    expected = expected_hash.strip().lower()
    if expected not in (md5, sha512):
        raise ValueError("the file does not match the hash published by Cisco: do not use it")
    _dir().mkdir(parents=True, exist_ok=True)
    (_dir() / name).write_bytes(data)
    meta = {"file": name, "version": image_version(name), "size": len(data), "md5": md5, "sha512": sha512,
            "checked_against": "md5" if expected == md5 else "sha512",
            "uploaded": datetime.now().isoformat(timespec="seconds")}
    (_dir() / (name + ".json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def list_images() -> list[dict]:
    if not _dir().exists():
        return []
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(_dir().glob("*.tar.json"))]


def get_image(name: str) -> dict | None:
    return next((i for i in list_images() if i["file"] == name), None)


# ---------------- per-device state ----------------

def _state_file() -> Path:
    return _dir() / "state.json"


def device_state(device_id: str) -> dict:
    return inventory._read(_state_file(), {}).get(device_id, {})


def _set_state(device_id: str, **values) -> None:
    data = inventory._read(_state_file(), {})
    data[device_id] = {**data.get(device_id, {}), **values, "updated": datetime.now().isoformat(timespec="seconds")}
    inventory._write(_state_file(), data)


def eligible(device: dict) -> bool:
    result = inventory.load_result(device["id"]) or {}
    return device["vendor"] == "cisco_ios" and bool(MODELS.match(result.get("model", "")))


# ---------------- SCP upload (sink protocol, over the existing SSH transport) ----------------

def scp_put(transport, local: Path, remote: str, progress=None) -> None:
    chan = transport.open_session()
    chan.settimeout(120)
    chan.exec_command(f"scp -t {remote}")

    def ack():
        b = chan.recv(1)
        if b != b"\x00":
            raise RuntimeError(f"SCP refused by the switch: {(b + chan.recv(512)).decode(errors='replace').strip()}")

    ack()
    size = local.stat().st_size
    chan.sendall(f"C0644 {size} {local.name}\n".encode())
    ack()
    sent = 0
    with local.open("rb") as f:
        while chunk := f.read(32768):
            chan.sendall(chunk)
            sent += len(chunk)
            if progress and sent % (4 * 1024 * 1024) < 32768:
                progress(f"copying the image: {100 * sent // size}%")
    chan.sendall(b"\x00")
    ack()
    chan.close()


# ---------------- staging and activation ----------------

def _free_bytes(dir_output: str) -> int:
    m = re.search(r"\((\d+) bytes free\)|(\d+) bytes free", dir_output)
    if not m:
        raise RuntimeError("cannot read the free flash space (dir flash:)")
    return int(m.group(1) or m.group(2))


def _boot_path(show_boot: str) -> str:
    m = re.search(r"BOOT path-list\s*:\s*(\S*)", show_boot)
    return m.group(1) if m else ""


def stage(device: dict, image: dict, jump, step) -> dict:
    name = image["file"]
    local = _dir() / name
    s = collector.open_session(device, jump)
    try:
        step("checks: version, boot variable, flash space")
        version = s.run("show version", 60)
        boot_before = _boot_path(s.run("show boot", 60))
        if image["version"] in version:
            raise RuntimeError(f"the switch already runs {image['version']}")
        free = _free_bytes(s.run("dir flash:", 60))
        need = int(image["size"] * 2.6)  # the tar + the extracted image, old image kept (/safe)
        if free < need:
            raise RuntimeError(f"not enough flash: {free // 1048576} MB free, {need // 1048576} MB needed")
        config = s.run("show running-config", 90)
        if not re.search(r"(?m)^aaa new-model", config) or not re.search(r"(?m)^aaa authorization exec ", config):
            raise RuntimeError("the switch SCP server needs 'aaa new-model' and 'aaa authorization exec': "
                               "LYSS does not change authentication, configure it first or copy the image manually")
        step("saving the configuration (write memory)")
        s.save()
        step("temporary SCP server on")
        done = s.configure(["ip scp server enable"])
        if any(collector.CLI_ERROR.search(o) for _, o in done):
            raise RuntimeError("the switch refused 'ip scp server enable'")
        try:
            step("copying the image to flash")
            scp_put(s.transport, local, f"flash:/{name}", step)
            step("verifying the MD5 on the switch")
            out = s.run(f"verify /md5 flash:/{name}", 600)
            if image["md5"] not in out.lower():
                raise RuntimeError("the MD5 computed by the switch does not match: image not installed")
            step("installing next to the current image (archive download-sw /safe /no-set-boot)")
            out = s.run(f"archive download-sw /safe /no-set-boot flash:/{name}", 3600)
            if re.search(r"(?i)error|fail|aborted|not enough", out):
                raise RuntimeError("archive download-sw failed: " + out.strip()[-300:])
            if Path(bin_path(name)).name not in s.run(f"dir {bin_path(name).rsplit('/', 1)[0]}", 60):
                raise RuntimeError("the new image is not in flash after installation")
            step("removing the copied tar")
            s.conn.send_command_timing(f"delete /force flash:/{name}", read_timeout=120)
        finally:
            step("temporary SCP server off")
            s.configure(["no ip scp server enable"])
            s.save()
        boot_after = _boot_path(s.run("show boot", 60))
        if boot_after != boot_before:
            raise RuntimeError(f"the boot variable changed unexpectedly ({boot_before} -> {boot_after})")
    finally:
        s.close()
    _set_state(device["id"], status="staged", image=name, version=image["version"], boot_before=boot_before)
    return {"outcome": f"{image['version']} staged; boot unchanged ({boot_before or 'default'}); no reboot"}


def activate(device: dict, jump, step) -> dict:
    from . import scan
    st = device_state(device["id"])
    if st.get("status") != "staged":
        raise RuntimeError("stage the image first")
    target = bin_path(st["image"])
    previous = st.get("boot_before") or ""
    s = collector.open_session(device, jump)
    try:
        step("checking that the new image is in flash")
        if target.split("/")[-1] not in s.run(f"dir {target}", 60):
            raise RuntimeError(f"{target} is no longer in flash: stage the image again (nothing changed)")
        # the previous image stays in the boot path: if the new one fails to load, the switch
        # falls back to it instead of stopping at the boot loader
        boot = f"{target};{previous}" if previous and previous != target else target
        step(f"boot system {boot}")
        done = s.configure([f"boot system {boot}"])
        if any(collector.CLI_ERROR.search(o) for _, o in done):
            raise RuntimeError("the switch refused the boot command")
        s.save()
        if target.split("/")[-1] not in s.run("show boot", 60):
            raise RuntimeError("boot variable not updated: reload cancelled")
        step("reloading the switch")
        out = s.conn.send_command_timing("reload", read_timeout=30)
        if re.search(r"(?i)save\?|\[yes/no\]", out):
            out = s.conn.send_command_timing("no", read_timeout=30)   # saved just above
        if "confirm" not in out.lower():
            # the reload did not start: never leave a new boot variable armed for the next
            # unplanned reboot
            s.configure([f"boot system {previous}"] if previous else ["no boot system"])
            s.save()
            raise RuntimeError("the switch did not ask to confirm the reload: boot variable restored, "
                               "nothing changed")
        try:
            s.conn.send_command_timing("\n", read_timeout=10)
        except Exception:
            pass  # the session drops while the switch reboots
    finally:
        try:
            s.close()
        except Exception:
            pass
    _set_state(device["id"], status="rebooting")
    step("waiting for the switch to come back (up to 20 minutes)")
    time.sleep(90)
    deadline = time.monotonic() + 20 * 60
    while time.monotonic() < deadline:
        try:
            collector.collect_device(device, jump)
            break
        except Exception:
            time.sleep(20)
    else:
        _set_state(device["id"], status="unreachable")
        raise RuntimeError("the switch did not come back within 20 minutes: check it on the console")
    result = scan.audit_device(device, "change")
    if result.get("firmware") != st["version"]:
        _set_state(device["id"], status="boot-mismatch")
        raise RuntimeError(f"the switch came back on {result.get('firmware')} instead of {st['version']}")
    _set_state(device["id"], status="upgraded")
    return {"outcome": f"upgraded to {st['version']}, scan done (level {result['summary']['achieved_level']})"}


# ---------------- background job (one switch at a time) ----------------

def current_job() -> dict | None:
    with _lock:
        return None if _job is None else dict(_job)


def running() -> bool:
    with _lock:
        return bool(_job and not _job["finished"])


def start(action: str, device_id: str, image_name: str = "") -> str | None:
    global _job
    from . import remediate, scan
    if not remediate.settings().get("firmware"):
        raise ValueError("firmware upgrades are not allowed: turn them on in Settings > Remediation")
    device = inventory.get_device(device_id)
    if device is None or not eligible(device):
        raise ValueError("this switch is not a supported Catalyst 1000")
    image = get_image(image_name) if action == "stage" else None
    if action == "stage" and image is None:
        raise ValueError("unknown image")
    previous = remediate.unclean_change(device_id)
    if previous:   # staging and activation save the running configuration
        raise ValueError("the last change on this switch may be incomplete (" + previous[:120]
                         + "): check the switch and run a scan first")
    sj = scan.current_job()
    remediation_busy = remediate.running()   # before taking our lock: remediate.start does the reverse
    with _lock:
        if (_job and not _job["finished"]) or remediation_busy or (sj and not sj["finished"]):
            return None
        _job = {"id": uuid.uuid4().hex[:8], "action": action, "device": device_id, "status": "running",
                "message": "", "outcome": "", "started": time.time(), "finished": None}
        job_id = _job["id"]

    def step(message):
        with _lock:
            _job["message"] = message

    def run():
        settings = inventory.load_settings().get("jump", {})
        jump = collector.JumpHost(settings) if settings.get("host") else None
        entry = {"ts": datetime.now().isoformat(timespec="seconds"), "device": device_id, "type": f"firmware-{action}",
                 "controls": ["LYSS-VULN-001"], "applied": [], "rolled_back": []}
        try:
            out = (stage(device, image, jump, step) if action == "stage" else activate(device, jump, step))
            entry["outcome"] = out["outcome"]
            with _lock:
                _job.update(status="done", outcome=out["outcome"])
        except Exception as exc:
            entry["outcome"] = f"error: {exc}"[:300]
            with _lock:
                _job.update(status="error", outcome=f"{exc}"[:300])
        finally:
            from .remediate import log_change
            log_change(entry)
            if jump:
                jump.close()
            with _lock:
                _job["finished"] = time.time()

    threading.Thread(target=run, daemon=True).start()
    return job_id
