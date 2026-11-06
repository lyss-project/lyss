# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Device inventory, settings and scan results, all stored in the data directory:
LYSS_DATA_DIR if set (e.g. a Docker volume), else <project>/private (git-ignored) for a source
checkout, else a per-user folder for an installed package (%LOCALAPPDATA%\\LYSS on Windows,
$XDG_DATA_HOME/lyss or ~/.local/share/lyss elsewhere)."""

import hashlib
import hmac
import ipaddress
import json
import os
import re
import threading
from pathlib import Path

from . import vault
from .engine import INSTALLED, ROOT

PRIVATE = DEVICES_FILE = SETTINGS_FILE = RESULTS_DIR = Path()


def default_data_dir() -> Path:
    """Where LYSS keeps devices, credentials and results when LYSS_DATA_DIR is not set. An
    installed package never writes next to its own code."""
    if not INSTALLED:
        return ROOT / "private"
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "LYSS"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "lyss"


def configure(data_dir: Path | str) -> None:
    """Point every data file at data_dir (used at start-up and by the tests)."""
    global PRIVATE, DEVICES_FILE, SETTINGS_FILE, RESULTS_DIR
    PRIVATE = Path(data_dir)
    DEVICES_FILE = PRIVATE / "devices.json"
    SETTINGS_FILE = PRIVATE / "settings.json"
    RESULTS_DIR = PRIVATE / "results"
    vault._key_file = PRIVATE / "master.key"


configure(os.environ.get("LYSS_DATA_DIR") or default_data_dir())

ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_lock = threading.Lock()


def _read(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


# ---------------- devices ----------------

def load_devices() -> list[dict]:
    return _read(DEVICES_FILE, [])


def get_device(device_id: str) -> dict | None:
    return next((d for d in load_devices() if d["id"] == device_id), None)


def validate_device(data: dict, vendors: list[str]) -> list[str]:
    errors = []
    if not ID_PATTERN.match(data.get("id", "")):
        errors.append("Name: lowercase letters, digits and dashes only (max 40).")
    host = data.get("host", "")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_PATTERN.match(host):
            errors.append("Address: not a valid IP address or hostname.")
    if data.get("vendor") not in vendors and data.get("vendor") != "auto":
        errors.append("Platform: unknown adapter.")
    if not 1 <= int(data.get("port") or 0) <= 65535:
        errors.append("SSH port: 1-65535.")
    if data.get("profile"):
        if get_profile(data["profile"]) is None:
            errors.append("Credential profile: not found.")
    elif not 0 < len(data.get("username", "")) <= 64:
        errors.append("Username: required (max 64 characters).")
    if data.get("site") and not any(s["id"] == data["site"] for s in load_settings().get("sites", [])):
        errors.append("Site: not found.")
    return errors


def save_device(data: dict, password: str | None, original_id: str | None = None) -> None:
    """Create or update a device. An empty password keeps the stored one.
    With data["profile"] set, the credentials come from that profile instead."""
    with _lock:
        devices = load_devices()
        old = next((d for d in devices if d["id"] == (original_id or data["id"])), None)
        profile = data.get("profile") or ""
        record = {
            "id": data["id"],
            "host": data["host"],
            "port": int(data["port"]),
            "vendor": data["vendor"],
            "username": "" if profile else data["username"],
            "via_jump": bool(data.get("via_jump")),
            "profile": profile,
            "site": data.get("site") or "",   # empty = site chosen automatically from the address
            "secret": "" if profile else (vault.protect(password) if password else (old or {}).get("secret", "")),
        }
        devices = [d for d in devices if d["id"] not in {record["id"], original_id}]
        devices.append(record)
        devices.sort(key=lambda d: d["id"])
        _write(DEVICES_FILE, devices)


def set_site(device_id: str, site: str) -> None:
    """Pin a device to a site ("" = automatic, from its address)."""
    with _lock:
        devices = load_devices()
        for d in devices:
            if d["id"] == device_id:
                d["site"] = site
        _write(DEVICES_FILE, devices)


def set_vendor(device_id: str, vendor: str) -> None:
    """Record the platform detected for a device added with platform "auto"."""
    with _lock:
        devices = load_devices()
        for d in devices:
            if d["id"] == device_id:
                d["vendor"] = vendor
        _write(DEVICES_FILE, devices)


def delete_device(device_id: str) -> None:
    with _lock:
        _write(DEVICES_FILE, [d for d in load_devices() if d["id"] != device_id])
        (RESULTS_DIR / f"{device_id}.json").unlink(missing_ok=True)


def device_credentials(device: dict) -> tuple[str, str]:
    """(username, password) of a device, from its credential profile or its own secret."""
    if device.get("profile"):
        profile = get_profile(device["profile"])
        if profile is None:
            raise ValueError(f"credential profile '{device['profile']}' no longer exists")
        return profile["username"], vault.unprotect(profile["secret"])
    return device["username"], vault.unprotect(device["secret"])


# ---------------- credential profiles ----------------

def load_profiles() -> list[dict]:
    return load_settings().get("profiles", [])


def get_profile(profile_id: str) -> dict | None:
    return next((p for p in load_profiles() if p["id"] == profile_id), None)


def save_profile(name: str, username: str, password: str) -> str:
    """Create or replace a profile (id derived from the name). Returns its id."""
    profile_id = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")[:40] or "profile"
    with _lock:
        settings = load_settings()
        profiles = [p for p in settings.get("profiles", []) if p["id"] != profile_id]
        profiles.append({"id": profile_id, "name": name.strip()[:60], "username": username.strip()[:64],
                         "secret": vault.protect(password)})
        settings["profiles"] = sorted(profiles, key=lambda p: p["name"].lower())
        _write(SETTINGS_FILE, settings)
    return profile_id


def delete_profile(profile_id: str) -> bool:
    """Delete a profile unless a device still uses it."""
    if any(d.get("profile") == profile_id for d in load_devices()):
        return False
    with _lock:
        settings = load_settings()
        settings["profiles"] = [p for p in settings.get("profiles", []) if p["id"] != profile_id]
        _write(SETTINGS_FILE, settings)
    return True


# ---------------- settings ----------------

def load_settings() -> dict:
    return _read(SETTINGS_FILE, {"jump": {}, "admin": None})


def save_settings(settings: dict) -> None:
    with _lock:
        _write(SETTINGS_FILE, settings)


def hash_password(password: str, salt: bytes | None = None) -> dict:
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024)
    return {"salt": salt.hex(), "hash": digest.hex()}


def check_password(password: str, stored: dict | None) -> bool:
    if not stored:
        return False
    candidate = hash_password(password, bytes.fromhex(stored["salt"]))["hash"]
    return hmac.compare_digest(candidate, stored["hash"])


# ---------------- results ----------------

def save_result(device_id: str, result: dict) -> None:
    _write(RESULTS_DIR / f"{device_id}.json", result)


def load_result(device_id: str) -> dict | None:
    return _read(RESULTS_DIR / f"{device_id}.json", None)
