# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Encryption at rest of collected configurations, device state, archived versions and results;
retention of the history; Settings > Data protection; "lyss data". Synthetic switches."""

import json
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from lyss import collector, history, inventory, scan, sealed, vault
from lyss.__main__ import main
from lyss.web import app as webapp

from conftest import load_case

SECRET = "enable secret 5 $1$fake$FictitiousHashOnly"


@pytest.fixture(params=["aesgcm"] + (["dpapi"] if sys.platform == "win32" else []))
def backend(request, monkeypatch, data_dir):
    if request.param == "aesgcm":
        monkeypatch.setenv("LYSS_VAULT_AESGCM", "1")
    else:
        monkeypatch.delenv("LYSS_VAULT_AESGCM", raising=False)
    assert vault.backend() == request.param
    return request.param


def add_switch(device_id="lab-sw", case_name="ios-weak", extra=""):
    case = load_case(case_name)
    inventory.save_device({"id": device_id, "host": "192.0.2.10", "port": "22", "vendor": case["vendor"],
                           "username": "ro", "via_jump": False}, "Fict1tious!")
    device = inventory.get_device(device_id)
    cfg, state = collector.config_paths(device)
    sealed.write_text(cfg, case["config"] + extra)        # as the collector does
    sealed.write_text(state, case["state"])
    return device, cfg, state


def test_files_are_encrypted_and_read_back(backend):
    device, cfg, state = add_switch(extra=f"\n{SECRET}\n")
    raw = cfg.read_bytes()
    assert raw.startswith(sealed.MAGIC) and b"FictitiousHashOnly" not in raw and b"hostname" not in raw
    assert SECRET in sealed.read_text(cfg)
    result = scan.audit_device(device, "schedule")
    results_file = inventory.RESULTS_DIR / f"{device['id']}.json"
    assert sealed.is_sealed(results_file) and inventory.load_result(device["id"])["summary"] == result["summary"]
    version = history.versions(device["id"])[0]["file"]
    archived = history._dir(device["id"]) / "configs" / version
    assert sealed.is_sealed(archived) and b"FictitiousHashOnly" not in archived.read_bytes()
    assert SECRET in history.read_version(device["id"])                  # restore: the full text
    assert all("FictitiousHashOnly" not in l for l in history.config_diff(device["id"], version))   # UI: redacted


def test_tampering_is_detected(backend):
    _, cfg, _ = add_switch()
    raw = bytearray(cfg.read_bytes())
    raw[-5] ^= 0xFF
    cfg.write_bytes(bytes(raw))
    with pytest.raises(Exception):
        sealed.read_text(cfg)


def test_plain_files_of_older_versions_stay_readable_and_get_sealed(backend):
    device, cfg, state = add_switch()
    plain = sealed.read_text(cfg)
    cfg.write_text(plain, encoding="utf-8")                              # written by LYSS <= 0.13
    cfg.write_bytes(cfg.read_bytes().replace(b"\n", b"\r\n").replace(b"\r\r\n", b"\r\n"))   # as on Windows
    assert not sealed.is_sealed(cfg) and sealed.read_text(cfg) == plain
    assert sealed.status()["plain"] == 1
    assert sealed.seal_existing() == 1 and sealed.is_sealed(cfg) and sealed.read_text(cfg) == plain
    assert sealed.status() == {"enabled": True, "backend": backend, "sealed": 2, "plain": 0}


def test_switching_encryption_off_and_unsealing(backend):
    add_switch()
    inventory.save_settings({**inventory.load_settings(), "encrypt_data": False})
    _, cfg, _ = add_switch("lab-sw-2")
    assert not sealed.is_sealed(cfg)                                     # new files: plain
    assert sealed.unseal_all() == 2 and sealed.status()["sealed"] == 0


def test_scan_job_seals_existing_plain_files(backend, monkeypatch):
    _, cfg, _ = add_switch()
    cfg.write_text(sealed.read_text(cfg), encoding="utf-8")
    monkeypatch.setattr(scan.collector, "collect_many", lambda devices, jump, update: None)
    monkeypatch.setattr(scan.discovery, "from_neighbors", lambda: 0)
    scan.start([], trigger="manual")
    for _ in range(100):
        if scan.current_job()["finished"]:
            break
        import time
        time.sleep(0.05)
    assert sealed.is_sealed(cfg)
    assert "Encrypted 1 data file(s) written without encryption." in scan.current_job()["notices"]


def test_retention_keeps_the_last_versions_and_recent_history(data_dir, monkeypatch):
    device, cfg, _ = add_switch()
    now = datetime(2026, 6, 1, 12, 0, 0)
    clock = {"now": now}
    monkeypatch.setattr(history, "_now", lambda: clock["now"])
    for days, text in ((100, "hostname v1\n"), (90, "hostname v2\n"), (80, "hostname v3\n"),
                       (70, "hostname good\n"), (50, "hostname current\n")):
        clock["now"] = now - timedelta(days=days)
        history.archive_config(device["id"], text, "schedule")
    for line in ({"ts": (now - timedelta(days=d)).isoformat(), "trigger": "schedule", "level": 0, "pass": 0,
                  "fail": 1, "unknown": 0, "verdicts": {}} for d in (100, 50)):
        path = history._dir(device["id"]) / "scans.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
    inventory.save_settings({**inventory.load_settings(), "retention_days": 30})
    clock["now"] = now
    history.archive_config(device["id"], "hostname current\n", "schedule")         # today, unchanged
    texts = [history.read_version(device["id"], v["file"]) for v in history.versions(device["id"])]
    # older than 30 days, but the last 3 distinct versions are always kept
    assert texts == ["hostname current\n", "hostname good\n", "hostname v3\n"]
    files = sorted(v["file"] for v in history.versions(device["id"]))
    assert sorted(p.name for p in (history._dir(device["id"]) / "configs").glob("*.cfg")) == files
    assert history.backup_status(device["id"])["last_automatic"] == now.isoformat()
    history.record_scan(device["id"], {"scanned_at": now.isoformat(), "summary": {
        "achieved_level": 1, "pass": 1, "fail": 0, "unknown": 0}, "findings": []}, "schedule")
    assert [s["ts"] for s in history.load_scans(device["id"])] == [now.isoformat()]
    # a switch reset to factory defaults after a long outage: the good version is still there
    clock["now"] = now + timedelta(days=1)
    history.archive_config(device["id"], "hostname Switch\n", "schedule")
    assert "hostname good\n" in [history.read_version(device["id"], v["file"]) for v in history.versions(device["id"])]


def test_archive_rewrites_a_missing_version_and_keeps_files_of_others(data_dir):
    device, _, _ = add_switch()
    entry = history.archive_config(device["id"], "hostname a\n", "schedule")
    folder = history._dir(device["id"]) / "configs"
    (folder / entry["file"]).unlink()                                   # lost (crash, other process)
    history.archive_config(device["id"], "hostname a\n", "schedule")   # same content
    assert history.read_version(device["id"]) == "hostname a\n"
    (folder / "20990101-000000.cfg").write_text("written by another process", encoding="utf-8")
    history.archive_config(device["id"], "hostname b\n", "schedule")
    assert (folder / "20990101-000000.cfg").exists()                   # not in our index: never deleted


def test_concurrent_writers_never_corrupt_a_file(data_dir):
    import threading
    path = data_dir / "results" / "x.json"
    errors = []

    def writer(ch):
        try:
            for _ in range(20):
                sealed.write_text(path, ch * 5000)
        except Exception as exc:   # noqa: BLE001
            errors.append(exc)
    threads = [threading.Thread(target=writer, args=(c,)) for c in "AB"]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and sealed.read_text(path) in ("A" * 5000, "B" * 5000)
    assert not list(path.parent.glob("*.tmp"))


def test_missing_master_key_with_encrypted_data_is_refused(data_dir, monkeypatch):
    monkeypatch.setenv("LYSS_VAULT_AESGCM", "1")
    add_switch()                                                        # secrets and files with the key
    (data_dir / "master.key").unlink()                                 # e.g. LYSS_MASTER_KEY forgotten
    with pytest.raises(RuntimeError, match="master key is missing"):
        vault.protect("x")
    assert not (data_dir / "master.key").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_dpapi_secret_blob_is_not_readable_as_a_file(data_dir, monkeypatch):
    monkeypatch.delenv("LYSS_VAULT_AESGCM", raising=False)
    blob = vault.protect("Sw1tch-Secret")
    path = data_dir / "results" / "planted.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(sealed.MAGIC + b"D" + bytes.fromhex(blob))
    with pytest.raises(OSError):
        sealed.read_text(path)


@pytest.fixture
def client(data_dir):
    webapp._sessions.clear()
    webapp._failures.update(count=0, locked_until=0)
    c = TestClient(webapp.app, base_url="http://127.0.0.1:8765")
    r = c.post("/setup", data={"password": "correct horse battery", "confirm": "correct horse battery"},
               follow_redirects=False)
    assert r.status_code == 303
    return c


def test_settings_data_protection(client):
    import re
    add_switch()
    page = client.get("/settings").text
    assert "Data protection" in page and "2 encrypted file(s), 0 plain" in page
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    r = client.post("/settings/data", data={"csrf": "forged", "retention_days": "7"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert "retention_days" not in inventory.load_settings()                 # nothing saved
    r = client.post("/settings/data", data={"csrf": csrf, "retention_days": "-3", "encrypt": "1"})
    assert r.status_code == 400 and "Retention" in r.text
    r = client.post("/settings/data", data={"csrf": csrf, "retention_days": "365"})
    assert r.status_code == 200 and "encryption off for new files" in r.text
    settings = inventory.load_settings()
    assert settings["encrypt_data"] is False and settings["retention_days"] == 365


def test_cli_data_commands(data_dir, capsys):
    device, cfg, _ = add_switch(extra=f"\n{SECRET}\n")
    scan.audit_device(device, "schedule")
    assert main(["data", "status"]) == 0 and "encryption at rest: on" in capsys.readouterr().out
    assert main(["data", "config", device["id"], "--list"]) == 0
    assert history.versions(device["id"])[0]["file"] in capsys.readouterr().out
    assert main(["data", "config", device["id"]]) == 0 and SECRET in capsys.readouterr().out
    assert main(["data", "config", device["id"], "--version", "../../devices.json"]) == 2
    assert main(["data", "config", "no-such-switch"]) == 2
    assert main(["data", "unseal"]) == 2 and sealed.is_sealed(cfg)          # needs --yes
    assert main(["data", "unseal", "--yes"]) == 0 and not sealed.is_sealed(cfg)
    assert inventory.load_settings()["encrypt_data"] is False
    assert main(["data", "seal"]) == 0 and sealed.is_sealed(cfg)
