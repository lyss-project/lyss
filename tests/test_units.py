# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Unit tests: redaction, neighbour parsing, discovery helpers, vault, history, scheduler."""

import base64
import os
from datetime import datetime, timedelta

import pytest

from lyss import discovery, history, scheduler, topology, vault
from lyss.engine import backup_verdict, expand_ports, normalize_port, redact


# ---------------- redaction ----------------

@pytest.mark.parametrize("line, secret", [
    ("enable secret 9 $9$abc$def", "$9$abc$def"),
    ("enable password cisco123", "cisco123"),
    ("username bob privilege 15 password 7 0822455D0A16", "0822455D0A16"),
    ("username admin password encrypted Zm9vYmFy privilege 15", "Zm9vYmFy"),
    ("snmp-server community S3cretComm RO 10", "S3cretComm"),
    (" key 7 13061E010803", "13061E010803"),
    ("radius-server host 192.0.2.1 key PlainKey", "PlainKey"),
    ('password manager user-name "admin" plaintext "hunter2"', "hunter2"),
    ("tacacs-server key MyTacacsKey", "MyTacacsKey"),
])
def test_redact_hides_secret_values(line, secret):
    assert secret not in redact(line)


def test_redact_keeps_well_known_defaults_visible():
    assert "public" in redact("snmp-server community public RO")
    assert redact("enable password level 15 encrypted abc") == "enable password level 15 encrypted <redacted>"


# ---------------- ports and neighbours ----------------

@pytest.mark.parametrize("raw, norm", [
    ("GigabitEthernet1/0/5", "gi1/0/5"), ("gigabitethernet5", "gi5"), ("Gig 1/0/23", "gi1/0/23"),
    ("Gi1/0/23", "gi1/0/23"), ("TenGigabitEthernet1/1/1", "te1/1/1"), ("fa0/1", "fa0/1"),
])
def test_normalize_port(raw, norm):
    assert normalize_port(raw) == norm


@pytest.mark.parametrize("text, ports", [
    ("1-4", {"1", "2", "3", "4"}),
    ("1-2,A1-A3,Trk1", {"1", "2", "a1", "a2", "a3", "trk1"}),
    ('"25"', {"25"}),
    ("27-28", {"27", "28"}),
])
def test_expand_hp_port_lists(text, ports):
    assert expand_ports(text) == ports


HP_LLDP = """ LLDP Remote Devices Information

  LocalPort | ChassisId                 PortId PortDescr SysName
  --------- + ------------------------- ------ --------- ----------------------
  27        | 00 00 5e 00 53 01         49     49        LAB-CORE
  A1        | 0000ab-000009             gi2    gi2       LAB-ACC-02"""


def test_hp_lldp_remote_devices():
    rows = topology.parse_hp_lldp(HP_LLDP.splitlines())
    assert [(r["local_port"], r["chassis"], r["remote_port"], r["name"]) for r in rows] == [
        ("27", "00:00:5e:00:53:01", "49", "LAB-CORE"),
        ("a1", "00:00:ab:00:00:09", "gi2", "LAB-ACC-02"),
    ]
    assert topology.norm_mac("0000ab-000001") == "0000ab000001"


def test_hp_secrets_are_redacted():
    assert "S3cret" not in redact('radius-server host 192.0.2.10 key "S3cret"')
    assert "FAKE" not in redact('snmpv3 user "lyss" auth sha "FAKEHASH" priv aes "FAKEHASH"')


@pytest.mark.parametrize("line, secret", [
    ("snmp-server user mon LYSS v3 auth sha AuthPw123 priv aes 128 PrivPw456", ("AuthPw123", "PrivPw456")),
    ("snmp-server user mon LYSS v3 auth md5 AuthPw123 priv des PrivPw456", ("AuthPw123", "PrivPw456")),
    ("snmp-server user mon LYSS v3 auth-sha AuthPw123 priv-aes PrivPw456", ("AuthPw123", "PrivPw456")),
])
def test_snmpv3_user_secrets_are_redacted(line, secret):
    out = redact(line)
    assert all(s not in out for s in secret), out
    assert out.startswith("snmp-server user mon LYSS v3 auth")


SB_LLDP = """System capability legend:
B - Bridge; R - Router; W - Wlan Access Point; T - telephone;
  Port        Device ID        Port ID       System Name    Capabilities  TTL
--------- ----------------- ------------- ----------------- ------------ -----
gi2       02:00:00:00:aa:01     gi23                             B        119
gi3       02:00:00:00:aa:02 02:00:00:00:a GWN7605_02:00:00:     B, W      97
                            a:02          00:aa:02
""".splitlines()

IOS_CDP = """Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
LAB-SW-02.example.local
                 Gig 1/0/21        168              S I   C1000-24T Gig 2/0/21
lab-esx-01       Gig 1/0/2         162               S    VMware ES vmnic1
Total cdp entries displayed : 2""".splitlines()

CDP_DETAIL = """---------------------------------------------
Device-ID: 020000000003
Platform: Cisco SG350-52P (PID:SG350-52P-K9)-VSD
Capabilities: Switch IGMP
Interface: gi25, Port ID (outgoing port): gi41
Version: 2.5.0.83
SysName: lab-access-03
Addresses:
          IP 192.0.2.55
---------------------------------------------
Device ID: lab-esx-01
Entry address(es):
  IP address: 192.0.2.80
Platform: VMware ESXi,  Capabilities: Switch
Interface: GigabitEthernet1/0/2,  Port ID (outgoing port): vmnic1""".splitlines()


def test_parse_sb_lldp_with_wrapped_cells():
    rows = topology.parse_neighbors(SB_LLDP, "cisco_sb", "lldp")
    assert [(r["local_port"], r["remote_port"], r["caps"]) for r in rows] == [("gi2", "gi23", "B"), ("gi3", "02:00:00:00:aa:02", "B, W")]
    assert rows[1]["name"] == "GWN7605_02:00:00:00:aa:02"


def test_parse_ios_cdp_with_long_device_id_line():
    rows = topology.parse_neighbors(IOS_CDP, "cisco_ios", "cdp")
    assert rows[0]["device_id"] == "LAB-SW-02.example.local"
    assert (rows[0]["local_port"], rows[0]["remote_port"]) == ("gi1/0/21", "gi2/0/21")
    assert rows[1]["platform"].startswith("VMware") and len(rows) == 2


def test_parse_neighbor_details_any_layout():
    recs = topology.parse_neighbor_details(CDP_DETAIL)
    assert recs[0]["ips"] == ["192.0.2.55"] and recs[0]["sysname"] == "lab-access-03"
    assert recs[0]["local_port"] == "gi25" and recs[0]["remote_port"] == "gi41"
    assert recs[1]["ips"] == ["192.0.2.80"] and recs[1]["local_port"] == "gi1/0/2"


def test_norm_mac_formats():
    assert topology.norm_mac("98a2.c085.9c80") == topology.norm_mac("98:A2:C0:85:9C:80") == "98a2c0859c80"
    assert topology.norm_mac("LAB-SWT-01") is None


# ---------------- discovery helpers ----------------

def test_ranges_and_expansion():
    nets, errors = discovery.parse_ranges("192.0.2.0/30, 198.51.100.10-12 203.0.113.7")
    assert not errors
    assert discovery.expand(nets) == ["192.0.2.1", "192.0.2.2", "198.51.100.10", "198.51.100.11",
                                      "198.51.100.12", "203.0.113.7"]
    assert discovery.parse_ranges("198.0.0.0/8")[1] and discovery.parse_ranges("1.2.3.4-300")[1]


@pytest.mark.parametrize("banner, adapter", [
    ("SSH-2.0-Cisco-1.25", "cisco_ios"), ("SSH-2.0-OpenSSH_7.3p1.RL", "cisco_sb"),
    ("SSH-2.0-Mocana SSH 6.3", "hp_procurve"), ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3", None),
])
def test_ssh_fingerprints(banner, adapter):
    assert discovery.guess_platform(banner, discovery.SSH_FINGERPRINTS)[0] == adapter


@pytest.mark.parametrize("platform, adapter", [
    ("Cisco SG350-52P (PID:SG350-52P-K9)-VSD", "cisco_sb"), ("cisco C1000-24T-4G-L", "cisco_ios"),
    ("Cisco IOS Software, C1000 Software", "cisco_ios"), ("Aruba JL256A 2930F-48G", "hp_procurve"),
    ("HP J9772A 2530-48G-PoEP Switch, revision YA.16.10.0012, ROM YA.15.20", "hp_procurve"),
    ("Aruba JL675A 6100 48G CL4 4SFP+ Swch FL.10.13.1040", "aruba_aoscx"),
    ("Virtual.10.17.1010", "aruba_aoscx"), ("Aruba AOS-CX 6300M", "aruba_aoscx"),
    ("Juniper Networks, Inc. ex2300-24t Ethernet Switch, kernel JUNOS 23.4R2", "juniper_junos"),
    ("S5735-L24T4S-A1 Huawei Versatile Routing Platform Software VRP (R) software, Version 5.170", "huawei_vrp"),
    ("H3C Comware Platform Software, Software Version 7.1.064", None),
])
def test_platform_from_neighbour(platform, adapter):
    assert discovery.guess_platform(platform, discovery.PLATFORMS)[0] == adapter


# ---------------- vault ----------------

def test_vault_round_trip_native():
    blob = vault.protect("s3cr3t-é")
    assert "s3cr3t" not in blob and vault.unprotect(blob) == "s3cr3t-é"


def test_vault_aesgcm_backend(monkeypatch, tmp_path):
    monkeypatch.setenv("LYSS_VAULT_AESGCM", "1")
    monkeypatch.setenv("LYSS_MASTER_KEY", base64.b64encode(os.urandom(32)).decode())
    blob = vault.protect("portable-secret")
    assert blob.startswith("aesgcm:") and vault.unprotect(blob) == "portable-secret"
    with pytest.raises(Exception):
        vault.unprotect(blob[:-4] + "AAAA")  # tampering is detected


def test_vault_aesgcm_key_file(monkeypatch, tmp_path):
    monkeypatch.setenv("LYSS_VAULT_AESGCM", "1")
    monkeypatch.delenv("LYSS_MASTER_KEY", raising=False)
    monkeypatch.setattr(vault, "_key_file", tmp_path / "master.key")
    blob = vault.protect("x")
    assert (tmp_path / "master.key").exists() and vault.unprotect(blob) == "x"


# ---------------- history and backup evidence ----------------

def test_archive_versions_and_redacted_diff(data_dir):
    history.archive_config("sw1", "hostname a\nenable secret 9 $9$old\n", "manual")
    same = history.archive_config("sw1", "hostname a\nenable secret 9 $9$old\n", "schedule")
    assert not same["changed"]
    newer = history.archive_config("sw1", "hostname b\nenable secret 9 $9$new\n", "schedule")
    assert newer["changed"] and len(history.versions("sw1")) == 2
    diff = "\n".join(history.config_diff("sw1", newer["file"]))
    assert "+hostname b" in diff and "$9$new" not in diff and "$9$old" not in diff
    status = history.backup_status("sw1")
    assert status["last_automatic"] and status["versions"] == 2


def test_attestation_and_expiry(data_dir):
    history.attest("sw1", "Oxidized daily")
    assert history.backup_status("sw1")["attestation"]["reference"] == "Oxidized daily"
    history.revoke_attestation("sw1")
    assert history.backup_status("sw1")["attestation"] is None


def test_backup_verdicts():
    now = datetime.now()
    fresh = (now - timedelta(days=1)).isoformat()
    old = (now - timedelta(days=30)).isoformat()
    assert backup_verdict({"last": fresh, "last_automatic": fresh, "versions": 1}, 7)[0] == "pass"
    assert backup_verdict({"last": fresh, "last_automatic": old, "versions": 1}, 7)[0] == "fail"
    assert backup_verdict({"last": fresh, "last_automatic": None, "versions": 1}, 7)[0] == "fail"
    expired = {"reference": "x", "date": old, "expires": old, "expired": True}
    assert backup_verdict({"last": None, "last_automatic": None, "attestation": expired}, 7)[0] == "fail"
    assert backup_verdict(None, 7) == (None, [])


def test_scan_changes():
    prev = {"verdicts": {"A": "pass", "B": "fail", "C": "fail"}}
    cur = {"verdicts": {"A": "fail", "B": "pass", "C": "fail"}}
    assert history.changes(prev, cur) == {"new_fail": ["A"], "fixed": ["B"]}


# ---------------- SSH host key pinning ----------------

def test_host_key_trust_on_first_use_then_pinned(data_dir):
    import paramiko
    from lyss import collector
    first, other = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    fp = collector.verify_host_key("192.0.2.10", 22, first)        # first contact: recorded
    assert collector.known_fingerprint("192.0.2.10", 22) == fp
    assert collector.verify_host_key("192.0.2.10", 22, first) == fp  # same key: accepted
    with pytest.raises(collector.HostKeyMismatch):
        collector.verify_host_key("192.0.2.10", 22, other)          # different key: refused
    collector.verify_host_key("192.0.2.10", 2222, other)            # another port is another identity
    collector.forget_host_key("192.0.2.10", 22)                      # legitimate re-key
    assert collector.verify_host_key("192.0.2.10", 22, other) == collector.fingerprint(other)


# ---------------- scheduler ----------------

def test_scheduler_due_and_catch_up():
    s = {"enabled": True, "time": "02:30", "days": list(range(7))}
    day = datetime(2026, 11, 3, 3, 0)
    assert scheduler.should_run(s, day) == datetime(2026, 11, 3, 2, 30)
    assert scheduler.should_run({**s, "last_run": "2026-11-03T02:31:00"}, day) is None
    assert scheduler.should_run(s, datetime(2026, 11, 3, 10, 0)) is None  # older than the catch-up window
    assert scheduler.should_run({**s, "enabled": False}, day) is None
    assert scheduler.should_run({**s, "days": [6]}, day) is None  # Tuesday not selected
