# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Specification 0.7.0-draft: stricter test procedures after the automated reviews of the CISO
Assistant pull request (CodeRabbit, Qodo). Each test shows the weak configuration that used to
pass. Synthetic data."""

import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from conftest import load_case

from lyss.engine import audit, backup_verdict

HERE = Path(__file__).parent


def verdict(case: str, control: str, edit=None) -> tuple[str, list[str]]:
    c = load_case(case)
    config = edit(c["config"]) if edit else c["config"]
    f = next(f for f in audit(config, c["vendor"], 2, c["state"], c["context"]) if f.control_id == control)
    return f.verdict, f.evidence


def l3(fixture: str, vendor: str, control: str, edit=None, state: str = "") -> tuple[str, list[str]]:
    text = (HERE / "l3" / fixture).read_text(encoding="utf-8")
    text = edit(text) if edit else text
    f = next(f for f in audit(text, vendor, 3, state) if f.control_id == control)
    return f.verdict, f.evidence


def sub(pattern, repl):
    def edit(cfg):
        new, n = re.subn(pattern, repl, cfg, flags=re.M)
        assert n, f"pattern not found: {pattern}"
        return new
    return edit


def add(text):
    return lambda cfg: cfg.rstrip("\n").removesuffix("end").rstrip("\n") + "\n" + text + "\n"


# ---------------- LYSS-AUTH-010: only local accounts as fallback ----------------

@pytest.mark.parametrize("case, edit", [
    ("ios-hardened", sub(r"^aaa authentication login default group NPS-GRP local$",
                         "aaa authentication login default group NPS-GRP none")),
    ("ios-hardened", sub(r"^aaa authentication login default group NPS-GRP local$",
                         "aaa authentication login default group NPS-GRP local none")),
    ("ios-hardened", sub(r"^aaa authentication login default group NPS-GRP local$",
                         "aaa authentication login default group NPS-GRP line")),
    ("sb-hardened", sub(r"^aaa authentication login default radius local$",
                        "aaa authentication login default radius none")),
    ("hp-hardened", sub(r"^aaa authentication ssh login radius local$", "aaa authentication ssh login radius none")),
    ("arista-hardened", sub(r"^aaa authentication login default group TACACS local$",
                            "aaa authentication login default group TACACS none")),
])
def test_auth_010_fails_on_a_fallback_other_than_local(case, edit):
    assert verdict(case, "LYSS-AUTH-010")[0] == "pass"
    assert verdict(case, "LYSS-AUTH-010", edit)[0] == "fail"


def test_auth_010_named_vty_list_with_none_fallback_fails():
    edit = lambda cfg: sub(r"^aaa authentication login default group NPS-GRP local$",
                           "aaa authentication login default group NPS-GRP local\n"
                           "aaa authentication login VTY group NPS-GRP none")(cfg).replace(
        " transport input ssh", " transport input ssh\n login authentication VTY")
    assert verdict("ios-hardened", "LYSS-AUTH-010", edit)[0] == "fail"


def test_auth_010_a_server_group_named_none_is_not_a_fallback():
    edit = sub(r"^aaa authentication login default group NPS-GRP local$",
               "aaa authentication login default group none local")
    assert verdict("ios-hardened", "LYSS-AUTH-010", edit)[0] == "pass"


# ---------------- LYSS-LOG-010: forwarding turned off ----------------

def test_log_010_fails_when_forwarding_to_syslog_hosts_is_off():
    assert verdict("ios-hardened", "LYSS-LOG-010", add("no logging trap"))[0] == "fail"


# ---------------- LYSS-ACC-011: link aggregations towards servers ----------------

PO_ACCESS = ("interface Port-channel5\n switchport access vlan 10\n switchport mode access\n!\n"
             "interface GigabitEthernet1/0/3\n switchport access vlan 10\n switchport mode access\n"
             " spanning-tree bpduguard enable\n channel-group 5 mode active\n!")


def test_acc_011_access_port_channel_needs_bpdu_guard_on_the_port_channel():
    no_default = sub(r"^spanning-tree portfast edge bpduguard default\n", "")
    guarded_ports = sub(r"^interface GigabitEthernet1/0/1\n switchport mode access$",
                        "interface GigabitEthernet1/0/1\n switchport mode access\n spanning-tree bpduguard enable")
    base = lambda cfg: guarded_ports(no_default(cfg))
    assert verdict("ios-hardened", "LYSS-ACC-011", base)[0] == "pass"
    with_po = lambda cfg: base(cfg).replace("ip access-list standard MGMT", PO_ACCESS + "\nip access-list standard MGMT")
    assert verdict("ios-hardened", "LYSS-ACC-011", with_po)[0] == "fail"
    guarded_po = lambda cfg: with_po(cfg).replace(" switchport mode access\n!\ninterface GigabitEthernet1/0/3",
                                                  " switchport mode access\n spanning-tree bpduguard enable\n!\n"
                                                  "interface GigabitEthernet1/0/3")
    assert verdict("ios-hardened", "LYSS-ACC-011", guarded_po)[0] == "pass"


def test_acc_011_arista_access_port_channel_needs_bpdu_guard():
    no_default = sub(r"^spanning-tree edge-port bpduguard default\n", "")
    c = load_case("arista-hardened")
    po = "interface Port-Channel7\n   switchport access vlan 10\n!\n"
    f = next(f for f in audit(no_default(c["config"]).replace("\nend", "\n" + po + "end"), "arista_eos", 2,
                              c["state"], c["context"]) if f.control_id == "LYSS-ACC-011")
    assert f.verdict == "fail"


# ---------------- LYSS-ACC-020 / 021: trusted access ports ----------------

@pytest.mark.parametrize("fixture, vendor, control, edit", [
    ("cisco_ios.cfg", "cisco_ios", "LYSS-ACC-020",
     sub(r"^ description user$", " description user\n ip dhcp snooping trust")),
    ("cisco_ios.cfg", "cisco_ios", "LYSS-ACC-021",
     sub(r"^ description user$", " description user\n ip arp inspection trust")),
    ("arista_eos.cfg", "arista_eos", "LYSS-ACC-021",
     sub(r"^   switchport access vlan 10$", "   switchport access vlan 10\n   ip arp inspection trust")),
    ("mikrotik.rsc", "mikrotik", "LYSS-ACC-020", sub(r"interface=ether2 pvid=10$", "interface=ether2 pvid=10 trusted=yes")),
    ("mikrotik.rsc", "mikrotik", "LYSS-ACC-021", sub(r"interface=ether2 pvid=10$", "interface=ether2 pvid=10 trusted-arp=yes")),
])
def test_trusted_access_port_fails(fixture, vendor, control, edit):
    assert l3(fixture, vendor, control)[0] == "pass"
    assert l3(fixture, vendor, control, edit)[0] == "fail"


def test_sb_trusted_access_port_fails():
    state = (HERE / "l3" / "cisco_sb.state").read_text(encoding="utf-8")
    for control, line in (("LYSS-ACC-020", " ip dhcp snooping trust"), ("LYSS-ACC-021", " ip arp inspection trust")):
        assert l3("cisco_sb.cfg", "cisco_sb", control, state=state)[0] == "pass"
        edit = sub(r"^interface GigabitEthernet1$", "interface GigabitEthernet1\n" + line)
        assert l3("cisco_sb.cfg", "cisco_sb", control, edit, state)[0] == "fail"


# ---------------- LYSS-ACC-022: open mode ----------------

def test_acc_022_open_authentication_fails():
    assert l3("cisco_ios.cfg", "cisco_ios", "LYSS-ACC-022")[0] == "pass"
    edit = sub(r"^ authentication port-control auto$", " authentication port-control auto\n authentication open")
    assert l3("cisco_ios.cfg", "cisco_ios", "LYSS-ACC-022", edit)[0] == "fail"


# ---------------- LYSS-ACC-023: a 100 % limit limits nothing ----------------

@pytest.mark.parametrize("fixture, vendor, edit, expected", [
    ("cisco_ios.cfg", "cisco_ios", sub(r"^ storm-control broadcast level 5\.00$", " storm-control broadcast level 100.00"), "fail"),
    ("cisco_ios.cfg", "cisco_ios", sub(r"^ storm-control broadcast level 5\.00$", " storm-control broadcast level 100"), "fail"),
    ("arista_eos.cfg", "arista_eos", sub(r"^   storm-control broadcast level 5$", "   storm-control broadcast level 100"), "fail"),
    ("mikrotik.rsc", "mikrotik", sub(r"ether2 storm-rate=5$", "ether2 storm-rate=100"), "unknown"),
    ("cisco_ios.cfg", "cisco_ios", sub(r"^ storm-control broadcast level 5\.00$", " storm-control broadcast level 10.00"), "pass"),
])
def test_acc_023_rejects_a_100_percent_threshold(fixture, vendor, edit, expected):
    assert l3(fixture, vendor, "LYSS-ACC-023", edit)[0] == expected


def test_sb_acc_023_rejects_a_100_percent_threshold():
    state = (HERE / "l3" / "cisco_sb.state").read_text(encoding="utf-8")
    edit = sub(r"^ storm-control broadcast level 5$", " storm-control broadcast level 100")
    assert l3("cisco_sb.cfg", "cisco_sb", "LYSS-ACC-023", edit, state)[0] == "fail"


# ---------------- LYSS-BKP-001: how often backups really run ----------------

def _backup(last_days_ago: float, previous_days_ago: float | None) -> dict:
    now = datetime.now()
    iso = lambda d: (now - timedelta(days=d)).replace(microsecond=0).isoformat()
    return {"last": iso(last_days_ago), "last_automatic": iso(last_days_ago),
            "previous_automatic": iso(previous_days_ago) if previous_days_ago is not None else None,
            "versions": 2, "attestation": None}


@pytest.mark.parametrize("last, previous, expected", [
    (1, 2, "pass"),      # daily
    (1, 8, "pass"),      # weekly, exactly 7 days apart
    (1, 31, "fail"),     # monthly: fresh today, too old most of the month
    (1, None, "pass"),   # first automatic backup: the interval is not known yet
    (9, 10, "fail"),     # stopped: last backup too old
])
def test_bkp_001_checks_the_backup_interval(last, previous, expected):
    assert backup_verdict(_backup(last, previous), 7)[0] == expected
