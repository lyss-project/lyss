# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Specification 0.5.0-draft: each case reproduces a weakness found in review (intuitem/ciso-assistant-
community#5246), where a test procedure was looser than its statement. Starting from a hardened
synthetic configuration, one change must flip the control to "fail" (or keep it passing when the
change is legitimate)."""

import re

import pytest
from conftest import load_case

from lyss.engine import audit


def verdict(case: str, control: str, edit=None, state: str | None = None) -> str:
    c = load_case(case)
    config = edit(c["config"]) if edit else c["config"]
    findings = audit(config, c["vendor"], 2, c["state"] if state is None else state, c["context"])
    return next(f.verdict for f in findings if f.control_id == control)


def add(text):
    return lambda cfg: cfg.rstrip("\n") + "\n" + text + "\n"


def sub(pattern, repl):
    def edit(cfg):
        new, n = re.subn(pattern, repl, cfg, flags=re.M)
        assert n, f"pattern not found: {pattern}"
        return new
    return edit


NTP_STATE = "===== show ntp status =====\n{}\n"
SNTP_STATE = "===== show sntp status =====\n{}\n"


@pytest.mark.parametrize("case, edit, expected", [
    # LYSS-AUTH-002: MD5 (type 5) and flawed SHA-256 (type 4) are not strong hashes
    ("ios-hardened", None, "pass"),
    ("ios-hardened", sub(r"^enable algorithm-type scrypt secret 9 \S+", "enable secret 5 $1$FAKE$FAKEFAKEFAKEFAKEFAKE"), "fail"),
    ("ios-hardened", sub(r"^enable algorithm-type scrypt secret 9 \S+", "enable secret 4 FAKEFAKEFAKEFAKEFAKE"), "fail"),
    ("ios-hardened", sub(r"^username admin privilege 15 secret 9 \S+", "username admin privilege 15 secret 5 $1$FAKE$FAKE"), "fail"),
    # Cisco Business: 40 hex digits = unsalted SHA-1
    ("sb-hardened", None, "pass"),
    ("sb-hardened", sub(r"^enable password level 15 encrypted \S+", "enable password level 15 encrypted " + "ab" * 20), "fail"),
    ("sb-hardened", sub(r"^(username admin password encrypted) \S+", r"\1 " + "ab" * 20), "fail"),
    # HPE AOS-S: sha1 is not accepted, sha256 is
    ("hp-hardened", None, "pass"),
    ("hp-hardened", sub(r"\bsha256\b", "sha1"), "fail"),
])
def test_auth_002_strong_hash_only(case, edit, expected):
    assert verdict(case, "LYSS-AUTH-002", edit) == expected


@pytest.mark.parametrize("case, edit, expected", [
    ("ios-hardened", add("snmp-server group RO v3 auth"), "fail"),
    ("ios-hardened", add("snmp-server group RO v3 noauth"), "fail"),
    ("ios-hardened", add("snmp-server group RO2 v3 priv"), "pass"),
    ("sb-hardened", add("snmp-server group RO v3 auth read Default"), "fail"),
    ("sb-hardened", add("snmp-server group RO v3 noauth read Default"), "fail"),
    ("hp-hardened", add('snmpv3 user "ro" auth sha "FAKEHASH"'), "fail"),
    ("hp-hardened", add("snmpv3 group operatornoauth user \"ro\" sec-model ver3"), "fail"),
])
def test_auth_011_snmpv3_requires_auth_priv(case, edit, expected):
    assert verdict(case, "LYSS-AUTH-011", edit) == expected


@pytest.mark.parametrize("case, edit, expected", [
    ("ios-hardened", None, "pass"),
    # a line password before AAA ends the method list without AAA
    ("ios-hardened", sub(r"^aaa authentication login default group", "aaa authentication login default line group"), "fail"),
    # a named local-only list used by the vty lines bypasses AAA
    ("ios-hardened", add("aaa authentication login VTY local\nline vty 5 15\n login authentication VTY"), "fail"),
    # a local-only list used by the console only is fine
    ("ios-hardened", add("aaa authentication login CONSOLE local\nline con 0\n login authentication CONSOLE"), "pass"),
    ("sb-hardened", None, "pass"),
    ("sb-hardened", sub(r"^aaa authentication login default radius local", "aaa authentication login default local radius"), "fail"),
    ("sb-hardened", add("aaa authentication login SSHLOCAL local\nline ssh\n login authentication SSHLOCAL\nexit"), "fail"),
])
def test_auth_010_aaa_first_on_every_remote_login_path(case, edit, expected):
    assert verdict(case, "LYSS-AUTH-010", edit) == expected


@pytest.mark.parametrize("case, edit, expected", [
    ("ios-hardened", None, "pass"),
    ("ios-hardened", add("interface GigabitEthernet1/0/9\n switchport mode access\n switchport access vlan 10"), "fail"),
    ("ios-hardened", add("interface GigabitEthernet1/0/9\n switchport mode access\n switchport access vlan 20"), "pass"),
    ("sb-hardened", None, "pass"),
    ("sb-hardened", add("interface GigabitEthernet5\n switchport access vlan 50\nexit"), "fail"),
    ("hp-hardened", None, "pass"),
    # untagged user ports in the management VLAN (not tagged anywhere, not a trunk group)
    ("hp-hardened", sub(r"^(vlan 99\n(?:   .*\n)*?   tagged Trk1)", r"\1\n   untagged 25"), "fail"),
    # an uplink: port 26 carries VLAN 10 tagged and the management VLAN untagged (native)
    ("hp-hardened", lambda cfg: sub(r"^(vlan 99\n(?:   .*\n)*?   tagged Trk1)", r"\1\n   untagged 26")(
        sub(r"^   untagged 1-26$", "   untagged 1-25\n   tagged 26")(cfg)), "pass"),
])
def test_mgmt_011_no_access_port_in_the_management_vlan(case, edit, expected):
    assert verdict(case, "LYSS-MGMT-011", edit) == expected


@pytest.mark.parametrize("case, edit, expected", [
    ("ios-hardened", sub(r"^banner login .*$", "banner login ^CWelcome to the lab switch^C"), "fail"),
    ("ios-hardened", sub(r"^banner login .*$", "banner motd ^CUnauthorised access is prohibited.^C"), "pass"),
    ("sb-hardened", sub(r"^banner login \^\nAuthorized access only\. Activity is logged\.\n\^", "banner login ^\nWelcome\n^"), "fail"),
    ("sb-hardened", sub(r"^banner login", "banner exec"), "fail"),  # shown only after login
    ("hp-hardened", sub(r"^banner motd", "banner exec"), "fail"),
])
def test_mgmt_012_pre_login_banner_states_authorized_use(case, edit, expected):
    assert verdict(case, "LYSS-MGMT-012", edit) == expected


@pytest.mark.parametrize("case, edit", [("ios-hardened", add("no logging on")), ("sb-hardened", add("no logging on"))])
def test_log_010_fails_when_logging_is_disabled_globally(case, edit):
    assert verdict(case, "LYSS-LOG-010") == "pass"
    assert verdict(case, "LYSS-LOG-010", edit) == "fail"


@pytest.mark.parametrize("case, section, text, expected", [
    ("ios-hardened", NTP_STATE, "Clock is unsynchronized, stratum 16, no reference clock", "fail"),
    ("ios-hardened", NTP_STATE, "Clock is synchronized, stratum 3, reference is 192.0.2.123", "pass"),
    ("sb-hardened", SNTP_STATE, "Clock is not synchronized", "fail"),
    ("sb-hardened", SNTP_STATE, "Clock is synchronized, stratum 2, reference is 192.0.2.123, unicast", "pass"),
])
def test_log_011_checks_clock_synchronization_when_state_is_collected(case, section, text, expected):
    state = load_case(case)["state"] + section.format(text)
    assert verdict(case, "LYSS-LOG-011", state=state) == expected


def test_acc_011_neighbour_discovery_never_exempts_a_port():
    """Cisco Business: an access port where LLDP sees a bridge is still an edge port."""
    c = load_case("sb-hardened")
    lldp = "===== show lldp neighbors =====\nPort  Device ID  Port ID  System Name  Capabilities  TTL\ngi1  00:00:5e:00:53:99  gi9  rogue  B  120\n"
    edit = sub(r"^(interface GigabitEthernet1\n switchport mode access)\n spanning-tree bpduguard enable", r"\1")
    findings = audit(edit(c["config"]), c["vendor"], 2, c["state"] + lldp, c["context"])
    f = next(f for f in findings if f.control_id == "LYSS-ACC-011")
    assert f.verdict == "fail", f.evidence
