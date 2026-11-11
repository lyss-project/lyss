# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Verification of specification 0.8.0-draft (11/11/2026): each case reproduces a gap found between
the specification and the engine or an adapter. Synthetic data."""

from pathlib import Path

from lyss import ci
from lyss.config import parse
from lyss.engine import Finding, audit, conformance, evaluate_control

CASES = Path(__file__).parent / "cases"


def case(name: str) -> str:
    return (CASES / name / "config.cfg").read_text(encoding="utf-8")


def verdict(text: str, vendor: str, control: str, level: int = 2, state: str = ""):
    f = next(f for f in audit(text, vendor, level, state) if f.control_id == control)
    return f.verdict, f.evidence


def finding(control_id, level, v, advisory=False):
    return Finding(control_id, level, control_id, v, [], "", "", {}, advisory)


def test_a_level_whose_controls_are_all_not_applicable_is_met():
    # a core switch without access ports: Level 3 is "pass or not applicable" (section 4)
    core = [finding("a", 1, "pass"), finding("b", 2, "pass"), finding("c", 3, "not_applicable")]
    assert conformance(core)["achieved_level"] == 3
    assert conformance(core[:2] + [finding("c", 3, "unknown")])["achieved_level"] == 2
    assert conformance([finding("a", 1, "fail"), finding("c", 3, "not_applicable")])["achieved_level"] == 0


def test_a_control_without_adapter_check_is_unknown_not_not_applicable():
    control = {"id": "LYSS-X-900", "level": 2, "title": "t", "mappings": {}}
    assert evaluate_control(parse("hostname a\n"), control, None).verdict == "unknown"


def test_ios_port_left_at_its_default_mode_needs_bpdu_guard():
    base = case("ios-hardened")
    assert verdict(base, "cisco_ios", "LYSS-ACC-011")[0] == "pass"
    per_port = base.replace("spanning-tree portfast edge bpduguard default\n", "")
    # an enabled port with no "switchport mode" line acts as an access port: it counts
    unconfigured = per_port + "interface GigabitEthernet1/0/40\n description spare\n!\n"
    assert verdict(unconfigured, "cisco_ios", "LYSS-ACC-011")[0] == "fail"
    shut = per_port + "interface GigabitEthernet1/0/40\n shutdown\n!\n"
    assert verdict(shut, "cisco_ios", "LYSS-ACC-011")[0] == verdict(per_port, "cisco_ios", "LYSS-ACC-011")[0]


def test_ios_disabled_port_in_the_management_vlan_is_not_a_finding():
    base = case("ios-hardened")
    assert verdict(base, "cisco_ios", "LYSS-MGMT-011")[0] == "pass"
    import re
    vlan = re.search(r"(?m)^interface Vlan(\d+)\n ip address \d", base).group(1)
    port = f"interface GigabitEthernet1/0/41\n switchport mode access\n switchport access vlan {vlan}\n"
    assert verdict(base + port + "!\n", "cisco_ios", "LYSS-MGMT-011")[0] == "fail"
    assert verdict(base + port + " shutdown\n!\n", "cisco_ios", "LYSS-MGMT-011")[0] == "pass"


def test_junos_access_port_in_a_vlan_with_a_switch_address_fails():
    base = case("junos-hardened")
    assert verdict(base, "juniper_junos", "LYSS-MGMT-011")[0] == "pass"
    bad = base.replace("vlan members USERS", "vlan members MGMT")
    v, evidence = verdict(bad, "juniper_junos", "LYSS-MGMT-011")
    assert v == "fail" and "MGMT" in evidence[0]


def test_mikrotik_bridge_port_untagged_in_the_management_vlan_fails():
    base = case("mikrotik-hardened")
    state = (CASES / "mikrotik-hardened" / "state.txt").read_text(encoding="utf-8")
    assert verdict(base, "mikrotik", "LYSS-MGMT-011", state=state)[0] == "pass"
    bad = base.replace("interface=ether2 pvid=20", "interface=ether2 pvid=99")
    assert bad != base and verdict(bad, "mikrotik", "LYSS-MGMT-011", state=state)[0] == "fail"


def test_huawei_untagged_hybrid_port_is_an_access_port():
    base = case("vrp-hardened")
    assert verdict(base, "huawei_vrp", "LYSS-ACC-011")[0] == "pass"
    hybrid = base.replace("interface XGigabitEthernet0/0/1\n",
                          "interface GigabitEthernet0/0/9\n port hybrid pvid vlan 10\n port hybrid untagged vlan 10\n#\n"
                          "interface XGigabitEthernet0/0/1\n")
    assert verdict(hybrid, "huawei_vrp", "LYSS-ACC-011")[0] == "fail"       # no "stp edged-port enable"
    uplink = hybrid.replace(" port hybrid untagged vlan 10\n", " port hybrid tagged vlan 10 99\n")
    assert verdict(uplink, "huawei_vrp", "LYSS-ACC-011")[0] == "pass"       # a hybrid uplink is not counted


def test_advisory_failure_is_labelled_and_never_an_error_in_reports():
    result = {"device": "sw.cfg", "vendor": "cisco_ios", "file": "sw.cfg", "summary": {"achieved_level": 1, "pass": 1, "fail": 1, "unknown": 0},
              "findings": [{"control_id": "LYSS-MGMT-001", "level": 1, "title": "t", "verdict": "fail", "evidence": ["x"],
                            "advisory": True, "line": 1}]}
    spec = {"spec_version": "1.1.0", "controls": [{"id": "LYSS-MGMT-001", "level": 1, "title": "t"}]}
    sarif = ci.sarif([result], spec, lambda r: r["file"])["runs"][0]["results"][0]
    assert sarif["level"] == "note" and "advisory" in sarif["message"]["text"]
    assert ci.codequality([result], lambda r: r["file"])[0]["severity"] == "info"
    assert "advisory: not counted" in ci.summary_markdown([result], "1.1.0", 1, 1)


# ---- LYSS-MGMT-010: every remote management path, not only SSH

def test_ios_web_interface_and_snmp_need_a_source_restriction():
    base = case("ios-hardened")
    assert verdict(base, "cisco_ios", "LYSS-MGMT-010")[0] == "pass"
    assert verdict(base.replace("ip http access-class ipv4 MGMT\n", ""), "cisco_ios", "LYSS-MGMT-010")[0] == "fail"
    assert verdict(base.replace("v3 priv access MGMT", "v3 priv"), "cisco_ios", "LYSS-MGMT-010")[0] == "fail"
    assert verdict(base + "snmp-server community s3cretCommunity RO\n", "cisco_ios", "LYSS-MGMT-010")[0] == "fail"
    assert verdict(base + "snmp-server community s3cretCommunity RO 10\n", "cisco_ios", "LYSS-MGMT-010")[0] == "pass"


def test_arista_eapi_and_snmp_need_an_access_list():
    base = case("arista-hardened")
    assert verdict(base, "arista_eos", "LYSS-MGMT-010")[0] == "pass"
    no_cp = base.replace("system control-plane\n   ip access-group MGMT in\n!\n", "")
    v, evidence = verdict(no_cp, "arista_eos", "LYSS-MGMT-010")
    assert v == "fail" and "eAPI" in evidence[0]
    snmp_only = no_cp.replace("management api http-commands\n   no shutdown\n", "management api http-commands\n   shutdown\n")
    assert verdict(snmp_only, "arista_eos", "LYSS-MGMT-010")[0] == "pass"      # SSH ACL + SNMP ACL
    assert verdict(snmp_only.replace("snmp-server ipv4 access-list MGMT\n", ""), "arista_eos", "LYSS-MGMT-010")[0] == "fail"


def test_huawei_web_and_snmp_need_an_acl():
    base = case("vrp-hardened")
    assert verdict(base, "huawei_vrp", "LYSS-MGMT-010")[0] == "pass"
    assert verdict(base.replace("privacy acl 2000", "privacy"), "huawei_vrp", "LYSS-MGMT-010")[0] == "fail"
    web = base.replace("undo http server enable\n", "undo http server enable\nhttp secure-server enable\n")
    assert verdict(web, "huawei_vrp", "LYSS-MGMT-010")[0] == "fail"
    assert verdict(web.replace("http secure-server enable\n", "http secure-server enable\nhttp acl 2000\n"), "huawei_vrp", "LYSS-MGMT-010")[0] == "pass"


def test_sonic_snmp_needs_a_control_plane_acl():
    base = case("sonic-hardened")
    assert verdict(base, "sonic", "LYSS-MGMT-010")[0] == "pass"
    assert verdict(base.replace('"services": ["SSH", "SNMP"]', '"services": ["SSH"]'), "sonic", "LYSS-MGMT-010")[0] == "fail"


def test_aoscx_switched_port_without_vlan_access_line_is_an_access_port():
    base = case("cx-hardened")
    assert verdict(base, "aruba_aoscx", "LYSS-ACC-011")[0] == "pass"
    port = "interface 1/1/5\n    no shutdown\n    no routing\n"
    assert verdict(base.replace("interface 1/1/48\n", port + "interface 1/1/48\n"), "aruba_aoscx", "LYSS-ACC-011")[0] == "fail"
    guarded = port + "    spanning-tree bpdu-guard\n"
    assert verdict(base.replace("interface 1/1/48\n", guarded + "interface 1/1/48\n"), "aruba_aoscx", "LYSS-ACC-011")[0] == "pass"