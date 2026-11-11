# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Level 3 (access-layer protection): every adapter implements the five controls, each one is
shown passing (tests/l3/ fixtures) and failing (the Level 2 "hardened" cases, which have no
Level 3 protection), and switches without access ports are not applicable. Synthetic data."""

from pathlib import Path

import pytest

from lyss.engine import (audit, conformance, expand_numbers, load_adapter, load_spec)

HERE = Path(__file__).parent
L3 = [c["id"] for c in load_spec()["controls"] if c["level"] == 3]
ADAPTERS = sorted(p.stem for p in (HERE.parent / "adapters").glob("*.yaml"))
FIXTURES = {   # vendor -> (fully protected configuration, its device state)
    "cisco_ios": ("cisco_ios.cfg", None),
    "cisco_sb": ("cisco_sb.cfg", "cisco_sb.state"),
    "hp_procurve": ("hp_procurve.cfg", "hp_procurve.state"),
    "arista_eos": ("arista_eos.cfg", None),
    "mikrotik": ("mikrotik.rsc", None),
    "aruba_aoscx": ("aruba_aoscx.cfg", None),
    "juniper_junos": ("juniper_junos.cfg", None),
    "huawei_vrp": ("huawei_vrp.cfg", None),
}
UNPROTECTED = {"cisco_ios": "ios-hardened", "cisco_sb": "sb-hardened", "hp_procurve": "hp-hardened",
               "arista_eos": "arista-hardened", "mikrotik": "mikrotik-hardened", "aruba_aoscx": "cx-hardened",
               "juniper_junos": "junos-hardened", "huawei_vrp": "vrp-hardened"}
# a verdict that cannot be shown failing without the setting, with the reason
NEVER_FAILS = {("mikrotik", "LYSS-ACC-023"): "storm-rate is a switch-chip setting: unknown when absent",
               ("juniper_junos", "LYSS-ACC-023"): "most EX models apply 80 % by default: unknown without a profile"}


def _verdicts(text: str, vendor: str, state: str = "") -> dict:
    return {f.control_id: f for f in audit(text, vendor, 3, state) if f.level == 3}


def test_level_3_controls_are_written():
    controls = [c for c in load_spec()["controls"] if c["level"] == 3]
    assert len(controls) == 5
    for c in controls:
        assert c.get("statement") and c.get("rationale") and c.get("test_procedure"), c["id"]
        assert c["mappings"].get("iso27001_2022") and c["mappings"].get("nist_800_53r5"), c["id"]


@pytest.mark.parametrize("vendor", ADAPTERS)
def test_every_adapter_implements_level_3(vendor):
    assert not [c for c in L3 if c not in load_adapter(vendor)["checks"]]


@pytest.mark.parametrize("vendor", sorted(FIXTURES))
def test_protected_access_switch_passes_level_3(vendor):
    cfg, state = FIXTURES[vendor]
    text = (HERE / "l3" / cfg).read_text(encoding="utf-8")
    state_text = (HERE / "l3" / state).read_text(encoding="utf-8") if state else ""
    found = _verdicts(text, vendor, state_text)
    assert {c: f.verdict for c, f in found.items()} == {c: "pass" for c in L3}, \
        {c: (f.verdict, f.evidence) for c, f in found.items() if f.verdict != "pass"}


@pytest.mark.parametrize("vendor", sorted(UNPROTECTED))
def test_level_2_switch_without_access_protection_fails_level_3(vendor):
    case = HERE / "cases" / UNPROTECTED[vendor]
    state = case / "state.txt"
    found = _verdicts((case / "config.cfg").read_text(encoding="utf-8"), vendor,
                      state.read_text(encoding="utf-8") if state.exists() else "")
    for control in L3:
        expected = "unknown" if (vendor, control) in NEVER_FAILS else "fail"
        assert found[control].verdict == expected, (control, found[control].evidence)
        if expected == "fail":
            assert found[control].remediation, control


def test_core_switch_without_access_ports_is_not_applicable():
    text = (HERE / "l3" / "cisco_ios-core.cfg").read_text(encoding="utf-8")
    found = _verdicts(text, "cisco_ios")
    assert {f.verdict for f in found.values()} == {"not_applicable"}
    assert "no enabled access port" in found["LYSS-ACC-020"].evidence[0]


def test_shut_ports_are_not_access_ports_for_level_3():
    # an unused port that is shut down is no access risk: only enabled access ports need 802.1X
    text = (HERE / "l3" / "cisco_ios.cfg").read_text(encoding="utf-8").replace(
        "!\nlldp run", "!\ninterface GigabitEthernet1/0/20\n switchport mode access\n shutdown\n!\nlldp run")
    assert _verdicts(text, "cisco_ios")["LYSS-ACC-022"].verdict == "pass"
    unshut = text.replace(" switchport mode access\n shutdown\n", " switchport mode access\n")
    finding = _verdicts(unshut, "cisco_ios")["LYSS-ACC-022"]
    assert finding.verdict == "fail" and "GigabitEthernet1/0/20" in finding.evidence[0]


def test_sonic_level_3_not_applicable_with_reason():
    text = (HERE / "cases" / "sonic-hardened" / "config.cfg").read_text(encoding="utf-8")
    found = _verdicts(text, "sonic")
    assert {f.verdict for f in found.values()} == {"not_applicable"}
    assert "no untagged VLAN member port" in found["LYSS-ACC-020"].evidence[0]
    # a SONiC switch that does have untagged ports is not waved through: LYSS cannot check it yet
    access = text.rstrip().rstrip("}") + ', "VLAN_MEMBER": {"Vlan10|Ethernet0": {"tagging_mode": "untagged"}}}'
    assert {f.verdict for f in _verdicts(access, "sonic").values()} == {"unknown"}


def test_uncovered_vlan_is_named():
    text = (HERE / "l3" / "cisco_ios.cfg").read_text(encoding="utf-8").replace(
        "ip dhcp snooping vlan 10,20-21", "ip dhcp snooping vlan 10")
    finding = _verdicts(text, "cisco_ios")["LYSS-ACC-020"]
    assert finding.verdict == "fail" and finding.evidence[0] == "access VLANs without DHCP snooping: 20"


def test_voice_ports_keep_cdp_and_lldp():
    # Gi1/0/2 has a voice VLAN and sends CDP/LLDP: exempt; removing the exemption fails it
    text = (HERE / "l3" / "cisco_ios.cfg").read_text(encoding="utf-8")
    assert _verdicts(text, "cisco_ios")["LYSS-ACC-024"].verdict == "pass"
    finding = _verdicts(text.replace(" switchport voice vlan 21\n", ""), "cisco_ios")["LYSS-ACC-024"]
    assert finding.verdict == "fail" and "GigabitEthernet1/0/2" in finding.evidence[0]


def test_vlan_lists():
    assert expand_numbers("10,20-22") == {"10", "20", "21", "22"}
    assert expand_numbers("10 20") == {"10", "20"}
    assert expand_numbers('"5-6, 9"') == {"5", "6", "9"}
    assert expand_numbers("all") == set()


def test_level_3_is_reached_only_on_top_of_level_2():
    findings = audit((HERE / "l3" / "cisco_ios.cfg").read_text(encoding="utf-8"), "cisco_ios", 3)
    assert conformance(findings)["achieved_level"] < 3   # the fixture does not meet Level 1/2
