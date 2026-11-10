# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Level 3 on Juniper EX (ELS) and Huawei S series (VRP): rules written from the vendors'
documentation (preview platforms). Each special case is shown both ways. Synthetic data."""

from pathlib import Path

from lyss.engine import audit

L3 = Path(__file__).parent / "l3"


def v(text: str, vendor: str, control: str) -> tuple[str, list]:
    f = next(f for f in audit(text, vendor, 3) if f.control_id == control)
    return f.verdict, f.evidence


def junos() -> str:
    return (L3 / "juniper_junos.cfg").read_text(encoding="utf-8")


def vrp() -> str:
    return (L3 / "huawei_vrp.cfg").read_text(encoding="utf-8")


# ---- Junos -------------------------------------------------------------------------------------

def test_junos_trusted_group_with_an_access_port_fails():
    trusted = ("set vlans USERS forwarding-options dhcp-security group SRV overrides trusted\n"
               "set vlans USERS forwarding-options dhcp-security group SRV interface ge-0/0/0.0\n")
    assert v(junos() + trusted, "juniper_junos", "LYSS-ACC-020")[0] == "fail"
    assert v(junos() + trusted, "juniper_junos", "LYSS-ACC-021")[0] == "fail"
    uplink = trusted.replace("ge-0/0/0.0", "xe-0/1/0.0")   # a trunk may be trusted
    assert v(junos() + uplink, "juniper_junos", "LYSS-ACC-020")[0] == "pass"


def test_junos_vlan_without_dhcp_security_is_named():
    text = junos().replace("set vlans VOICE-USERS forwarding-options dhcp-security arp-inspection\n", "")
    verdict, evidence = v(text, "juniper_junos", "LYSS-ACC-020")
    assert verdict == "fail" and evidence[0] == "access VLANs without DHCP snooping: VOICE-USERS"


def test_junos_dot1x_needs_a_profile_and_every_access_port():
    no_profile = junos().replace("set protocols dot1x authenticator authentication-profile-name NAC\n", "")
    assert v(no_profile, "juniper_junos", "LYSS-ACC-022")[0] == "fail"
    one_missing = junos().replace("set protocols dot1x authenticator interface ge-0/0/2.0 mac-radius\n", "")
    assert v(one_missing, "juniper_junos", "LYSS-ACC-022") == ("fail", ["access ports without 802.1X / MAC RADIUS: ge-0/0/2", "interfaces ge-0/0/2"])
    every = one_missing.replace("interface ge-0/0/0.0 supplicant multiple", "interface all supplicant multiple")
    assert v(every, "juniper_junos", "LYSS-ACC-022")[0] == "pass"


def test_junos_storm_profile_of_100_percent_or_without_broadcast_fails():
    for bad in ("bandwidth-percentage 100", "no-broadcast"):
        text = junos().replace("storm-control-profiles USER-SC all bandwidth-percentage 5", f"storm-control-profiles USER-SC all {bad}")
        assert v(text, "juniper_junos", "LYSS-ACC-023")[0] == "fail", bad
    unknown = junos().replace("set interfaces ge-0/0/2 unit 0 family ethernet-switching storm-control USER-SC\n", "")
    assert v(unknown, "juniper_junos", "LYSS-ACC-023")[0] == "unknown"   # the 80 % default may apply


def test_junos_lldp_voice_port_exempt_and_global_disable():
    assert v(junos(), "juniper_junos", "LYSS-ACC-024")[0] == "pass"      # ge-0/0/2 is a VoIP port
    no_voip = junos().replace("set switch-options voip interface ge-0/0/2.0 vlan VOICE\n", "")
    assert v(no_voip, "juniper_junos", "LYSS-ACC-024")[0] == "fail"
    assert v(no_voip + "set protocols lldp disable\n", "juniper_junos", "LYSS-ACC-024")[0] == "pass"


# ---- Huawei VRP --------------------------------------------------------------------------------

def test_vrp_snooping_needs_both_global_switches():
    assert v(vrp().replace("dhcp snooping enable\n#\nvlan batch", "vlan batch"), "huawei_vrp", "LYSS-ACC-020")[0] == "fail"
    assert v(vrp().replace("#\ndhcp enable\n", "\n"), "huawei_vrp", "LYSS-ACC-020")[0] == "fail"


def test_vrp_snooping_per_port_instead_of_per_vlan():
    per_port = (vrp().replace("vlan 10\n dhcp snooping enable\n", "vlan 10\n")
                .replace(" port default vlan 10\n", " port default vlan 10\n dhcp snooping enable\n"))
    assert v(per_port, "huawei_vrp", "LYSS-ACC-020")[0] == "pass"
    missing = vrp().replace("vlan 10\n dhcp snooping enable\n", "vlan 10\n")
    assert v(missing, "huawei_vrp", "LYSS-ACC-020")[0] == "fail"


def test_vrp_trusted_access_port_fails():
    text = vrp().replace(" port default vlan 20\n", " port default vlan 20\n dhcp snooping trusted\n")
    assert v(text, "huawei_vrp", "LYSS-ACC-020")[0] == "fail"


def test_vrp_authentication_profile_must_run_dot1x_or_mac():
    empty = vrp().replace(" dot1x-access-profile d1x\n mac-access-profile mac\n", "")
    assert v(empty, "huawei_vrp", "LYSS-ACC-022")[0] == "fail"
    common = (vrp().replace(" authentication-profile nac\n", " dot1x enable\n")
              .replace("dot1x-access-profile name d1x\n", "dot1x enable\n#\ndot1x-access-profile name d1x\n"))
    assert v(common, "huawei_vrp", "LYSS-ACC-022")[0] == "pass"


def test_vrp_storm_control_forms_and_100_percent():
    assert v(vrp(), "huawei_vrp", "LYSS-ACC-023")[0] == "pass"   # broadcast-suppression and storm-control
    assert v(vrp().replace("broadcast-suppression 5", "broadcast-suppression 100"), "huawei_vrp", "LYSS-ACC-023")[0] == "fail"


def test_vrp_lldp_receive_only_voice_exempt_global_off():
    assert v(vrp(), "huawei_vrp", "LYSS-ACC-024")[0] == "pass"
    sending = vrp().replace(" lldp admin-status rx\n", "")
    assert v(sending, "huawei_vrp", "LYSS-ACC-024")[0] == "fail"
    assert v(sending.replace("#\ndhcp enable\n", "#\nundo lldp enable\n#\ndhcp enable\n"), "huawei_vrp", "LYSS-ACC-024")[0] == "pass"


def test_junos_only_a_trusted_group_trusts_its_ports():
    # review 0.18: an access port in a group with another override (no-option82) is not trusted,
    # even when some other group of the switch is
    other = ("set vlans USERS forwarding-options dhcp-security group NO82 overrides no-option82\n"
             "set vlans USERS forwarding-options dhcp-security group NO82 interface ge-0/0/0.0\n"
             "set vlans USERS forwarding-options dhcp-security group UPLINK overrides trusted\n"
             "set vlans USERS forwarding-options dhcp-security group UPLINK interface xe-0/1/0.0\n")
    assert v(junos() + other, "juniper_junos", "LYSS-ACC-020")[0] == "pass"
    assert v(junos() + other, "juniper_junos", "LYSS-ACC-021")[0] == "pass"


def test_vrp_storm_control_max_rate_100_percent_fails():
    text = vrp().replace("max-rate percent 5", "max-rate percent 100")
    assert v(text, "huawei_vrp", "LYSS-ACC-023")[0] == "fail"


def test_vrp_port_bound_to_a_profile_without_dot1x_or_mac_fails():
    # a second profile (e.g. web portal only) bound to an access port does not count
    text = (vrp().replace("authentication-profile name nac\n", "authentication-profile name portal\n#\nauthentication-profile name nac\n")
            .replace(" port default vlan 20\n stp edged-port enable\n authentication-profile nac\n",
                     " port default vlan 20\n stp edged-port enable\n authentication-profile portal\n"))
    verdict, evidence = v(text, "huawei_vrp", "LYSS-ACC-022")
    assert verdict == "fail"