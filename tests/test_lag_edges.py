# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Link aggregations towards end devices (servers) are edge ports (LYSS-ACC-011) on Cisco Business,
HPE AOS-S and RouterOS; HPE trusted ports and 100 % broadcast limits (LYSS-ACC-020/021/023).
Synthetic data."""

from pathlib import Path

from conftest import load_case

from lyss.engine import audit

HERE = Path(__file__).parent


def verdict(text: str, vendor: str, state: str, control: str, level: int = 2, context=None) -> tuple[str, list]:
    f = next(f for f in audit(text, vendor, level, state, context) if f.control_id == control)
    return f.verdict, f.evidence


def case(name: str):
    c = load_case(name)
    return c["config"], c["state"], c["context"]


# ---------------- HPE AOS-S: trunk group to a server ----------------

def hp_with_server_trunk(protected: bool) -> str:
    config, _, _ = case("hp-hardened")
    config = config.replace("trunk 27-28 trk1 lacp", "trunk 27-28 trk1 lacp\ntrunk 23-24 trk2 lacp")
    config = config.replace("   untagged 1-26\n", "   untagged 1-26,Trk2\n")
    if protected:
        config = config.replace("spanning-tree 1-26 bpdu-protection",
                                "spanning-tree 1-26 bpdu-protection\nspanning-tree Trk2 bpdu-protection")
    assert "trk2" in config
    return config


def test_hp_uplink_trunk_group_is_not_an_edge_port():
    config, state, ctx = case("hp-hardened")
    assert verdict(config, "hp_procurve", state, "LYSS-ACC-011", context=ctx)[0] == "pass"


def test_hp_trunk_group_tagged_in_no_vlan_is_unknown_until_protected():
    # field report 12/11/2026: a trunk group carrying only untagged VLAN 1 may link two switches
    # (BPDU protection would cut it) or go to a server: the configuration cannot tell, so unknown
    _, state, ctx = case("hp-hardened")
    f = next(f for f in audit(hp_with_server_trunk(False), "hp_procurve", 2, state, ctx) if f.control_id == "LYSS-ACC-011")
    assert f.verdict == "unknown" and any("trk2" in e for e in f.evidence), f.evidence
    assert "never if it links two switches" in f.note
    assert verdict(hp_with_server_trunk(True), "hp_procurve", state, "LYSS-ACC-011", context=ctx)[0] == "pass"


def hp_l3(edit=None) -> tuple[str, str]:
    text = (HERE / "l3" / "hp_procurve.cfg").read_text(encoding="utf-8")
    state = (HERE / "l3" / "hp_procurve.state").read_text(encoding="utf-8")
    return (edit(text) if edit else text), state


def test_hp_trusted_access_port_fails_snooping_and_arp_protection():
    text, state = hp_l3()
    for control in ("LYSS-ACC-020", "LYSS-ACC-021"):
        assert verdict(text, "hp_procurve", state, control, 3)[0] == "pass"
    text, state = hp_l3(lambda t: t.replace("dhcp-snooping trust Trk1", "dhcp-snooping trust 1,Trk1")
                        .replace("arp-protect trust Trk1", "arp-protect trust 2,Trk1"))
    v, ev = verdict(text, "hp_procurve", state, "LYSS-ACC-020", 3)
    assert v == "fail" and "non-uplink ports trusted for DHCP snooping: 1" in ev[0], ev
    v, ev = verdict(text, "hp_procurve", state, "LYSS-ACC-021", 3)
    assert v == "fail" and "non-uplink ports trusted for ARP protection: 2" in ev[0], ev


def test_hp_100_percent_broadcast_limit_fails():
    text, state = hp_l3()
    assert verdict(text, "hp_procurve", state, "LYSS-ACC-023", 3)[0] == "pass"
    text, state = hp_l3(lambda t: t.replace("interface 1\n   rate-limit bcast in percent 5",
                                            "interface 1\n   rate-limit bcast in percent 100", 1))
    assert verdict(text, "hp_procurve", state, "LYSS-ACC-023", 3)[0] == "fail"


# ---------------- Cisco Business: port-channel to a server ----------------

def sb_with_port_channel(body: str) -> str:
    config, _, _ = case("sb-hardened")
    assert "line ssh" in config
    return config.replace("line ssh", f"interface Port-channel1\n{body}exit\nline ssh", 1)


def test_sb_port_channel_to_a_server_needs_bpdu_guard():
    config, state, ctx = case("sb-hardened")
    assert verdict(config, "cisco_sb", state, "LYSS-ACC-011", context=ctx)[0] == "pass"  # no port-channel
    v, ev = verdict(sb_with_port_channel(" switchport access vlan 10\n"), "cisco_sb", state, "LYSS-ACC-011", context=ctx)
    assert v == "fail" and any("Port-channel1" in e for e in ev), ev
    guarded = " switchport access vlan 10\n spanning-tree bpduguard enable\n"
    assert verdict(sb_with_port_channel(guarded), "cisco_sb", state, "LYSS-ACC-011", context=ctx)[0] == "pass"
    trunk = " switchport mode trunk\n"
    assert verdict(sb_with_port_channel(trunk), "cisco_sb", state, "LYSS-ACC-011", context=ctx)[0] == "pass"


# ---------------- RouterOS: a bond is a bridge port like any other ----------------

def test_mikrotik_bond_to_a_server_is_checked_as_a_bridge_port():
    config, state, ctx = case("mikrotik-hardened")
    bond = ("2 interface=bond1 bridge=bridge edge=yes pvid=20 "
            "frame-types=admit-only-untagged-and-priority-tagged bpdu-guard=")
    marker = "1 interface=ether2 bridge=bridge"
    assert marker in state
    for guard, expected in (("yes", "pass"), ("no", "fail")):
        new_state = state.replace(marker, f"{bond}{guard}\n{marker}", 1)
        assert verdict(config, "mikrotik", new_state, "LYSS-ACC-011", context=ctx)[0] == expected
