# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Arista EOS: outputs in the layout of cEOS-lab 4.37.0F (lab, 2026-11), with fictitious names,
addresses and MAC addresses."""

from lyss.collector import COMMANDS
from lyss.config import parse
from lyss.engine import audit, detect_vendor, extract_facts, load_adapter
from lyss.topology import parse_eos_lldp

LLDP_DETAIL = """\
Interface Ethernet1 detected 1 LLDP neighbors:

  Neighbor 0200.0000.0b02/"Ethernet1", age 8 seconds
  Discovered 0:00:40 ago; Last changed 0:00:40 ago
  - Chassis ID type: MAC address (4)
    Chassis ID     : 0200.0000.0b02
  - Port ID type: Interface name (5)
    Port ID     : "Ethernet1"
  - Time To Live: 120 seconds
  - System Name: "lab-eos-02"
  - System Description: "Arista Networks EOS version 4.37.0F-00000000.4370F.1 (engineering build) running on an Arista cEOSLab"
  - System Capabilities : Bridge, Router
    Enabled Capabilities: Bridge
  - Management Address Subtype: IPv4 (1)
    Management Address        : 192.0.2.42
    Interface Number Subtype  : ifIndex (2)
    Interface Number          : 0
  - IEEE802.1 Port VLAN ID: 1
  - IEEE802.3 Link Aggregation
    Link Aggregation Status: Capable, Disabled (0x01)
    Port ID                : 0
  - IEEE802.3 Maximum Frame Size: 9236 bytes
Interface Ethernet2 detected 0 LLDP neighbors:
""".splitlines()

SHOW_VERSION = """\
Arista cEOSLab
Hardware version:
Serial number: FAKE0000030
Hardware MAC address: 0200.0000.0b01
System MAC address: 0200.0000.0b01

Software image version: 4.37.0F-00000000.4370F.1 (engineering build)
Architecture: i686
"""

RUNNING_CONFIG_HEAD = """\
! Command: show running-config at line 1
! device: lab-eos-01 (cEOSLab, EOS-4.37.0F-00000000.4370F.1 (engineering build))
!
no aaa root
!
hostname lab-eos-01
!
spanning-tree mode mstp
!
interface Ethernet1
!
no ip routing
!
end
"""


def test_lldp_detail_gives_the_link_with_the_first_port_id():
    rows = parse_eos_lldp(LLDP_DETAIL)
    assert len(rows) == 1
    row = rows[0]
    assert (row["local_port"], row["remote_port"], row["name"]) == ("ethernet1", "ethernet1", "lab-eos-02")
    assert row["chassis"] == "0200.0000.0b02" and row["ips"] == ["192.0.2.42"] and row["caps"] == "B"
    assert row["platform"].startswith("Arista Networks EOS")


def test_version_is_trimmed_from_the_build_string():
    adapter = load_adapter("arista_eos")
    facts = extract_facts(parse("", f"===== show version =====\n{SHOW_VERSION}"), adapter)
    assert facts["model"] == "cEOSLab" and facts["version"] == "4.37.0F"
    # offline: from the running-config header
    facts = extract_facts(parse(RUNNING_CONFIG_HEAD), adapter)
    assert facts["model"] == "cEOSLab" and facts["version"] == "4.37.0F"


def test_fresh_eos_configuration_is_recognised_and_assessed():
    assert detect_vendor(RUNNING_CONFIG_HEAD) == "arista_eos"
    verdicts = {f.control_id: f.verdict for f in audit(RUNNING_CONFIG_HEAD, "arista_eos", 2)}
    # factory defaults: no Telnet / HTTP, but no idle timeout, AAA, banner, syslog, NTP, ACL
    assert verdicts["LYSS-MGMT-001"] == verdicts["LYSS-MGMT-003"] == "pass"
    for control in ("LYSS-MGMT-004", "LYSS-AUTH-010", "LYSS-MGMT-012", "LYSS-LOG-010",
                    "LYSS-LOG-011", "LYSS-MGMT-010"):
        assert verdicts[control] == "fail", control
    # no account and no enable password at all: nothing to judge
    assert verdicts["LYSS-AUTH-002"] == "unknown"


def test_telnet_state_wording_of_eos_4_37():
    state = "===== show management telnet =====\nTelnet status for Default VRF is enabled \n"
    verdicts = {f.control_id: f.verdict for f in audit(RUNNING_CONFIG_HEAD, "arista_eos", 1, state)}
    assert verdicts["LYSS-MGMT-001"] == "fail"


def test_collector_sends_show_commands_only():
    cmds = COMMANDS["arista_eos"]
    assert cmds["netmiko"] == "arista_eos" and cmds["config"] == "show running-config"
    assert all(c.startswith("show ") for c in cmds["state"])
