# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""End-to-end tests on the simulated demo lab (fictitious switches on 127.0.0.1): the real
collector, audit, topology, discovery and remediation run against simulated Cisco IOS,
Cisco SB and HPE Aruba switches, without any hardware."""

import pytest

from lyss import collector, discovery, inventory, remediate, scan, sealed, topology
from lyss.sim import Simulator, load_lab
from lyss.sim.config import RunningConfig
from lyss.sim.render import show


@pytest.fixture
def sim():
    simulator = Simulator(load_lab("demo"), base_port=0).start()
    yield simulator
    simulator.stop()


def register(sim, ids=None) -> list[dict]:
    creds = sim.lab.credentials
    sim.pin_host_keys()
    for sw in sim.lab.switches.values():
        if ids is None or sw.id in ids:
            inventory.save_device({"id": sw.id, "host": "127.0.0.1", "port": sw.port, "vendor": sw.platform,
                                   "username": creds["username"], "via_jump": False}, creds["password"])
    return inventory.load_devices()


def collect(devices) -> dict:
    status = {}
    collector.collect_many(devices, {}, lambda device_id, s, message: status.__setitem__(device_id, (s, message)))
    return status


# what the demo lab is designed to show (see src/lyss/sim/labs/demo/lab.yaml), Level 3 included
LEVEL3 = {"LYSS-ACC-020", "LYSS-ACC-021", "LYSS-ACC-022", "LYSS-ACC-023", "LYSS-ACC-024"}
EXPECTED_FAILS = {
    "demo-core": LEVEL3,                       # Level 2; no access-layer protection on its user ports
    "demo-acc-01": {"LYSS-MGMT-004", "LYSS-AUTH-010", "LYSS-MGMT-010", "LYSS-MGMT-012", "LYSS-LOG-010",
                    "LYSS-ACC-010", "LYSS-ACC-011"} | LEVEL3,
    "demo-sb-01": {"LYSS-MGMT-010", "LYSS-MGMT-012", "LYSS-ACC-010", "LYSS-ACC-011"} | LEVEL3,
    # RouterOS factory defaults, 7.24.1 = one point release before the CISA KEV fixes
    "demo-crs-01": {"LYSS-MGMT-001", "LYSS-MGMT-003", "LYSS-VULN-001", "LYSS-AUTH-010", "LYSS-MGMT-010",
                    "LYSS-MGMT-011", "LYSS-MGMT-012", "LYSS-MGMT-013", "LYSS-LOG-010", "LYSS-ACC-010",
                    "LYSS-ACC-011", "LYSS-ACC-020", "LYSS-ACC-021", "LYSS-ACC-022", "LYSS-ACC-024"},
    # well-run SONiC switch, except SONiC's own "public" community and cleartext TACACS+ key
    "demo-leaf-01": {"LYSS-AUTH-001", "LYSS-AUTH-004", "LYSS-AUTH-011", "LYSS-ACC-010"},
    # Arista campus switch hardened to Level 3 (simulated EOS, fixed outputs)
    "demo-eos-01": set(),
}
# preview platforms: controls they cannot show both ways stay unknown (see tests/test_controls.py)
EXPECTED_UNKNOWNS = {
    "demo-crs-01": {"LYSS-AUTH-002", "LYSS-ACC-023"},   # CRS storm-rate: switch-chip setting
    "demo-leaf-01": {"LYSS-VULN-001", "LYSS-ACC-011"},
}


def test_whole_lab_is_collected_audited_and_mapped(data_dir, sim):
    devices = register(sim)
    inventory.save_settings({**inventory.load_settings(), "level3": True})   # as the demo does
    status = collect(devices)
    assert all(s == "collected" for s, _ in status.values()), status

    results = {d["id"]: scan.audit_device(d, "schedule") for d in devices}
    for sw in sim.lab.switches.values():
        result = results[sw.id]
        cfg, state = collector.config_paths(inventory.get_device(sw.id))
        assert sw.hostname in sealed.read_text(cfg)
        for command in collector.COMMANDS[sw.platform]["state"]:
            assert f"===== {command} =====" in sealed.read_text(state)
        if sw.platform == "hp_procurve":
            # HP verdicts belong to the HP adapter tests; here: collection and facts only
            assert "JL253A" in result["model"] and result["firmware"] == "WC.16.10.0012"
            continue
        assert result["model"] == sw.model and result["firmware"] == sw.version
        assert result["summary"]["achieved_level"] == sw.spec["expected_level"], (sw.id, result["summary"])
        if sw.id in EXPECTED_FAILS:
            fails = {f["control_id"] for f in result["findings"] if f["verdict"] == "fail"}
            assert fails == EXPECTED_FAILS[sw.id], sw.id
        unknown = {f["control_id"] for f in result["findings"] if f["verdict"] == "unknown"}
        assert unknown == EXPECTED_UNKNOWNS.get(sw.id, set()), sw.id

    graph = topology.build()
    managed = {frozenset((e["a"], e["b"])) for e in graph["edges"] if not (e["a"] + e["b"]).count("ext:")}
    assert managed == {frozenset(pair) for pair in [
        ("demo-core", "demo-acc-01"), ("demo-core", "demo-acc-02"), ("demo-core", "demo-sb-01"),
        ("demo-core", "demo-hp-01"), ("demo-acc-01", "demo-sb-02"),
        ("demo-acc-01", "demo-crs-01"), ("demo-acc-01", "demo-leaf-01"), ("demo-core", "demo-eos-01")]}
    core_acc = next(e for e in graph["edges"] if {e["a"], e["b"]} == {"demo-core", "demo-acc-01"})
    assert core_acc["ports"][0]["confirmed"]  # seen from both ends
    externals = {n["label"].split(".")[0]: n["kind"] for n in graph["nodes"] if not n["managed"]}
    assert externals == {"DEMO-AP-01": "ap", "DEMO-LAB-SW": "switch"}

    # the unmanaged switch announced over CDP becomes a discovery candidate; managed ones do not
    discovery.from_neighbors()
    assert set(discovery.load()["candidates"]) == {"198.51.100.40"}


def test_remediation_end_to_end_on_a_simulated_switch(data_dir, sim):
    devices = register(sim, {"demo-acc-02"})
    inventory.save_settings({**inventory.load_settings(), "remediation": {"enabled": True}})
    device = devices[0]
    assert collect(devices)["demo-acc-02"][0] == "collected"
    before = scan.audit_device(device, "manual")
    failing = {f["control_id"] for f in before["findings"] if f["verdict"] == "fail"}
    # one command each (netmiko waits ~2 s per configuration command); Telnet on the vty lines
    # is covered by test_configuration_commands_change_the_state_outputs
    fixes = ["LYSS-MGMT-002", "LYSS-MGMT-003"]
    assert set(fixes) <= failing

    steps = []
    entry = remediate.apply_device(device, fixes, None, lambda message, percent=None: steps.append(percent))
    assert entry["outcome"] == "applied and saved", entry
    assert sorted(entry["applied"]) == fixes and entry["saved"]

    sw = sim.lab.switches["demo-acc-02"]
    assert sw.saved == sw.running.text()                    # written to the startup configuration
    assert "no ip http server" in sw.running.top() and "ip http server" not in sw.running.top()
    assert sw.ssh_banner().startswith("SSH-2.0-")           # SSHv1 no longer offered
    after = {f["control_id"]: f["verdict"] for f in inventory.load_result("demo-acc-02")["findings"]}
    assert all(after[c] == "pass" for c in fixes)
    assert remediate.load_changes()[0]["outcome"] == "applied and saved"


def test_wrong_password_is_rejected(data_dir, sim):
    sw = sim.lab.switches["demo-core"]
    inventory.save_device({"id": "demo-core", "host": "127.0.0.1", "port": sw.port, "vendor": "cisco_ios",
                           "username": "lyss-demo", "via_jump": False}, "not-the-password")
    status = collect(inventory.load_devices())
    assert status["demo-core"][0] == "error" and "uthentication" in status["demo-core"][1]


def test_configuration_commands_change_the_state_outputs():
    lab = load_lab("demo")
    sw = lab.switches["demo-sb-02"]                         # Cisco SB: Telnet and HTTP on by default
    ports = show(sw, "show services tcp-udp")
    assert "All:23" in ports and "All:80" in ports
    sw.running.configure(None, "no ip telnet server")
    sw.running.configure(None, "no ip http server")
    assert "no ip telnet server" in sw.running.top()
    ports = show(sw, "show services tcp-udp")
    assert "All:23" not in ports and "All:80" not in ports
    sw.running.configure(None, "ip telnet server")          # back to the default: the line goes
    assert "no ip telnet server" not in sw.running.top()

    ios = lab.switches["demo-acc-02"]
    ios.running.configure(None, "no snmp-server community public")
    assert not any(l.startswith("snmp-server community public") for l in ios.running.top())
    vty = ios.running.open_block("line vty 0 4")
    assert "*:23" in show(ios, "show control-plane host open-ports")     # Telnet allowed on vty lines
    for block in ios.running.blocks(r"^line vty"):
        ios.running.configure(block, "transport input ssh")
    vty = ios.running.find_block("line vty 0 4")
    assert vty.children.count("transport input ssh") == 1 and "transport input telnet ssh" not in vty.children
    assert "*:23" not in show(ios, "show control-plane host open-ports")


def test_sb_multiline_banner_round_trip():
    text = "hostname X\nbanner login ^\nAuthorized access only.\n^\ninterface vlan 1\n ip address 192.0.2.1 255.255.255.0\nexit\n"
    cfg = RunningConfig(text, "cisco_sb")
    assert cfg.text() == text
    cfg.set_banner("login", ["New text"], "^")
    assert "banner login ^\nNew text\n^" in cfg.text()


def test_simulated_lab_contains_only_documentation_addresses():
    import re
    lab = load_lab("demo")
    text = "\n".join((lab.folder / f"{sid}.cfg").read_text(encoding="utf-8") for sid in lab.switches)
    text += (lab.folder / "lab.yaml").read_text(encoding="utf-8")
    network = re.compile(r"(?i)(address|host|server|logging|permit|mgmt_ip|\bip:)")
    ips = [ip for line in text.splitlines() if network.search(line)
           for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)]
    assert ips
    for ip in ips:
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "255.", "0.0.0.")), ip
    for mac in re.findall(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", text, re.I):
        assert mac.lower().startswith("00:00:5e:00:53:"), mac
