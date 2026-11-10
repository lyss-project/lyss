# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""AOS-CX configuration layout as the switch prints it (checked on the AOS-CX 10.17 virtual platform):
enabled ports show "no shutdown", disabled ports show nothing, the CLI timeout is stored as
"cli-session" / "timeout N". Also the block filter "where" given as a list. Synthetic data."""

from conftest import load_case

from lyss.config import parse
from lyss.engine import audit, evaluate_rule


def verdict(text: str, state: str, control: str, context=None) -> tuple[str, list]:
    f = next(f for f in audit(text, "aruba_aoscx", 2, state, context) if f.control_id == control)
    return f.verdict, f.evidence


def hardened():
    c = load_case("cx-hardened")
    return c["config"], c["state"], c["context"]


def test_disabled_access_port_without_shutdown_line_is_not_counted():
    # 1/1/2 has "vlan access 10" but no "no shutdown": disabled, so no BPDU guard is needed
    config, state, ctx = hardened()
    assert "interface 1/1/2\n    vlan access 10\n" in config
    assert verdict(config, state, "LYSS-ACC-011", ctx)[0] == "pass"


def test_enabled_access_port_without_bpdu_guard_fails():
    config, state, ctx = hardened()
    config = config.replace("interface 1/1/2\n    vlan access 10\n",
                            "interface 1/1/2\n    no shutdown\n    vlan access 10\n")
    v, evidence = verdict(config, state, "LYSS-ACC-011", ctx)
    assert v == "fail"
    assert any("1/1/2" in e for e in evidence)


def test_disabled_port_does_not_make_its_vlan_a_management_vlan_clash():
    # MGMT-011: an in-band management VLAN shared with a disabled access port is not a clash
    config, state, ctx = hardened()
    config = config.replace("vlan 1,10,99\n", "vlan 1,10,99\ninterface vlan 10\n    ip address 192.0.2.50/24\n")
    config = config.replace("interface mgmt\n    no shutdown\n    ip static 192.0.2.41/24\n", "")
    clash = config.replace("interface 1/1/2\n    vlan access 10\n",
                           "interface 1/1/2\n    no shutdown\n    vlan access 10\n")
    clash = clash.replace("interface 1/1/1\n    no shutdown\n    vlan access 10\n", "interface 1/1/1\n    vlan access 20\n")
    assert verdict(clash, state, "LYSS-MGMT-011", ctx)[0] == "fail"
    only_disabled = config.replace("interface 1/1/1\n    no shutdown\n    vlan access 10\n",
                                   "interface 1/1/1\n    no shutdown\n    vlan access 20\n")
    assert verdict(only_disabled, state, "LYSS-MGMT-011", ctx)[0] == "pass"


def test_cli_session_timeout_block():
    config, state, ctx = hardened()
    assert verdict(config, state, "LYSS-MGMT-004", ctx)[0] == "pass"
    assert verdict(config.replace("    timeout 10\n", "    timeout 30\n"), state, "LYSS-MGMT-004", ctx)[0] == "fail"


def test_not_synchronized_line_fails_even_though_it_contains_synchronized_with():
    # the real "not synchronized" sentence also contains "synchronized with": the fail rule wins
    config, state, ctx = hardened()
    state = state.replace("Synchronized to NTP Server 192.0.2.123 at stratum 2.", "Not synchronized with an NTP server.")
    assert verdict(config, state, "LYSS-LOG-011", ctx)[0] == "fail"


def test_where_list_needs_every_pattern():
    cfg = parse("interface 1/1/1\n    vlan access 10\ninterface 1/1/2\n    no shutdown\n    vlan access 10\n",
                vendor="aruba_aoscx")
    rule = {"block": r"^interface (\S+)$", "where": [r"^vlan access", r"^no shutdown"], "every_contains": r"^no shutdown"}
    ok, evidence = evaluate_rule(cfg, rule)
    assert ok and evidence == ["interface 1/1/2 / no shutdown"]
    assert evaluate_rule(cfg, {"block": r"^interface (\S+)$", "where": r"^vlan access", "every_contains": r"^no shutdown"})[0] is False
