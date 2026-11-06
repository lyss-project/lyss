# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""SONiC: config_db JSON flattened into blocks, secrets redacted, platform recognised. Synthetic data."""

import json

from lyss import discovery
from lyss.collector import COMMANDS
from lyss.config import flatten_json, parse
from lyss.engine import audit, redact

CONFIG = {
    "SNMP_COMMUNITY": {"public": {"TYPE": "RO"}},
    "TACPLUS_SERVER": {"192.0.2.49": {"passkey": "FakeTacKey1", "priority": "1"}},
    "ACL_TABLE": {"SSH_ONLY": {"services": ["SSH", "SNMP"], "type": "CTRLPLANE"}},
    "BANNER_MESSAGE": {"global": {"login": "Authorized access only.\nActivity is logged.", "state": "enabled"}},
    "VLAN_INTERFACE": {"Vlan1": {}, "Vlan1|192.0.2.10/24": {}},
    "VERSIONS": {"DATABASE": {"VERSION": "version_202505_01"}},
}


def test_flatten_json_one_block_per_entry_sorted():
    text = flatten_json(CONFIG)
    assert "ACL_TABLE|SSH_ONLY\n  services=SSH,SNMP\n  type=CTRLPLANE\n" in text
    assert "VLAN_INTERFACE|Vlan1\nVLAN_INTERFACE|Vlan1|192.0.2.10/24\n" in text
    # a multi-line value stays on one line, so a field can never fake a block header
    assert "  login=Authorized access only.\\nActivity is logged.\n" in text
    assert text.index("ACL_TABLE") < text.index("BANNER_MESSAGE") < text.index("VLAN_INTERFACE")


def test_parse_detects_json_and_builds_blocks():
    cfg = parse(json.dumps(CONFIG, indent=4))
    headers = [b.header for b in cfg.blocks]
    assert "TACPLUS_SERVER|192.0.2.49" in headers
    block = next(b for b in cfg.blocks if b.header == "ACL_TABLE|SSH_ONLY")
    assert "type=CTRLPLANE" in [c.strip() for c in block.children]


def test_parse_keeps_invalid_json_as_text():
    cfg = parse("{ not json\nhostname x\n")
    assert any("hostname x" in line for line in cfg.lines)


def test_redact_json_fields_and_communities():
    assert redact("  passkey=FakeTacKey1") == "  passkey=<redacted>"
    assert redact("  SNMP_USER_AUTH_PASSWORD=FakeAuth9") == "  SNMP_USER_AUTH_PASSWORD=<redacted>"
    assert redact("SNMP_COMMUNITY|n0t-public") == "SNMP_COMMUNITY|<redacted>"
    # well-known communities are the finding itself: they stay visible
    assert redact("SNMP_COMMUNITY|public") == "SNMP_COMMUNITY|public"
    # inside block evidence ("header / child")
    assert "FakeTacKey1" not in redact("TACPLUS_SERVER|192.0.2.49 / passkey=FakeTacKey1")


def test_no_json_secret_in_any_evidence():
    config = dict(CONFIG, SNMP_COMMUNITY={"public": {"TYPE": "RO"}, "s3cretCommunity": {"TYPE": "RW"}})
    for f in audit(json.dumps(config), "sonic", 2):
        for line in f.evidence:
            assert "FakeTacKey1" not in line and "s3cretCommunity" not in line, (f.control_id, line)


def test_sonic_recognised_and_collected_read_only():
    assert discovery.guess_platform("SONiC Software Version: SONiC.202505.0", discovery.PLATFORMS)[0] == "sonic"
    cmds = COMMANDS["sonic"]
    for command in [cmds["config"], *cmds["state"]]:
        assert command.split()[0] in ("show", "ss"), command
        assert "sudo" not in command and "config " not in command
