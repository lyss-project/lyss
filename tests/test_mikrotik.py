# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""MikroTik RouterOS: firmware release lines, "all" rules, community-name redaction, discovery,
read-only collection. Synthetic data."""

import re

import pytest

from lyss import discovery
from lyss.collector import COMMANDS
from lyss.config import parse
from lyss.engine import _is_vulnerable, evaluate_rule, firmware_verdict, redact

KEV_FIX = ["6.49.21", "7.23.4", "7.24.2"]


@pytest.mark.parametrize("version, vulnerable", [
    ("6.49.20", True), ("6.49.21", False),     # 6.x line
    ("6.48.7", True),                          # older 6.x line, below the next listed line
    ("7.20.4", True),                          # 7.x line older than every listed 7.x line
    ("7.23.3", True), ("7.23.4", False),       # long-term line
    ("7.24.1", True), ("7.24.2", False),       # stable line
    ("7.25.1", False),                         # newer than every listed line
])
def test_fix_per_release_line(version, vulnerable):
    assert _is_vulnerable(version, KEV_FIX) is vulnerable


def test_fix_affected_from_and_single_version():
    # RouterOS 7 only: a 6.x device is not affected
    assert _is_vulnerable("6.49.23", ["7.23.6", "7.24.3"], affected_from="7.0") is False
    assert _is_vulnerable("7.24.2", ["7.23.6", "7.24.3"], affected_from="7.0") is True
    assert _is_vulnerable("6.42", "6.42.1") is True and _is_vulnerable("6.42.1", "6.42.1") is False
    assert _is_vulnerable("15.2(7)E8", "15.2(7)E13") is True   # single fix, unchanged behaviour
    assert _is_vulnerable("1.0", None) is True


def test_routeros_firmware_verdicts():
    verdict, evidence = firmware_verdict({"vendor": "mikrotik", "model": "CRS326-24G-2S+", "version": "7.24.1"})
    assert verdict == "fail" and any("CISA KEV" in e for e in evidence)
    assert firmware_verdict({"vendor": "mikrotik", "model": "CHR", "version": "7.25.1"})[0] == "pass"


def test_all_rule_needs_every_part():
    cfg = parse("x\n", "===== /snmp print =====\n  enabled: no\n"
                       "===== /snmp community print terse =====\n0 * name=public security=none\n")
    rule = {"all": [{"state": r"^\s*enabled: yes", "section": "/snmp print"},
                    {"state": r"\bname=public\s", "section": "/snmp community print terse"}]}
    assert evaluate_rule(cfg, rule) == (False, [])
    cfg = parse("x\n", "===== /snmp print =====\n  enabled: yes\n"
                       "===== /snmp community print terse =====\n0 * name=public security=none\n")
    matched, evidence = evaluate_rule(cfg, rule)
    assert matched and len(evidence) == 2


def test_community_names_redacted_but_defaults_visible():
    assert "s3cret" not in redact("1   name=s3cret addresses=::/0 security=none read-access=yes")
    assert "name=public" in redact("0 * name=public addresses=::/0 security=none read-access=yes")
    # export line of a renamed default community
    assert "lab-v3" not in redact("/snmp community set [ find default=yes ] name=lab-v3 security=private")
    # other "name=" fields are not secrets
    assert "name=telnet" in redact(" 3     name=telnet port=23 proto=tcp available-from=")


def test_routeros_recognised():
    assert discovery.guess_platform("SSH-2.0-ROSSSH", discovery.SSH_FINGERPRINTS)[0] == "mikrotik"
    assert discovery.guess_platform("MikroTik RouterOS 7.25.1 (stable) CRS326-24G-2S+",
                                    discovery.PLATFORMS)[0] == "mikrotik"


def test_routeros_collection_is_read_only():
    cmds = COMMANDS["mikrotik"]
    assert cmds["config"] == "/export terse"           # never "show-sensitive"
    for command in cmds["state"]:
        assert re.search(r"\bprint\b", command), command
        assert not re.search(r"\b(set|add|remove|enable|disable|reset|show-sensitive)\b", command), command
