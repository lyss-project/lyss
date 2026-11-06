# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""MikroTik RouterOS: firmware release lines, "all" rules, community-name redaction, discovery,
read-only collection. Synthetic data."""

import re
from datetime import datetime, timezone

import pytest

from lyss import discovery, oxidized
from lyss.collector import COMMANDS
from lyss.config import parse, routeros_terse
from lyss.engine import _is_vulnerable, audit, evaluate_rule, firmware_verdict, redact

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


OXIDIZED_BACKUP = """\
#                   version: 7.20.4 (stable)
#          factory-software: 7.12
#         architecture-name: arm
#                board-name: CRS326-24G-2S+
#                  platform: MikroTik
# installed-version: 7.20.4
# software id = FAKE-0009
#
# model = CRS326-24G-2S+
/interface bridge
add name=bridge
/ip address
add address=192.0.2.9/24 interface=bridge network=192.0.2.0
/ip service
set ftp disabled=yes
set www disabled=yes
/radius
add address=192.0.2.49 secret=FakeOxidizedSecret1 service=login
/snmp community
set [ find default=yes ] authentication-password=FakeOxAuth1 name=ox-fake-community \\
    security=private
/system note
set note="Authorized access only. Activity is logged." show-at-cli-login=yes
/user aaa
set use-radius=yes
/user group
add name=lyss-read policy="ssh,read,!local,!te\\
    lnet,!write,!sensitive"
"""


def test_hierarchical_export_becomes_one_command_per_line():
    text = routeros_terse(OXIDIZED_BACKUP)
    assert "/ip service set www disabled=yes" in text
    assert "/radius add address=192.0.2.49 secret=FakeOxidizedSecret1 service=login" in text
    # a line wrapped in the middle of a word is joined exactly
    assert '/user group add name=lyss-read policy="ssh,read,!local,!telnet,!write,!sensitive"' in text
    assert "# model = CRS326-24G-2S+" in text            # comments kept
    terse = "/ip service set telnet disabled=yes\n/interface bridge port remove 0\n"
    assert routeros_terse(terse) == terse                 # already terse: unchanged


def test_oxidized_routeros_backup_is_assessed_without_leaking_secrets():
    node = {"name": "crs-09", "model": "RouterOS", "group": "", "ip": "192.0.2.9",
            "last": {"status": "success", "end": "2026-11-05 03:00:00 UTC"}}
    result = oxidized.assess(node, OXIDIZED_BACKUP, now=datetime(2026, 11, 6, tzinfo=timezone.utc))
    verdicts = {f["control_id"]: f["verdict"] for f in result["findings"]}
    assert result["vendor"] == "mikrotik" and result["model"] == "CRS326-24G-2S+" and result["firmware"] == "7.20.4"
    assert verdicts["LYSS-MGMT-001"] == "fail"       # Telnet never disabled: on by factory default
    assert verdicts["LYSS-MGMT-003"] == "pass"       # www disabled
    assert verdicts["LYSS-MGMT-013"] == "fail"       # strong-crypto left at its default (no)
    assert verdicts["LYSS-VULN-001"] == "fail"       # 7.20.4: before the CISA KEV fixes
    assert verdicts["LYSS-AUTH-010"] == "pass"       # use-radius + a login RADIUS server
    assert verdicts["LYSS-AUTH-001"] == "pass"       # SNMP never enabled
    assert verdicts["LYSS-MGMT-011"] == "fail"       # address on the bridge itself
    assert verdicts["LYSS-MGMT-012"] == "pass"
    assert verdicts["LYSS-LOG-011"] == "fail"        # NTP client never enabled
    assert verdicts["LYSS-BKP-001"] == "pass"        # recent Oxidized backup
    dump = repr(result)
    for secret in ("FakeOxidizedSecret1", "FakeOxAuth1", "ox-fake-community"):
        assert secret not in dump


def test_pasted_export_saved_by_notepad_is_audited_offline():
    # a plain "/export" copied from a terminal into Windows Notepad: byte-order mark, wrapped lines
    pasted = ("﻿# 2026-11-06 12:51:14 by RouterOS 6.44.6\n# software id = FAKE-0010\n#\n"
              "/ip service\nset telnet disabled=yes\n/ip ssh\nset strong-crypto=\\\n    yes\n")
    findings = {f.control_id: f for f in audit(pasted, "mikrotik", 2)}
    assert findings["LYSS-MGMT-001"].verdict == "pass"
    assert findings["LYSS-MGMT-013"].verdict == "pass"            # wrapped line joined
    assert findings["LYSS-AUTH-003"].verdict == "fail"            # 6.44.6 < 6.45.1, from the header
    assert findings["LYSS-VULN-001"].verdict == "fail"            # version read from the header
    current = audit(pasted.replace("6.44.6", "7.25.1"), "mikrotik", 2)
    assert {f.control_id: f.verdict for f in current}["LYSS-AUTH-003"] == "pass"


def test_routeros_collection_is_read_only():
    cmds = COMMANDS["mikrotik"]
    assert cmds["config"] == "/export terse"           # never "show-sensitive"
    for command in cmds["state"]:
        assert re.search(r"\bprint\b", command), command
        assert not re.search(r"\b(set|add|remove|enable|disable|reset|show-sensitive)\b", command), command
