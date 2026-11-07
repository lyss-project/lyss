# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Zyxel GS1900 (preview, firmware only): CVE-2026-7273 (CISA KEV, exploited on ~1,000 switches
since August 2026) from a pasted "show version" / System Information text. Synthetic data;
layout of "show version" as published by GS1900 users."""

import json

import pytest

from lyss.browser import run
from lyss.engine import audit, conformance, detect_vendor, load_firmware_data

SHOW_VERSION = """\
Model Name       : GS1900-24E
System Name      : lab-gs1900
Firmware Version : V2.90(AAHK.1)C0 | 06/10/2026
Serial Number    : FAKE0000040
"""


def _vuln(text: str):
    return next(f for f in audit(text, "zyxel_gs1900", 2) if f.control_id == "LYSS-VULN-001")


def test_show_version_is_recognised():
    assert detect_vendor(SHOW_VERSION) == "zyxel_gs1900"
    # the web page text without "Model Name" still has the firmware line
    assert detect_vendor("Firmware Version V2.80(AAHJ.3)C0\n") == "zyxel_gs1900"


def test_vulnerable_firmware_fails_with_the_fix():
    finding = _vuln(SHOW_VERSION)
    assert finding.verdict == "fail"
    text = " ".join(finding.evidence)
    assert "CVE-2026-7273" in text and "2.90(AAHK.2)" in text


@pytest.mark.parametrize("version, verdict", [
    ("V2.90(AAHK.2)C0", "pass"),      # the patched release
    ("V2.90(AAHK.3)C0", "pass"),      # later
    ("V2.80(AAHK.3)C0", "fail"),      # older line: "2.90(AAHK.1)C0 and earlier"
    ("V2.20(AAHK.1)", "fail"),        # old format without the C suffix
])
def test_firmware_versions(version, verdict):
    assert _vuln(SHOW_VERSION.replace("V2.90(AAHK.1)C0", version)).verdict == verdict


def test_firmware_code_alone_identifies_the_model():
    text = "Firmware Version : V2.90(ABTP.1)C0\n"          # ABTP = GS1900-24HPv2
    finding = _vuln(text)
    assert finding.verdict == "fail" and "2.90(ABTP.2)" in " ".join(finding.evidence)


def test_model_not_in_the_advisory_stays_unknown():
    text = "Model Name : GS1900-24HP\nFirmware Version : V2.60(XXXX.1)C0\n"   # end-of-support v1
    assert _vuln(text).verdict == "unknown"


def test_every_listed_model_has_one_patched_release():
    entries = [e for e in load_firmware_data() if e["vendor"] == "zyxel_gs1900"]
    assert len(entries) == 10
    for e in entries:
        (adv,) = e["advisories"]
        assert adv["kev"] and adv["fixed_in"].startswith("2.90(") and adv["fixed_in"].endswith(".2)")


def test_configuration_controls_are_unknown_never_not_applicable():
    findings = audit(SHOW_VERSION.replace("V2.90(AAHK.1)C0", "V2.90(AAHK.2)C0"), "zyxel_gs1900", 3)
    others = {f.verdict for f in findings if f.control_id not in ("LYSS-VULN-001",)}
    assert others == {"unknown"}
    assert conformance(findings)["achieved_level"] == 0     # firmware alone never reaches Level 1


def test_browser_audit_of_a_pasted_show_version():
    result = json.loads(run(SHOW_VERSION))
    assert result["ok"] and result["vendor"] == "zyxel_gs1900"
    vuln = next(f for f in result["findings"] if f["control_id"] == "LYSS-VULN-001")
    assert vuln["verdict"] == "fail"
