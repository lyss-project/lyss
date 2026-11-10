# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Accepted risks: never a pass, always dated, refused when malformed. Synthetic data."""

import json
import os
from datetime import date, timedelta
from pathlib import Path

import pytest

from lyss import accepted
from lyss.__main__ import main

HERE = Path(__file__).parent
WEAK = HERE / "cases" / "ios-weak" / "config.cfg"
TODAY = date(2026, 11, 10)
GOOD = """accepted_risks:
  - control: LYSS-MGMT-001
    switches: ["sw-old-*"]
    reason: End of life switch, Telnet needed by the old console server until replacement
    approved_by: Security officer
    expires: 2027-03-31
"""


def write(folder: Path, body: str, name: str = "accepted.yaml") -> Path:
    p = folder / name
    p.write_text(body, encoding="utf-8")
    return p


def test_load_and_match(tmp_path):
    [a] = accepted.load(write(tmp_path, GOOD), TODAY)
    assert a.control == "LYSS-MGMT-001" and a.expires == date(2027, 3, 31)
    assert a.covers("sw-old-01.cfg") and a.covers("site-a/sw-old-02.cfg") and not a.covers("sw-new-01.cfg")


@pytest.mark.parametrize("old, new, message", [
    ("    approved_by: Security officer\n", "", "missing approved_by"),
    ("control: LYSS-MGMT-001", "control: LYSS-NOPE-999", "unknown control"),
    ("expires: 2027-03-31", "expires: 2028-01-01", "more than one year ahead"),
    ("expires: 2027-03-31", "expires: soon", "must be a date"),
    ("reason: End of life switch, Telnet needed by the old console server until replacement", "reason: short",
     "'reason' must be a text"),
    ("    expires: 2027-03-31\n", "    expires: 2027-03-31\n    note: x\n", "unknown note"),
])
def test_malformed_entries_are_refused(tmp_path, old, new, message):
    with pytest.raises(ValueError, match=message):
        accepted.load(write(tmp_path, GOOD.replace(old, new)), TODAY)


def test_broken_yaml_message_never_quotes_the_file(tmp_path):
    body = "accepted_risks:\nSECRET-VALUE-THAT-MUST-NOT-BE-PRINTED: [unclosed\n"
    with pytest.raises(ValueError) as e:
        accepted.load(write(tmp_path, body), TODAY)
    assert "not valid YAML" in str(e.value) and "SECRET" not in str(e.value)


def test_symbolic_link_is_refused(tmp_path):
    link = tmp_path / "link.yaml"
    try:
        os.symlink(write(tmp_path, GOOD), link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links not available here")
    with pytest.raises(ValueError, match="symbolic link"):
        accepted.load(link, TODAY)


def test_apply_marks_failures_only_and_reports_expired_and_unused(tmp_path):
    [a] = accepted.load(write(tmp_path, GOOD), TODAY)
    findings = [{"control_id": "LYSS-MGMT-001", "verdict": "fail"}, {"control_id": "LYSS-MGMT-002", "verdict": "pass"}]
    used: set = set()
    assert accepted.apply("sw-old-01.cfg", findings, [a], used, TODAY) == []
    assert findings[0]["verdict"] == "fail" and findings[0]["accepted"]["expires"] == "2027-03-31"
    assert "accepted" not in findings[1]
    later = [{"control_id": "LYSS-MGMT-001", "verdict": "fail"}]
    notes = accepted.apply("sw-old-01.cfg", later, [a], set(), date(2027, 4, 1))
    assert "expired on 2027-03-31" in notes[0] and "accepted" not in later[0]
    assert accepted.unused([a], set()) and not accepted.unused([a], {0})


def run_audit(folder: Path, *extra: str) -> tuple[int, dict, str]:
    configs = folder / "configs"
    configs.mkdir(parents=True)
    (configs / "sw-old-01.cfg").write_text(WEAK.read_text(encoding="utf-8"), encoding="utf-8")
    results, summary = folder / "r.json", folder / "summary.md"
    code = main(["audit", "--level", "1", "--require-level", "1", "--json-file", str(results),
                 "--summary", str(summary), *extra, str(configs)])
    return code, json.loads(results.read_text(encoding="utf-8")), summary.read_text(encoding="utf-8")


def test_gate_ignores_accepted_failures_but_the_level_is_unchanged(tmp_path):
    code, doc, _ = run_audit(tmp_path / "before")
    assert code == 1
    result = doc["results"][0]
    fails = sorted({f["control_id"] for f in result["findings"] if f["verdict"] == "fail" and f["level"] == 1})
    expires = (date.today() + timedelta(days=90)).isoformat()
    risks = write(tmp_path, "accepted_risks:\n" + "".join(
        f"  - control: {c}\n    switches: [sw-old-01]\n    reason: Replacement ordered, see change ticket\n"
        f"    approved_by: Security officer\n    expires: {expires}\n" for c in fails), "risks.yaml")
    code, doc, summary = run_audit(tmp_path / "after", "--accepted-risks", str(risks))
    after = doc["results"][0]
    assert code == 0
    assert after["summary"] == result["summary"]                   # never a pass: same level and counts
    assert all(f.get("accepted") for f in after["findings"] if f["verdict"] == "fail" and f["level"] == 1)
    assert "accepted risk until" in summary and "still count as failed" in summary


def test_a_broken_file_stops_the_audit(tmp_path, capsys):
    bad = write(tmp_path, "accepted_risks: [ {control: LYSS-MGMT-001} ]\n")
    assert main(["audit", "--accepted-risks", str(bad), str(WEAK)]) == 2
    assert "missing" in capsys.readouterr().err
