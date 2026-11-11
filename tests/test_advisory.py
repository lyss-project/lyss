# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Advisory controls (specification section 8, decided 11/11/2026): a control added within a MAJOR
version is assessed and reported but never decides a level or a CI gate. Synthetic data."""

import importlib.util
from pathlib import Path

import yaml

from lyss import ci
from lyss.engine import Finding, audit, conformance, evaluate_control, load_spec
from lyss.config import parse

ROOT = Path(__file__).resolve().parent.parent


def finding(control_id, level, verdict, advisory=False):
    return Finding(control_id, level, control_id, verdict, [], "", "", {}, advisory)


def test_advisory_failure_never_lowers_the_level():
    findings = [finding("LYSS-MGMT-001", 1, "pass"), finding("LYSS-X-900", 1, "fail", advisory=True),
                finding("LYSS-MGMT-010", 2, "pass")]
    summary = conformance(findings)
    assert summary["achieved_level"] == 2          # the advisory failure does not count
    assert summary["fail"] == 1                    # but it is still reported


def test_advisory_failure_never_fails_a_ci_gate():
    result = {"device": "sw", "findings": [
        {"control_id": "LYSS-MGMT-001", "level": 1, "verdict": "pass"},
        {"control_id": "LYSS-X-900", "level": 1, "verdict": "fail", "advisory": True}]}
    assert ci.failing([result], 1) == []
    normal = {**result, "findings": [{**f, "advisory": False} for f in result["findings"]]}
    assert ci.failing([normal], 1) == [normal]


def test_evaluate_control_marks_advisory_controls():
    control = {"id": "LYSS-X-900", "level": 2, "title": "t", "status": "advisory", "mappings": {}}
    check = {"fail_if_any": [{"line": "^telnet"}], "otherwise": "pass"}
    f = evaluate_control(parse("telnet server\nhostname a\n"), control, check)
    assert f.verdict == "fail" and f.advisory
    normal = evaluate_control(parse("telnet server\n"), {**control, "status": None}, check)
    assert not normal.advisory


def test_no_advisory_control_before_1_0():
    # advisory controls only exist within a MAJOR version: none before 1.0
    assert not [c["id"] for c in load_spec()["controls"] if c.get("status") == "advisory"]


def test_specification_document_marks_advisory_controls(tmp_path, monkeypatch):
    spec = yaml.safe_load((ROOT / "spec" / "lyss-spec.yaml").read_text(encoding="utf-8"))
    spec["controls"].append({"id": "LYSS-MGMT-900", "level": 2, "status": "advisory", "added": "1.1.0",
                             "title": "Example advisory control", "statement": "s", "rationale": "r",
                             "test_procedure": "t", "evidence": ["config"], "mappings": {}})
    path = tmp_path / "spec.yaml"
    path.write_text(yaml.safe_dump(spec, allow_unicode=True), encoding="utf-8")
    module_spec = importlib.util.spec_from_file_location("build_spec", ROOT / "tools" / "build_spec.py")
    build_spec = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(build_spec)
    monkeypatch.setattr(build_spec, "SPEC", path)
    text = build_spec.build()
    assert "| [LYSS-MGMT-900](#lyss-mgmt-900) | 2 (advisory) | Example advisory control |" in text
    assert "*Advisory control (added in 1.1.0): reported, not counted for conformance" in text
    assert "**Advisory control**" in text and "**Access port**" in text and "**Uplink**" in text


def test_junos_master_password_secret_is_not_cleartext():
    base = (ROOT / "tests" / "cases" / "junos-hardened" / "config.cfg").read_text(encoding="utf-8")
    assert 'set system radius-server 192.0.2.10 secret "$9$FAKE"' in base
    master = base.replace('secret "$9$FAKE"', 'secret "$8$aes256-gcm$hmac-sha2-256$FAKE"')
    findings = {f.control_id: f for f in audit(master, "juniper_junos", 1)}
    assert findings["LYSS-AUTH-004"].verdict == "pass"
    cleartext = base.replace('secret "$9$FAKE"', 'secret "PlainSharedKey"')
    assert {f.control_id: f for f in audit(cleartext, "juniper_junos", 1)}["LYSS-AUTH-004"].verdict == "fail"
