# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""SARIF (GitHub code scanning) and GitLab Code Quality reports of an offline audit; the GitLab
CI template. Synthetic data."""

import json
from datetime import date, timedelta
from pathlib import Path

import yaml

from lyss import __version__, ci
from lyss.__main__ import main

HERE = Path(__file__).parent
ROOT = HERE.parent


def run(tmp_path: Path, *extra: str) -> tuple[dict, list]:
    configs = tmp_path / "repo" / "configs"
    configs.mkdir(parents=True)
    (configs / "sw-a.cfg").write_text((HERE / "cases" / "ios-weak" / "config.cfg").read_text(encoding="utf-8"),
                                      encoding="utf-8")
    sarif, cq = tmp_path / "out.sarif", tmp_path / "cq.json"
    main(["audit", "--level", "2", "--json-file", str(tmp_path / "r.json"), "--sarif", str(sarif),
          "--codequality", str(cq), "--report-root", str(tmp_path / "repo"), *extra, str(configs)])
    return json.loads(sarif.read_text(encoding="utf-8")), json.loads(cq.read_text(encoding="utf-8"))


def test_sarif_results_point_at_the_proving_line(tmp_path):
    sarif, _ = run(tmp_path)
    run_ = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run_["tool"]["driver"]["version"] == __version__
    assert {r["id"] for r in run_["tool"]["driver"]["rules"]} >= {r["ruleId"] for r in run_["results"]}
    text = (HERE / "cases" / "ios-weak" / "config.cfg").read_text(encoding="utf-8").splitlines()
    by_rule = {r["ruleId"]: r for r in run_["results"]}
    telnet = by_rule["LYSS-MGMT-001"]["locations"][0]["physicalLocation"]
    assert telnet["artifactLocation"]["uri"] == "configs/sw-a.cfg"
    assert "transport input telnet" in text[telnet["region"]["startLine"] - 1]
    # a redacted evidence line is still found (the secret part matches anything)
    enable = by_rule["LYSS-AUTH-002"]["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert text[enable - 1].startswith("enable password")
    assert all(r["level"] in ("error", "warning", "note") for r in run_["results"])


def test_no_secret_reaches_the_reports(tmp_path):
    # the fictitious secrets of the weak case: the reports carry only redacted evidence
    sarif, cq = run(tmp_path)
    dumped = json.dumps(sarif) + json.dumps(cq)
    assert "<redacted>" in dumped
    for secret in ("cisco123", "0822455D0A16", "PlainSharedKey"):
        assert secret not in dumped, secret


def test_accepted_risks_are_suppressed_in_sarif_and_left_out_of_code_quality(tmp_path):
    expires = (date.today() + timedelta(days=30)).isoformat()
    risks = tmp_path / "risks.yaml"
    risks.write_text("accepted_risks:\n  - control: LYSS-MGMT-001\n    switches: [sw-a]\n"
                     "    reason: Console server needs Telnet until March\n    approved_by: Security officer\n"
                     f"    expires: {expires}\n", encoding="utf-8")
    sarif, cq = run(tmp_path, "--accepted-risks", str(risks))
    telnet = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "LYSS-MGMT-001")
    assert telnet["suppressions"][0]["status"] == "accepted" and "Console server" in telnet["suppressions"][0]["justification"]
    assert "LYSS-MGMT-001" not in {i["check_name"] for i in cq}
    assert {i["severity"] for i in cq} <= {"critical", "major", "minor"}
    assert len({i["fingerprint"] for i in cq}) == len(cq)


def test_locate():
    text = "hostname a\nline vty 0 4\n transport input telnet\n"
    assert ci.locate(text, ["line vty 0 4 / transport input telnet"]) == 3
    assert ci.locate(text, ["a sentence that is not in the file"]) is None


def test_gitlab_template_is_valid_and_pinned_to_this_release():
    job = yaml.safe_load((ROOT / "integrations" / "gitlab" / "lyss.gitlab-ci.yml").read_text(encoding="utf-8"))["lyss-audit"]
    assert all(isinstance(line, str) for line in job["script"])     # a ": " must never turn a line into a mapping
    assert job["variables"]["LYSS_VERSION"] == __version__
    assert job["artifacts"]["reports"]["codequality"] == "gl-code-quality-report.json"
    run_line = job["script"][-1]
    assert " -I -m lyss " in run_line and "--codequality" in " ".join(job["script"])
