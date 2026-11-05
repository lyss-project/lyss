# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""The Wazuh rules are generated from the specification and stay in sync with it."""

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "build_wazuh_rules.py"
RULES = ROOT / "integrations" / "wazuh" / "lyss_rules.xml"


def tool():
    spec = importlib.util.spec_from_file_location("build_wazuh_rules", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rules() -> dict:
    root = ElementTree.fromstring(RULES.read_text(encoding="utf-8"))
    return {r.get("id"): r for r in root.iter("rule")}


def test_published_rules_are_up_to_date():
    r = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_every_assessable_control_has_a_finding_and_a_regression_rule_with_its_nist_groups():
    spec = yaml.safe_load((ROOT / "spec" / "lyss-spec.yaml").read_text(encoding="utf-8"))
    by_control: dict[str, list] = {}
    for r in rules().values():
        field = r.find("field[@name='lyss.control']")
        if field is not None:
            by_control.setdefault(field.text.strip("^$"), []).append(r)
    for c in spec["controls"]:
        if not c.get("statement"):
            assert c["id"] not in by_control, f"draft {c['id']} must not have rules"
            continue
        found = {r.findtext("if_sid"): r for r in by_control[c["id"]]}
        assert set(found) == {"100802", "100804"}, c["id"]
        nist = {f"nist_800_53_{m.group(1)}.{m.group(2)}"
                for ref in c["mappings"].get("nist_800_53r5", []) if (m := re.match(r"([A-Z]{2})-(\d+)", ref))}
        for r in found.values():
            assert nist <= set(r.findtext("group").strip(",").split(",")), c["id"]
        assert found["100802"].get("level") == ("7" if c["level"] == 1 else "5")
        assert ("lyss_baseline" in found["100802"].findtext("group")) == (c["level"] == 1)


def test_rule_ids_are_unique_and_in_the_reserved_range():
    text = RULES.read_text(encoding="utf-8")
    ids = re.findall(r'<rule id="(\d+)"', text)
    assert len(ids) == len(set(ids)) and all(100800 <= int(i) <= 100869 for i in ids)


def test_nist_references_become_wazuh_groups():
    assert tool().nist_groups(["AC-17(2)", "IA-5", "IA-5(1)", "bogus"]) == ["nist_800_53_AC.17", "nist_800_53_IA.5"]


def test_install_script_regression_level_targets_only_regression_rules():
    """install.sh --regression-level rewrites the level of rule 100804 and 100840-100869 only."""
    sed = re.search(r'sed -i -E "/<rule id=\\"\(([^)]*)\)\\"/', (RULES.parent / "install.sh").read_text(encoding="utf-8"))
    pattern = re.compile(f"^({sed.group(1)})$")
    regression_ids = {i for i, r in rules().items() if r.findtext("if_sid") == "100804" or i == "100804"}
    assert {i for i in rules() if pattern.match(i)} == regression_ids
