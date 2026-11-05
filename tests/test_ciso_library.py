# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""The CISO Assistant libraries (integrations/ciso-assistant/) are generated from the specification,
follow the structure the CISO Assistant loader accepts, and are up to date."""

import copy
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "build_ciso_library.py"
# backend/core/models.py URN_REGEX (CISO Assistant v4.1)
URN = re.compile(r"^urn:([a-zA-Z0-9_-]+):([a-zA-Z0-9_-]+):([a-zA-Z0-9_-]+)(?::([a-zA-Z0-9_-]+))?:([0-9A-Za-z\[\]\(\)\-\._:]+)$")
ANNEX_A = {5: 37, 6: 8, 7: 14, 8: 34}


def load_tool():
    spec = importlib.util.spec_from_file_location("build_ciso_library", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    out = tmp_path_factory.mktemp("ciso")
    r = subprocess.run([sys.executable, str(SCRIPT), "--out-dir", str(out), "--date", "2026-01-01"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    spec = yaml.safe_load((ROOT / "spec" / "lyss-spec.yaml").read_text(encoding="utf-8"))
    version = spec["spec_version"]
    fw_text = (out / f"lyss-{version}.yaml").read_text(encoding="utf-8")
    map_text = (out / f"mapping-lyss-and-iso27001-2022-{version}.yaml").read_text(encoding="utf-8")
    return {"spec": spec, "fw_text": fw_text, "map_text": map_text,
            "fw": yaml.safe_load(fw_text), "map": yaml.safe_load(map_text)}


def test_generator_validation_passes(generated):
    assert load_tool().validate(generated["fw"], generated["map"]) == []


def test_library_metadata(generated):
    for lib in (generated["fw"], generated["map"]):
        for key in ("urn", "locale", "ref_id", "name", "description", "copyright", "version",
                    "publication_date", "provider", "packager", "objects"):
            assert lib.get(key) not in (None, ""), key
        assert lib["locale"] == "en"
        assert lib["provider"] == "Mouad Lyaazale"
        assert lib["packager"] == "LYSS project"
        assert lib["copyright"] == "LYSS specification © 2026 Mouad Lyaazale, CC BY 4.0"
        assert isinstance(lib["version"], int)
        assert str(lib["publication_date"]) == "2026-01-01"
        assert URN.match(lib["urn"]) and lib["urn"].startswith("urn:lyss:risk:library:")
    assert generated["map"]["dependencies"] == ["urn:lyss:risk:library:lyss",
                                                "urn:intuitem:risk:library:iso27001-2022"]


def test_no_yaml_anchors(generated):
    for text in (generated["fw_text"], generated["map_text"]):
        assert not re.search(r"[&*]id\d+", text)


def test_tree_structure(generated):
    fw = generated["fw"]["objects"]["framework"]
    assert fw["urn"] == "urn:lyss:risk:framework:lyss"
    nodes = fw["requirement_nodes"]
    by_urn = {}
    for n in nodes:
        assert URN.match(n["urn"]) and n["urn"] == n["urn"].lower(), n["urn"]
        assert n["urn"] not in by_urn, f"duplicate {n['urn']}"
        assert isinstance(n["assessable"], bool)
        assert len(n["name"]) <= 200
        if "parent_urn" in n:
            assert n["parent_urn"] in by_urn, f"{n['ref_id']}: parent listed later or missing"
            assert n["depth"] == by_urn[n["parent_urn"]]["depth"] + 1
        else:
            assert n["depth"] == 1
        by_urn[n["urn"]] = n
    groups = {g["ref_id"] for g in fw["implementation_groups_definition"]}
    assert all(set(n["implementation_groups"]) <= groups for n in nodes)
    # Only controls are assessable, and they sit at depth 3 under level / domain nodes.
    assert all(n["assessable"] == (n["depth"] == 3) for n in nodes)


def test_every_control_is_one_assessable_requirement(generated):
    spec = generated["spec"]
    nodes = {n["ref_id"]: n for n in generated["fw"]["objects"]["framework"]["requirement_nodes"]}
    controls = spec["controls"]
    assert sum(n["assessable"] for n in nodes.values()) == len(controls)
    for c in controls:
        n = nodes[c["id"]]
        assert n["urn"] == f"urn:lyss:risk:req_node:lyss:{c['id'].lower()}"
        assert n["name"] == c["title"]
        if c.get("statement"):
            assert n["description"] == " ".join(c["statement"].split())
            assert c["rationale"] in n["annotation"]
        else:
            assert "Draft control" in n["annotation"]
        level_node = nodes[f"L{c['level']}"]
        domain_node = nodes[f"L{c['level']}.{c['id'].split('-')[1]}"]
        assert n["parent_urn"] == domain_node["urn"] and domain_node["parent_urn"] == level_node["urn"]
        # cumulative levels: a level-N control belongs to the audits of level N and above
        assert n["implementation_groups"] == [f"L{x}" for x in sorted(spec["levels"]) if x >= c["level"]]


def test_iso_mappings_match_the_specification(generated):
    spec = generated["spec"]
    expected = {(f"urn:lyss:risk:req_node:lyss:{c['id'].lower()}",
                 f"urn:intuitem:risk:req_node:iso27001-2022:{ref.lower()}")
                for c in spec["controls"] for ref in c.get("mappings", {}).get("iso27001_2022", [])}
    # LYSS -> ISO only: an ISO control judged compliant must never mark LYSS controls compliant
    (forward,) = generated["map"]["objects"]["requirement_mapping_sets"]
    assert forward["source_framework_urn"] == "urn:lyss:risk:framework:lyss"
    assert forward["target_framework_urn"] == "urn:intuitem:risk:framework:iso27001-2022"
    pairs = [(m["source_requirement_urn"], m["target_requirement_urn"]) for m in forward["requirement_mappings"]]
    assert len(pairs) == len(set(pairs)) and set(pairs) == expected
    assert {m["relationship"] for m in forward["requirement_mappings"]} == {"subset"}
    for _, target in expected:
        theme, number = (int(x) for x in target.rsplit(":a.", 1)[1].split("."))
        assert 1 <= number <= ANNEX_A[theme], target


def test_library_version_grows_with_the_specification():
    v = load_tool().library_version
    assert v("0.4.0-draft") < v("0.4.0") < v("0.4.1-draft") < v("0.5.0") < v("1.0.0")
    with pytest.raises(ValueError):
        v("1.0")


def test_validation_catches_errors(generated):
    tool = load_tool()
    fw, mp = copy.deepcopy(generated["fw"]), copy.deepcopy(generated["map"])
    fw["objects"]["framework"]["requirement_nodes"][2]["parent_urn"] = "urn:lyss:risk:req_node:lyss:nowhere"
    mp["objects"]["requirement_mapping_sets"][0]["requirement_mappings"][0]["target_requirement_urn"] = \
        "urn:intuitem:risk:req_node:iso27001-2022:a.8.99"
    errors = tool.validate(fw, mp)
    assert any("nowhere" in e for e in errors)
    assert any("a.8.99" in e for e in errors)
    with pytest.raises(ValueError):
        tool.iso_node_urn("A.9.1")


def test_published_library_is_up_to_date():
    r = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
