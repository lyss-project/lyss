# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""The specification is complete, consistent, and its document is generated from it."""

import re
import subprocess
import sys
from pathlib import Path

from lyss.engine import load_spec

ROOT = Path(__file__).resolve().parents[1]
ID = re.compile(r"^LYSS-(MGMT|AUTH|LOG|VULN|BKP|ACC)-\d{3}$")


def test_control_ids_are_well_formed_and_unique():
    ids = [c["id"] for c in load_spec()["controls"]]
    assert len(ids) == len(set(ids))
    assert all(ID.match(i) for i in ids)


def test_level_1_and_2_controls_are_fully_specified():
    for c in load_spec()["controls"]:
        if c["level"] > 2:
            continue
        for field in ("title", "statement", "rationale", "test_procedure", "evidence"):
            assert c.get(field), f"{c['id']} lacks {field}"
        for ref in ("iso27001_2022", "nist_800_53r5", "cis_v8"):
            assert ref in c.get("mappings", {}), f"{c['id']} lacks the {ref} mapping"


def test_every_control_has_a_nis2_mapping_with_valid_points():
    for c in load_spec()["controls"]:
        points = c.get("mappings", {}).get("nis2_art21")
        assert points is not None, f"{c['id']} lacks the nis2_art21 mapping (an empty list is allowed)"
        assert set(points) <= set("abcdefghij"), c["id"]


def test_crosswalk_lists_every_mapping_and_is_informative():
    text = (ROOT / "docs" / "MAPPINGS.md").read_text(encoding="utf-8")
    assert "Informative only" in text and "not legal advice" in text
    for c in load_spec()["controls"]:
        for key, refs in c.get("mappings", {}).items():
            for ref in refs or []:
                shown = f"21(2)({ref})" if key == "nis2_art21" else str(ref)
                row = next((l for l in text.splitlines() if l.startswith(f"| {shown} |")), "")
                assert c["id"] in row, (c["id"], key, ref)


def test_spec_version_is_semver():
    assert re.match(r"^\d+\.\d+\.\d+(-[a-z0-9.]+)?$", load_spec()["spec_version"])


def test_generated_document_is_up_to_date():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "build_spec.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
