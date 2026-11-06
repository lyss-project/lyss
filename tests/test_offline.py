# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Offline audit of saved configurations (lyss audit): file types picked in a folder, optional
<name>.state.txt next to a configuration, JSON output. Synthetic data."""

import json
import re
import shutil
from pathlib import Path

from lyss.__main__ import config_files, main

CASES = Path(__file__).parent / "cases"


def test_folder_picks_every_configuration_type_but_not_state_files(tmp_path):
    for name in ("a.cfg", "b.rsc", "c.json", "d.txt", "a.state.txt", "notes.md", "image.bin"):
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    assert [p.name for p in config_files(tmp_path)] == ["a.cfg", "b.rsc", "c.json", "d.txt"]


def test_export_with_state_file_next_to_it(tmp_path, capsys):
    # a RouterOS export saved as router.rsc + the "print" outputs pasted into router.state.txt
    shutil.copy(CASES / "mikrotik-weak" / "config.cfg", tmp_path / "router.rsc")
    shutil.copy(CASES / "mikrotik-weak" / "state.txt", tmp_path / "router.state.txt")
    assert main(["audit", "--vendor", "mikrotik", "--level", "2", "--json", str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)["results"][0]
    verdicts = {f["control_id"]: f["verdict"] for f in result["findings"]}
    assert result["device"] == "router.rsc"
    assert verdicts["LYSS-ACC-010"] == "fail"       # needs the device state: read from router.state.txt
    assert verdicts["LYSS-VULN-001"] == "fail"


def test_offline_doc_lists_exactly_the_collected_state_commands():
    from lyss.collector import COMMANDS
    doc = (Path(__file__).parent.parent / "docs" / "OFFLINE.md").read_text(encoding="utf-8")
    labels = {"mikrotik": "MikroTik RouterOS", "cisco_ios": "Cisco IOS / IOS-XE", "sonic": "SONiC",
              "cisco_sb": "Cisco Small Business / Business", "hp_procurve": "HPE Aruba AOS-S"}
    assert set(labels) == set(COMMANDS)
    for vendor, label in labels.items():
        row = next(l for l in doc.splitlines() if l.startswith(f"| {label} | `") and "·" in l)
        documented = set(re.findall(r"`([^`]+)`", row))
        assert documented == set(COMMANDS[vendor]["state"]), vendor


def test_missing_path_is_reported(tmp_path, capsys):
    assert main(["audit", "--vendor", "mikrotik", str(tmp_path / "nope.rsc")]) == 2
    assert "no such file" in capsys.readouterr().err
