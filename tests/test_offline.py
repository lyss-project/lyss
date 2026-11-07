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


CASE_VENDORS = {"ios": "cisco_ios", "sb": "cisco_sb", "hp": "hp_procurve", "mikrotik": "mikrotik", "sonic": "sonic"}


def test_platform_recognised_from_every_fixture_and_demo_configuration():
    from lyss.engine import detect_vendor
    from lyss.sim.lab import load_lab
    for case in CASES.iterdir():
        config = case / "config.cfg"
        if config.exists():
            assert detect_vendor(config.read_text(encoding="utf-8")) == CASE_VENDORS[case.name.split("-")[0]], case.name
    lab = load_lab("demo")
    for switch_id, switch in lab.switches.items():
        text = (lab.folder / f"{switch_id}.cfg").read_text(encoding="utf-8")
        assert detect_vendor(text) == switch.platform, switch_id


def test_unrecognised_text_is_not_guessed():
    from lyss.engine import detect_vendor
    assert detect_vendor("") is None
    assert detect_vendor("hello\nworld\n") is None
    assert detect_vendor('{"name": "not a switch"}') is None


def test_auto_vendor_per_file(tmp_path, capsys):
    shutil.copy(CASES / "mikrotik-weak" / "config.cfg", tmp_path / "router.rsc")
    shutil.copy(CASES / "ios-weak" / "config.cfg", tmp_path / "catalyst.cfg")
    (tmp_path / "notes.txt").write_text("not a configuration\n", encoding="utf-8")
    assert main(["audit", "--json", str(tmp_path)]) == 2          # notes.txt not recognised: reported
    out = capsys.readouterr()
    assert {r["device"]: r["vendor"] for r in json.loads(out.out)["results"]} == {
        "catalyst.cfg": "cisco_ios", "router.rsc": "mikrotik"}
    assert "notes.txt: platform not recognised" in out.err


def test_version_flag(capsys):
    import pytest
    from lyss import __version__
    with pytest.raises(SystemExit) as exit_:
        main(["--version"])
    assert exit_.value.code == 0 and capsys.readouterr().out.strip() == f"LYSS {__version__}"


def test_missing_path_is_reported(tmp_path, capsys):
    assert main(["audit", "--vendor", "mikrotik", str(tmp_path / "nope.rsc")]) == 2
    assert "no such file" in capsys.readouterr().err
