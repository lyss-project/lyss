# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""CI use of the offline audit (GitHub Action, any CI): threshold exit code, Oxidized-style
folders, JSON file, markdown job summary that untrusted configurations cannot inject into.
Synthetic data."""

import json
import re
import shutil
from pathlib import Path

import yaml

from lyss import ci
from lyss.__main__ import config_files, main

CASES = Path(__file__).parent / "cases"
ROOT = Path(__file__).parent.parent


def oxidized_repo(tmp_path: Path) -> Path:
    """Like an Oxidized git output: one file per node, no suffix, group folders, a .git folder."""
    repo = tmp_path / "repo"
    (repo / "site-a").mkdir(parents=True)
    (repo / ".git").mkdir()
    shutil.copy(CASES / "ios-hardened" / "config.cfg", repo / "site-a" / "core-1")
    if (CASES / "ios-hardened" / "state.txt").exists():                      # device state next to it
        shutil.copy(CASES / "ios-hardened" / "state.txt", repo / "site-a" / "core-1.state.txt")
    shutil.copy(CASES / "ios-weak" / "config.cfg", repo / "site-a" / "access-2")
    shutil.copy(CASES / "mikrotik-weak" / "config.cfg", repo / "edge-3")
    shutil.copy(CASES / "ios-weak" / "config.cfg", repo / ".git" / "ORIG_HEAD")
    (repo / "README.md").write_text("# switch backups\n", encoding="utf-8")
    return repo


def test_pattern_recursive_and_hidden_folders(tmp_path):
    repo = oxidized_repo(tmp_path)
    assert config_files(repo) == []                                          # no known suffix
    names = [p.relative_to(repo).as_posix() for p in config_files(repo, "*", recursive=True)]
    assert names == ["README.md", "edge-3", "site-a/access-2", "site-a/core-1"]   # never .git


def test_threshold_exit_codes_json_file_and_summary(tmp_path, capsys):
    repo = oxidized_repo(tmp_path)
    out_json, summary = tmp_path / "results.json", tmp_path / "summary.md"
    summary.write_text("earlier step\n", encoding="utf-8")
    args = ["audit", "--pattern", "*", "--recursive", "--level", "2", "--json-file", str(out_json),
            "--summary", str(summary)]
    assert main([*args, str(repo)]) == 2                                     # README.md not recognised
    assert main([*args, "--skip-unrecognised", str(repo)]) == 0             # report only
    assert main([*args, "--skip-unrecognised", "--require-level", "1", str(repo)]) == 1
    err = capsys.readouterr().err
    assert "README.md: platform not recognised, skipped" in err and "failed control up to Level 1" in err

    doc = json.loads(out_json.read_text(encoding="utf-8"))
    results = {r["device"]: r for r in doc["results"]}
    assert set(results) == {"edge-3", "site-a/access-2", "site-a/core-1"} and doc["spec_version"]
    # offline, the hardened switch proves no level (its backups cannot be seen in a file) but has no
    # failed control: it passes the CI gate; the weak ones fail it
    assert [r["device"] for r in ci.failing(doc["results"], 2)] == ["edge-3", "site-a/access-2"]
    assert results["site-a/core-1"]["summary"]["fail"] == 0

    text = summary.read_text(encoding="utf-8")
    assert text.startswith("earlier step\n")                                 # appended, never replaced
    assert text.count("## LYSS audit") == 3 and "**required: no failed control up to Level 1," in text
    assert "**fails Level 1**" in text and "never fail the job" in text
    assert "LYSS\\-MGMT\\-001" in text or "LYSS\\-AUTH" in text               # failed controls listed

    hardened_only = tmp_path / "hardened"
    hardened_only.mkdir()
    shutil.copy(repo / "site-a" / "core-1", hardened_only / "core-1.cfg")
    assert main(["audit", "--level", "2", "--require-level", "2", str(hardened_only)]) == 0


def test_threshold_with_nothing_to_assess_is_an_error(tmp_path):
    (tmp_path / "empty").mkdir()
    assert main(["audit", "--require-level", "2", str(tmp_path / "empty")]) == 2


def test_summary_cannot_be_injected_by_a_configuration():
    evil_name = "x](https://evil.example/a.png) ![t](https://evil.example/p.png)|<img src=x onerror=alert(1)>"
    result = {"device": evil_name, "vendor": "cisco_ios",
              "summary": {"achieved_level": 0, "pass": 0, "fail": 1, "unknown": 0},
              "findings": [{"control_id": "LYSS-MGMT-001", "title": "Telnet", "level": 1, "verdict": "fail",
                            "evidence": ["description `x` ![a](https://evil.example/b.png) <script>alert(1)</script>"]}]}
    text = ci.summary_markdown([result], "0.6.0-draft", 2, 2)
    body = "\n".join(l for l in text.splitlines() if "evil" in l)
    outside_code = re.sub(r"`[^`]*`", "", body)
    for active in (r"(?<!\\)!(?<!\\)\[", r"(?<!\\)<", r"(?<!\\)\](?<!\\)\(", r"(?<!\\)\|\s*<"):
        assert not re.search(active, outside_code), active                   # only escaped forms remain
    row = next(l for l in text.splitlines() if l.startswith("| x"))
    assert row.count(" | ") == 5                                              # the "|" did not split the row
    evidence = re.findall(r"`[^`]*`", body)
    assert len(evidence) == 1 and "description 'x'" in evidence[0]            # backticks cannot close the span


def test_long_evidence_and_many_switches_stay_bounded():
    results = [{"device": f"sw{i:04d}", "vendor": "cisco_ios",
                "summary": {"achieved_level": 0, "pass": 1, "fail": 1, "unknown": 0},
                "findings": [{"control_id": "LYSS-MGMT-001", "title": "t", "level": 1, "verdict": "fail",
                              "evidence": ["a" * 5000]}]} for i in range(500)]
    text = ci.summary_markdown(results, "0.6.0-draft", 2)
    assert text.count("### ") == ci.MAX_DETAILED and "400 more configuration(s)" in text
    assert len(text.encode()) < 1024 * 1024 and "a" * (ci.MAX_EVIDENCE + 1) not in text


def test_action_never_pastes_inputs_into_scripts():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    for step in steps:
        assert "${{" not in step["run"], step["name"]                       # only through env:
    audit_step = next(s for s in steps if s["id"] == "audit")
    assert "::stop-commands::" in audit_step["run"] and 'args+=(-- "$target")' in audit_step["run"]
    passed = {v.strip("${} ").removeprefix("inputs.") for v in audit_step["env"].values() if "inputs." in v}
    assert passed == set(action["inputs"])                                   # every input, all via env


def test_action_never_imports_python_files_of_the_audited_repository():
    """A pull request could add lyss/, json.py or secrets.py: every interpreter call is isolated
    (-I) and runs from the runner's temporary folder; only hash-pinned PyYAML is installed."""
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    for step in action["runs"]["steps"]:
        assert step.get("working-directory") == "${{ runner.temp }}", step["name"]
        calls = re.findall(r'"\$(?:py|lp|LYSS_PY)"\s+(\S+)', step["run"])
        assert calls and all(c == "-I" for c in calls), (step["name"], calls)
    install = next(s for s in action["runs"]["steps"] if s["id"] == "install")["run"]
    assert "--require-hashes" in install and "action-requirements.txt" in install
    reqs = (ROOT / ".github" / "action-requirements.txt").read_text(encoding="utf-8")
    assert re.search(r"(?m)^pyyaml==\d", reqs) and reqs.count("--hash=sha256:") > 10
    assert not re.search(r"(?m)^(?!pyyaml|#|\s)\S", reqs)          # nothing else is installed


def test_unknown_vendor_and_level_are_refused(capsys):
    import pytest
    for bad in (["--vendor", "../../etc/passwd"], ["--level", "7"], ["--require-level", "0"]):
        with pytest.raises(SystemExit) as exit_:
            main(["audit", *bad, "."])
        assert exit_.value.code == 2
