# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Every place that states a version agrees: package, pyproject, README status, site metadata,
changelog, and the specification version implemented by every adapter."""

import re
from pathlib import Path

import yaml

from lyss import __version__
from lyss.engine import ADAPTER_DIR, load_spec

ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_and_package_versions_agree():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'(?m)^version = "([^"]+)"', pyproject).group(1) == __version__


def test_readme_status_states_the_current_versions():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    status = re.search(r"Status: \*\*(\d+\.\d+), (?:draft )?specification (\d+\.\d+)", readme)
    assert status, "README status line not found"
    assert status.group(1) == ".".join(__version__.split(".")[:2])
    assert status.group(2) == ".".join(load_spec()["spec_version"].split(".")[:2])


def test_site_metadata_states_the_current_version():
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    assert f'"softwareVersion": "{__version__}"' in site


def test_visible_version_mentions_are_current():
    """The site headline said "preview 0.12" for five releases: every prose mention of the tool or
    specification version must follow the package and the specification."""
    minor = ".".join(__version__.split(".")[:2])
    spec = load_spec()["spec_version"]
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    kicker = re.findall(r"(?:preview|préversion) (\d+\.\d+)", site)
    assert kicker and set(kicker) == {minor}, kicker
    mentions = {
        "docs/TESTERS.md": r"tool (\d+\.\d+), specification (\S+?)\)",
        "docs/VALIDATION.md": r"Last reviewed: [^(]*\(LYSS (\d+\.\d+)\)",
        "docs/LYSS-Specification.md": r"assessed \S+ with LYSS (\d+\.\d+)\.",
    }
    for name, pattern in mentions.items():
        m = re.search(pattern, (ROOT / name).read_text(encoding="utf-8"))
        assert m, f"{name}: version mention not found"
        assert m.group(1) == minor, f"{name}: says {m.group(1)}, package is {minor}"
        if m.lastindex == 2:
            assert m.group(2) == spec, f"{name}: says specification {m.group(2)}, current is {spec}"
    for name in ("docs/CI.md", "docs/VERSIONING.md"):
        pinned = set(re.findall(r'lyss==(\d+\.\d+\.\d+)|lyss@v(\d+\.\d+\.\d+)', (ROOT / name).read_text(encoding="utf-8")))
        assert {v for pair in pinned for v in pair if v} == {__version__}, f"{name}: {pinned}"


def test_changelog_has_an_entry_for_the_current_version():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"(?m)^## {re.escape(__version__)} \(\d{{4}}-\d{{2}}-\d{{2}}", changelog)


def test_every_workflow_file_is_valid_yaml():
    """GitHub silently fails a workflow it cannot parse (e.g. ": " inside a plain value)."""
    for f in sorted((ROOT / ".github" / "workflows").glob("*.yml")) + [ROOT / "action.yml"]:
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert isinstance(data, dict) and (data.get("jobs") or data.get("runs")), f.name


def test_third_party_actions_are_pinned_to_commit_shas():
    files = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + [ROOT / "action.yml"]
    for f in files:
        for line in f.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*-?\s*uses:\s*(\S+)", line)
            if m and not m.group(1).startswith("./"):
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", m.group(1)), f"{f.name}: {line.strip()}"
                assert re.search(r"#\s*v\d", line), f"{f.name}: say which version the SHA is: {line.strip()}"


def test_checkouts_leave_no_token_on_disk():
    """Plumber ISSUE-307: actions/checkout keeps the job token in .git/config unless told not to."""
    for f in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for job, spec in yaml.safe_load(f.read_text(encoding="utf-8"))["jobs"].items():
            for step in spec.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    assert (step.get("with") or {}).get("persist-credentials") is False, f"{f.name}: {job}"


def test_release_jobs_have_least_privilege():
    release = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    assert release["permissions"] == {"contents": "read"}
    jobs = release["jobs"]
    assert jobs["publish"]["permissions"] == {"id-token": "write"}
    assert jobs["sbom"]["permissions"] == {"contents": "write"}
    assert "permissions" not in jobs["build"]                     # the workflow default: read only


def test_platform_support_labels_agree_everywhere():
    """Option B (1.0 plan): each adapter says stable or preview; README, VALIDATION and the website
    must show the same label for that platform."""
    rows = {  # adapter -> text that starts its row in README / VALIDATION / site
        "cisco_ios": ("| Cisco IOS / IOS-XE (Catalyst) |", "| Cisco IOS / IOS-XE |", "Cisco IOS / IOS-XE (Catalyst)</td>"),
        "cisco_sb": ("| Cisco Small Business / Business (SG200-550X, CBS) |", "| Cisco Small Business / Business |",
                     "Cisco Small Business / Business (SG, CBS)</td>"),
        "hp_procurve": ("| HP ProCurve / HPE Aruba AOS-S |", "| HPE Aruba AOS-S |", "HPE Aruba AOS-S (ProCurve)</td>"),
        "mikrotik": ("| MikroTik RouterOS", "| MikroTik RouterOS |", "MikroTik RouterOS 6/7 (CRS, RouterBOARD, CHR)</td>"),
        "sonic": ("| SONiC (community builds) |", "| SONiC |", "SONiC (versions communautaires)</span></td>"),
        "arista_eos": ("| Arista EOS", "| Arista EOS |", "Arista EOS (série 7000, cEOS / vEOS)</span></td>"),
        "aruba_aoscx": ("| HPE Aruba AOS-CX", "| HPE Aruba AOS-CX |", "HPE Aruba AOS-CX</td>"),
        "huawei_vrp": ("| Huawei S series", "| Huawei S series (VRP) |", "Huawei série S (VRP)</span></td>"),
        "juniper_junos": ("| Juniper EX (Junos) |", "| Juniper EX (Junos) |", "Juniper EX (Junos)</td>"),
        "zyxel_gs1900": ("| Zyxel GS1900 |", "| Zyxel GS1900 |", "Zyxel GS1900</td>"),
    }
    assert set(rows) == {p.stem for p in ADAPTER_DIR.glob("*.yaml")}, "new adapter: add its rows here"
    readme = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    validation = (ROOT / "docs" / "VALIDATION.md").read_text(encoding="utf-8").splitlines()
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8").splitlines()

    def row(lines, start):
        found = [l.strip() for l in lines if l.strip().startswith(start) or (start.endswith("</td>") and start in l and "<tr>" in l)]
        assert len(found) == 1, (start, found)
        return found[0]

    for name, (r_readme, r_validation, r_site) in rows.items():
        adapter = yaml.safe_load((ADAPTER_DIR / f"{name}.yaml").read_text(encoding="utf-8"))
        support, tested_on = adapter.get("support"), adapter.get("tested_on")
        assert support in ("stable", "preview") and tested_on in ("real", "virtual", "synthetic"), name
        assert (support == "stable") == (tested_on in ("real", "virtual")), name
        assert str(adapter.get("status", "")).startswith(support + ","), name
        cell = row(readme, r_readme).split("|")[2].strip()
        assert cell.startswith("**stable**" if support == "stable" else "preview"), (name, cell)
        if support == "stable":
            assert ("real switches" in cell) == (tested_on == "real") and ("virtual" in cell) == (tested_on == "virtual"), (name, cell)
        cell = row(validation, r_validation).split("|")[2].strip()
        assert cell == ({"real": "**Stable** (real)", "virtual": "**Stable** (virtual)"}.get(tested_on, "Preview")), (name, cell)
        html = row(site, r_site)
        assert (f'"en">stable · ' in html) == (support == "stable") and (f'"en">preview · ' in html) == (support == "preview"), name


def test_every_adapter_implements_the_current_specification():
    spec_version = load_spec()["spec_version"]
    for path in sorted(ADAPTER_DIR.glob("*.yaml")):
        adapter = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert adapter.get("spec_version") == spec_version, path.name
