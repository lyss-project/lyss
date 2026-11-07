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
    status = re.search(r"Status: \*\*(\d+\.\d+), draft specification (\d+\.\d+)", readme)
    assert status, "README status line not found"
    assert status.group(1) == ".".join(__version__.split(".")[:2])
    assert status.group(2) == ".".join(load_spec()["spec_version"].split(".")[:2])


def test_site_metadata_states_the_current_version():
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    assert f'"softwareVersion": "{__version__}"' in site


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


def test_release_jobs_have_least_privilege():
    release = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    assert release["permissions"] == {"contents": "read"}
    jobs = release["jobs"]
    assert jobs["publish"]["permissions"] == {"id-token": "write"}
    assert jobs["sbom"]["permissions"] == {"contents": "write"}
    assert "permissions" not in jobs["build"]                     # the workflow default: read only


def test_every_adapter_implements_the_current_specification():
    spec_version = load_spec()["spec_version"]
    for path in sorted(ADAPTER_DIR.glob("*.yaml")):
        adapter = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert adapter.get("spec_version") == spec_version, path.name
