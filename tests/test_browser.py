# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""In-browser audit (site/audit.html): the Python entry point and the bundle the page loads.
Synthetic data."""

import importlib.util
import json
import zipfile
from pathlib import Path

from lyss.browser import VENDORS, run
from lyss.engine import ADAPTER_DIR

ROOT = Path(__file__).parent.parent
CASES = Path(__file__).parent / "cases"


def test_vendor_list_matches_the_adapters():
    assert set(VENDORS) == {p.stem for p in ADAPTER_DIR.glob("*.yaml")}


def test_pasted_routeros_export_is_recognised_and_audited():
    result = json.loads(run((CASES / "mikrotik-weak" / "config.cfg").read_text(encoding="utf-8")))
    assert result["ok"] and result["vendor"] == "mikrotik" and result["detected"]
    verdicts = {f["control_id"]: f["verdict"] for f in result["findings"]}
    assert verdicts["LYSS-MGMT-001"] == "fail"
    assert result["summary"]["fail"] > 0 and {f["level"] for f in result["findings"]} == {1, 2}


def test_explicit_vendor_level_and_state():
    config = (CASES / "mikrotik-weak" / "config.cfg").read_text(encoding="utf-8")
    state = (CASES / "mikrotik-weak" / "state.txt").read_text(encoding="utf-8")
    without = {f["control_id"]: f["verdict"] for f in json.loads(run(config, "mikrotik", 2))["findings"]}
    with_state = {f["control_id"]: f["verdict"] for f in json.loads(run(config, "mikrotik", 2, state))["findings"]}
    assert without["LYSS-ACC-010"] == "unknown" and with_state["LYSS-ACC-010"] == "fail"
    level1 = json.loads(run(config, "mikrotik", 1))
    assert {f["level"] for f in level1["findings"]} == {1} and not level1["detected"]
    level3 = json.loads(run(config, "mikrotik", 3))
    assert {f["level"] for f in level3["findings"]} == {1, 2, 3}
    assert {f["level"] for f in json.loads(run(config, "mikrotik", 9))["findings"]} == {1, 2, 3}


def test_errors_are_codes_for_the_page():
    assert json.loads(run("   ")) == {"ok": False, "error": "empty"}
    assert json.loads(run("just some text")) == {"ok": False, "error": "unrecognised"}
    assert json.loads(run("hostname x", "junos")) == {"ok": False, "error": "vendor"}


def test_secrets_never_in_the_result():
    config = (CASES / "ios-weak" / "config.cfg").read_text(encoding="utf-8")
    out = run(config)
    assert "cisco123" not in out and "0822455D0A16" not in out


def _build_tool():
    spec = importlib.util.spec_from_file_location("build_web_audit", ROOT / "tools" / "build_web_audit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_web_bundle_holds_exactly_what_the_page_needs(tmp_path):
    zip_path = _build_tool().build_bundle(tmp_path / "lyss-web.zip")
    names = set(zipfile.ZipFile(zip_path).namelist())
    assert {"lyss/__init__.py", "lyss/engine.py", "lyss/config.py", "lyss/browser.py",
            "home/spec/lyss-spec.yaml", "home/data/firmware.yaml"} <= names
    assert {f"home/adapters/{v}.yaml" for v in VENDORS} <= names
    examples = {n for n in names if n.startswith("examples/")}
    assert examples and all(json.loads(run(zipfile.ZipFile(zip_path).read(n).decode("utf-8")))["ok"] for n in examples)
    # nothing else of the package: no collector, web UI, vault... in the browser
    assert not {n for n in names if n.startswith("lyss/")} - {
        "lyss/__init__.py", "lyss/engine.py", "lyss/config.py", "lyss/browser.py"}


def test_pinned_pyodide_files_and_page_agree():
    tool = _build_tool()
    page = (ROOT / "site" / "audit.js").read_text(encoding="utf-8")
    assert f'PYODIDE_VERSION = "{tool.PYODIDE_VERSION}"' in page
    assert set(tool.PYODIDE_FILES) == {"pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm",
                                       "python_stdlib.zip", "pyodide-lock.json", tool.PYYAML_WHEEL}
    assert all(len(sha) == 64 for sha in tool.PYODIDE_FILES.values())


def test_site_policy_allows_webassembly_but_no_other_server():
    htaccess = (ROOT / "site" / ".htaccess").read_text(encoding="utf-8")
    csp = next(l for l in htaccess.splitlines() if "Content-Security-Policy" in l)
    assert "'wasm-unsafe-eval'" in csp and "connect-src 'self'" in csp
    assert "unsafe-eval'" not in csp.replace("'wasm-unsafe-eval'", "") and "http" not in csp
    assert "AddType application/wasm .wasm" in htaccess and "AddType text/javascript .mjs" in htaccess


def test_result_says_whether_the_platform_is_stable_or_preview():
    import json

    from lyss.browser import run
    cases = Path(__file__).parent / "cases"
    stable = json.loads(run((cases / "ios-hardened" / "config.cfg").read_text(encoding="utf-8")))
    preview = json.loads(run((cases / "junos-hardened" / "config.cfg").read_text(encoding="utf-8"), "juniper_junos"))
    assert (stable["support"], preview["support"]) == ("stable", "preview")