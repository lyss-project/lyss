# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""CISA KEV watch (tools/kev_watch.py): product filters, CVEs already in firmware.yaml, new vs
older entries, escaped report. Synthetic catalog (CVE-2099-*: fictitious identifiers)."""

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import kev_watch  # noqa: E402

WATCH = yaml.safe_load((ROOT / "data" / "kev-watch.yaml").read_text(encoding="utf-8"))


def entry(cve, vendor, product, added="2099-01-02", name="Test vulnerability"):
    return {"cveID": cve, "vendorProject": vendor, "product": product, "dateAdded": added, "vulnerabilityName": name}


def test_short_cve_lists_in_firmware_yaml_are_expanded():
    assert kev_watch.known_cves("id: cisco-sa-x (CVE-2023-20159/20160/20161/20189)") == {
        "CVE-2023-20159", "CVE-2023-20160", "CVE-2023-20161", "CVE-2023-20189"}
    real = kev_watch.known_cves((ROOT / "data" / "firmware.yaml").read_text(encoding="utf-8"))
    assert "CVE-2023-20189" in real and all(c.startswith("CVE-") for c in real)


def test_filters_keep_switch_platforms_and_drop_routers_and_software():
    f = WATCH["filters"]
    assert kev_watch.platform_of(entry("x", "Cisco", "IOS and IOS XE Software"), f) == "cisco_ios"
    assert kev_watch.platform_of(entry("x", "Cisco", "Catalyst 6800 Series Switches"), f) == "cisco_ios"
    assert kev_watch.platform_of(entry("x", "MikroTik", "RouterOS"), f) == "mikrotik"
    assert kev_watch.platform_of(entry("x", "Arista", "Extensible Operating System"), f) == "arista_eos"
    assert kev_watch.platform_of(entry("x", "Zyxel", "GS1900 Series Switches"), f) == "zyxel_gs1900"
    for vendor, product in (("Cisco", "IOS XR"), ("Cisco", "Small Business RV Series Routers"),
                            ("Cisco", "Catalyst SD-WAN Manager"), ("Arista", "VeloCloud Orchestrator"),
                            ("Hewlett Packard (HP)", "ProCurve Manager (PCM), PCM+, Identity Driven Manager (IDM)"),
                            ("Zyxel", "Multiple Firewalls")):
        assert kev_watch.platform_of(entry("x", vendor, product), f) is None, product


def test_new_older_reviewed_and_exit_code(tmp_path):
    since = str(WATCH["reviewed_until"])
    kev = {"catalogVersion": "2099.01.02", "vulnerabilities": [
        entry("CVE-2099-0001", "MikroTik", "RouterOS", added="2099-01-02"),          # new
        entry("CVE-2099-0002", "Cisco", "IOS Software", added="2000-01-01"),         # older, not reviewed
        entry("CVE-2099-0003", "Cisco", "IOS XR", added="2099-01-02"),               # not a switch
        entry("CVE-2099-0004", "Arista", "Extensible Operating System", added="2099-01-02"),   # in firmware text
        entry("CVE-2099-0005", "Zyxel", "Multiple Products", added="2099-01-02"),    # marked not applicable
    ]}
    watch = {**WATCH, "not_applicable": [{"cve": "CVE-2099-0005", "reason": "firewalls only", "checked": since}]}
    new, backlog, covered = kev_watch.review(kev, watch, "advisories: SA-9999 (CVE-2099-0004)")
    assert [e["cveID"] for e in new] == ["CVE-2099-0001"]
    assert [e["cveID"] for e in backlog] == ["CVE-2099-0002"] and covered == 2

    path = tmp_path / "kev.json"
    path.write_text(json.dumps(kev), encoding="utf-8")
    summary = tmp_path / "summary.md"
    assert kev_watch.main(["--kev", str(path), "--summary", str(summary)]) == 1    # a new entry: CI fails
    assert "CVE\\-2099\\-0001" in summary.read_text(encoding="utf-8")
    path.write_text(json.dumps({"vulnerabilities": kev["vulnerabilities"][1:3]}), encoding="utf-8")
    assert kev_watch.main(["--kev", str(path)]) == 0                                # only older / irrelevant


def test_report_escapes_catalog_text():
    kev = {"catalogVersion": "1"}
    evil = entry("CVE-2099-0009", "MikroTik", "RouterOS", name="![x](https://evil.example/p.png) <img src=x>")
    text = kev_watch.markdown(kev, WATCH, [{**evil, "platform": "mikrotik"}], [], 0)
    assert "![" not in text.replace("\\!\\[", "") and "<img" not in text.replace("\\<img", "")
