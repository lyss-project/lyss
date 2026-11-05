# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""The Wazuh dashboard file is generated, importable (valid saved objects) and only uses LYSS fields."""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "build_wazuh_dashboard.py"
NDJSON = ROOT / "integrations" / "wazuh" / "lyss-dashboard.ndjson"
EVENT_FIELDS = {"event", "device", "host", "site", "level", "control", "title", "message"}  # see src/lyss/events.py


def objects():
    return [json.loads(line) for line in NDJSON.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_published_dashboard_is_up_to_date():
    r = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_saved_objects_are_consistent():
    objs = objects()
    ids = {o["id"] for o in objs}
    assert all(o["id"].startswith("lyss-") for o in objs) and len(ids) == len(objs)
    dashboards = [o for o in objs if o["type"] == "dashboard"]
    assert len(dashboards) == 1
    panels = json.loads(dashboards[0]["attributes"]["panelsJSON"])
    refs = {r["name"]: r["id"] for r in dashboards[0]["references"]}
    assert len(panels) == len(refs) and all(refs[p["panelRefName"]] in ids for p in panels)
    for o in objs:
        if o["type"] == "visualization":
            json.loads(o["attributes"]["visState"])
            ss = json.loads(o["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            if "indexRefName" in ss:
                assert o["references"] == [{"name": ss["indexRefName"], "type": "index-pattern", "id": "wazuh-alerts-*"}]


def test_only_known_lyss_fields_and_rule_groups_are_used():
    text = NDJSON.read_text(encoding="utf-8")
    assert set(re.findall(r"data\.lyss\.(\w+)", text)) <= EVENT_FIELDS
    groups = set(re.findall(r"rule\.groups:(\w+)", text))
    rules = (ROOT / "integrations" / "wazuh" / "lyss_rules.xml").read_text(encoding="utf-8")
    assert groups and all(re.search(rf"\b{g},", rules) for g in groups)
