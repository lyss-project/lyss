# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Generate integrations/wazuh/lyss-dashboard.ndjson: a "LYSS - Switch security" dashboard for the
Wazuh dashboard (OpenSearch Dashboards saved objects; definitions only, no data).

    python tools/build_wazuh_dashboard.py           write the file
    python tools/build_wazuh_dashboard.py --check   exit 1 if the published file is out of date

Import: Wazuh dashboard > Dashboard management > Saved objects > Import (overwrite). Every object id
starts with "lyss-", so a new import replaces the previous version.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "integrations" / "wazuh" / "lyss-dashboard.ndjson"
ALERTS = "wazuh-alerts-*"   # the index pattern every Wazuh dashboard installation provides


def vis(objs, id_, title, vtype, params, aggs, query="", index=ALERTS):
    ss = {"query": {"query": query, "language": "kuery"}, "filter": []}
    refs = []
    if index:
        ss["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
        refs = [{"name": ss["indexRefName"], "type": "index-pattern", "id": index}]
    objs.append({"type": "visualization", "id": id_, "references": refs, "attributes": {
        "title": title, "description": "", "version": 1, "uiStateJSON": "{}",
        "visState": json.dumps({"title": title, "type": vtype, "params": params, "aggs": aggs}, sort_keys=True),
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss, sort_keys=True)}}})
    return id_


def count(label):
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": label}}


def unique(i, field, label):
    return {"id": str(i), "enabled": True, "type": "cardinality", "schema": "metric",
            "params": {"field": field, "customLabel": label}}


def terms(i, field, label, size=10, schema="bucket", order_by="1"):
    return {"id": str(i), "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "size": size, "order": "desc", "orderBy": order_by, "otherBucket": False,
                       "missingBucket": False, "customLabel": label}}


def table(objs, id_, title, aggs, query="", per=10):
    return vis(objs, id_, title, "table", {"perPage": per, "showPartialRows": False, "showMetricsAtAllLevels": False,
                                          "showTotal": False, "totalFunc": "sum", "percentageCol": ""}, aggs, query)


def pie(objs, id_, title, field, label, query=""):
    return vis(objs, id_, title, "pie", {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                                        "isDonut": True, "labels": {"show": False, "values": True, "last_level": True,
                                                                    "truncate": 100}},
               [count("Events"), terms(2, field, label, 10, "segment")], query)


def histogram(objs, id_, title, query, split_field, split_label):
    params = {"type": "histogram", "grid": {"categoryLines": False}, "addTooltip": True, "addLegend": True,
              "legendPosition": "right", "times": [], "addTimeMarker": False,
              "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                                "style": {}, "scale": {"type": "linear"},
                                "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
              "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                             "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                             "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                             "title": {"text": "Events"}}],
              "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                "data": {"label": "Events", "id": "1"}, "valueAxis": "ValueAxis-1",
                                "drawLinesBetweenPoints": True, "showCircles": True}]}
    aggs = [count("Events"),
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {},
                        "customLabel": "Time"}},
            terms(3, split_field, split_label, 10, "group")]
    return vis(objs, id_, title, "histogram", params, aggs, query)


def note(objs, id_, title, markdown):
    return vis(objs, id_, title, "markdown", {"markdown": markdown, "fontSize": 11, "openLinksInNewTab": True}, [],
               index=None)


def build() -> list[dict]:
    objs: list[dict] = []
    note(objs, "lyss-v-guide", "LYSS - how to read this dashboard", (
        "**LYSS - Switch security** (last 7 days, refreshed every 5 minutes)\n\n"
        "* **Failed controls**: each scan reports every control a switch fails (Level 1 Baseline "
        "failures are rule level 7, Level 2 Hardened failures level 5).\n"
        "* **Regressions**: a control that passed at the previous scan fails now, so the configuration "
        "changed. Investigate them first.\n"
        "* **NIST SP 800-53**: the same findings appear in Wazuh's NIST 800-53 compliance dashboard.\n\n"
        "Evidence and fixes for each finding: open the switch in LYSS. Specification: "
        "[lyss.dev](https://lyss.dev)"))
    table(objs, "lyss-v-levels", "LYSS - level per switch (latest scans)",
          [count("Scans"), terms(2, "data.lyss.device", "Switch", 50), terms(3, "data.lyss.level", "LYSS level", 3),
           terms(4, "data.lyss.site", "Site", 1)], "rule.groups:lyss_scan", per=15)
    table(objs, "lyss-v-controls", "LYSS - failed controls",
          [unique(1, "data.lyss.device", "Switches"), terms(2, "data.lyss.control", "Control", 30),
           terms(3, "data.lyss.title", "Requirement", 1)], "rule.groups:lyss_finding", per=15)
    pie(objs, "lyss-v-by-switch", "LYSS - failures by switch", "data.lyss.device", "Switch", "rule.groups:lyss_finding")
    histogram(objs, "lyss-v-regressions-time", "LYSS - regressions over time", "rule.groups:lyss_regression",
              "data.lyss.device", "Switch")
    table(objs, "lyss-v-regressions", "LYSS - regressions (configuration changed)",
          [count("Events"), terms(2, "data.lyss.device", "Switch", 30), terms(3, "data.lyss.control", "Control", 10),
           terms(4, "data.lyss.title", "Requirement", 1)], "rule.groups:lyss_regression", per=10)
    pie(objs, "lyss-v-nist", "LYSS - findings by NIST SP 800-53 control", "rule.nist_800_53", "NIST 800-53",
        "rule.groups:lyss_finding")
    table(objs, "lyss-v-errors", "LYSS - collection errors and discovered switches",
          [count("Events"), terms(2, "data.lyss.event", "Event", 2), terms(3, "data.lyss.device", "Switch", 20),
           terms(4, "data.lyss.message", "Message", 1)], "rule.groups:lyss_error or rule.groups:lyss_discovery")

    panels = [("lyss-v-guide", 0, 0, 16, 11), ("lyss-v-levels", 16, 0, 32, 11),
              ("lyss-v-controls", 0, 11, 28, 15), ("lyss-v-by-switch", 28, 11, 20, 15),
              ("lyss-v-regressions-time", 0, 26, 28, 12), ("lyss-v-regressions", 28, 26, 20, 12),
              ("lyss-v-nist", 0, 38, 24, 13), ("lyss-v-errors", 24, 38, 24, 13)]
    pj, refs = [], []
    for n, (vid, x, y, w, h) in enumerate(panels):
        pj.append({"version": "2.19.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(n + 1)},
                   "panelIndex": str(n + 1), "embeddableConfig": {}, "panelRefName": f"panel_{n}"})
        refs.append({"name": f"panel_{n}", "type": "visualization", "id": vid})
    objs.append({"type": "dashboard", "id": "lyss-dashboard", "references": refs, "attributes": {
        "title": "LYSS - Switch security", "description": "LYSS switch security assessments: levels, failed controls, regressions, NIST 800-53.",
        "hits": 0, "version": 1, "panelsJSON": json.dumps(pj, sort_keys=True),
        "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}, sort_keys=True),
        "timeRestore": True, "timeFrom": "now-7d", "timeTo": "now", "refreshInterval": {"pause": False, "value": 300000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"},
                                                                  "filter": []}, sort_keys=True)}}})
    return objs


def render() -> str:
    return "".join(json.dumps(o, sort_keys=True, ensure_ascii=False) + "\n" for o in build())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if the published file is out of date")
    args = ap.parse_args(argv)
    text = render()
    if args.check:
        ok = OUT.exists() and OUT.read_text(encoding="utf-8") == text
        print("Wazuh dashboard up to date" if ok else "Wazuh dashboard out of date: run python tools/build_wazuh_dashboard.py")
        return 0 if ok else 1
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"written {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
