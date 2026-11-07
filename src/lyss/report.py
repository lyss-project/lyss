# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Fleet views and exportable reports (standalone HTML for printing/PDF, and JSON)."""

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import PROJECT_LONG_NAME, PROJECT_NAME, __version__, inventory
from .engine import load_spec

TEMPLATES = Path(__file__).parent / "web" / "templates"
STATIC = Path(__file__).parent / "web" / "static"
SYMBOL = {"pass": "✓", "fail": "✗", "unknown": "?", "not_applicable": "–"}


def collect_results(device_ids: list[str] | None = None) -> list[dict]:
    """Latest result of each device (in inventory order), with the device record attached."""
    rows = []
    for device in inventory.load_devices():
        if device_ids and device["id"] not in device_ids:
            continue
        result = inventory.load_result(device["id"])
        if result:
            rows.append({"device": {k: v for k, v in device.items() if k != "secret"}, "result": result})
    return rows


def fleet(rows: list[dict]) -> dict:
    """Matrix (control x device), most frequent failures and level distribution."""
    spec = load_spec()
    max_level = max((f["level"] for r in rows for f in r["result"]["findings"]), default=1)
    controls = [c for c in spec["controls"] if c["level"] <= max_level]
    verdicts = {r["device"]["id"]: {f["control_id"]: f["verdict"] for f in r["result"]["findings"]} for r in rows}
    top = []
    for c in controls:
        failing = [d for d, v in verdicts.items() if v.get(c["id"]) == "fail"]
        if failing:
            top.append({"control": c, "count": len(failing), "devices": failing})
    top.sort(key=lambda t: (-t["count"], t["control"]["level"], t["control"]["id"]))
    levels = {}
    for r in rows:
        lvl = r["result"]["summary"]["achieved_level"]
        levels[lvl] = levels.get(lvl, 0) + 1
    return {
        "controls": controls,
        "verdicts": verdicts,
        "top": top,
        "fail_counts": {t["control"]["id"]: t["count"] for t in top},
        "levels": dict(sorted(levels.items())),
        "level_names": spec["levels"],
        "spec_version": spec["spec_version"],
        "totals": {k: sum(r["result"]["summary"][k] for r in rows) for k in ("pass", "fail", "unknown")},
    }


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))
    env.globals.update(project=PROJECT_NAME, project_long=PROJECT_LONG_NAME, version=__version__, symbol=SYMBOL)
    return env


def render_html(device_ids: list[str] | None = None, scope: str = "") -> str:
    """scope: name of the site the report covers ("" = whole fleet or one switch)."""
    rows = collect_results(device_ids)
    return _env().get_template("report.html").render(
        rows=rows,
        fleet=fleet(rows),
        # Level 3 appears in the report text when the results include Level 3 findings
        level3=any(f["level"] >= 3 for r in rows for f in r["result"]["findings"]),
        scope=scope,
        organization=inventory.load_settings().get("organization", ""),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        # inlined so the exported file is self-contained (no external references)
        maroc_svg=(STATIC / "maroc.svg").read_text(encoding="utf-8"),
        zellige_tile=_svg_inner(STATIC / "zellige.svg"),
    )


def _svg_inner(path: Path) -> str:
    """Body of an SVG file (between the <svg> tags), to reuse it inside a <pattern>."""
    text = path.read_text(encoding="utf-8")
    return text.split(">", 1)[1].rsplit("</svg>", 1)[0]


def render_json(device_ids: list[str] | None = None) -> str:
    rows = collect_results(device_ids)
    return json.dumps({
        "tool": PROJECT_NAME, "version": __version__,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "spec_version": load_spec()["spec_version"],
        "devices": [{**r["device"], **{"result": r["result"]}} for r in rows],
    }, indent=2, ensure_ascii=False)
