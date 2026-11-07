# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Entry point of the in-browser audit (lyss.dev/audit.html, Pyodide): the same engine, adapters
and data as the command line, on text pasted into the page. Nothing here touches the network."""

import json
from dataclasses import asdict

from . import PROJECT_NAME, __version__
from .engine import audit, conformance, detect_vendor, load_spec

VENDORS = ("arista_eos", "cisco_ios", "cisco_sb", "hp_procurve", "mikrotik", "sonic", "zyxel_gs1900")


def run(text: str, vendor: str = "auto", level: int = 2, state_text: str = "") -> str:
    """JSON result for the page: {ok, vendor, detected, summary, findings} or {ok: false, error}."""
    text = text or ""
    if not text.strip():
        return json.dumps({"ok": False, "error": "empty"})
    detected = vendor == "auto"
    if detected:
        vendor = detect_vendor(text)
        if vendor is None:
            return json.dumps({"ok": False, "error": "unrecognised"})
    elif vendor not in VENDORS:
        return json.dumps({"ok": False, "error": "vendor"})
    findings = audit(text, vendor, max(1, min(int(level), 3)), state_text or "")
    return json.dumps({
        "ok": True, "tool": PROJECT_NAME, "version": __version__, "spec_version": load_spec()["spec_version"],
        "vendor": vendor, "detected": detected, "summary": conformance(findings),
        "findings": [asdict(f) for f in findings],
    }, ensure_ascii=False)
