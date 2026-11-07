# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Regression test on YOUR real switches (private/ data, never committed).

The verdict matrix of every collected switch is compared with private/golden.json. When a rule
change alters a real verdict, the test fails and shows the difference: review it, then accept it
with `python -m pytest tests/test_private.py --update-golden`. Skipped when no private data exists.
"""

import json

import pytest

from lyss import collector, inventory, sealed
from lyss.engine import audit, ROOT

PRIVATE = ROOT / "private"
GOLDEN = PRIVATE / "golden.json"


def current_matrix() -> dict:
    previous = inventory.PRIVATE
    inventory.configure(PRIVATE)
    try:
        matrix = {}
        for device in inventory.load_devices():
            cfg, state = collector.config_paths(device)
            if not cfg.exists() or device["vendor"] == "auto":
                continue
            findings = audit(sealed.read_text(cfg, errors="replace"), device["vendor"], 2,
                             sealed.read_text(state, errors="replace") if state.exists() else "")
            # LYSS-BKP-001 depends on time (backup age): excluded from the regression matrix
            matrix[device["id"]] = {f.control_id: f.verdict for f in findings if f.control_id != "LYSS-BKP-001"}
        return matrix
    finally:
        inventory.configure(previous)


@pytest.mark.skipif(not (PRIVATE / "devices.json").exists(), reason="no private switch data on this machine")
def test_real_switch_verdicts_unchanged(request):
    matrix = current_matrix()
    if request.config.getoption("--update-golden") or not GOLDEN.exists():
        GOLDEN.write_text(json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8")
        pytest.skip(f"golden matrix written for {len(matrix)} switches")
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    diffs = [f"{d} {c}: {golden.get(d, {}).get(c)} -> {v}"
             for d, controls in matrix.items() for c, v in controls.items()
             if d in golden and golden[d].get(c) != v]
    assert not diffs, "real verdicts changed (review, then --update-golden):\n" + "\n".join(diffs)
