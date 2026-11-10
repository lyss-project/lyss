# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""lyss explain: every control can be explained offline, with the platform fix on request."""

import pytest

from lyss.__main__ import main
from lyss.engine import load_spec

CONTROLS = [c["id"] for c in load_spec()["controls"]]


@pytest.mark.parametrize("control", CONTROLS)
def test_every_control_is_explained(control, capsys):
    assert main(["explain", control]) == 0
    out = capsys.readouterr().out
    assert out.startswith(control) and "Requirement" in out and "Test procedure" in out
    assert "References (informative)" in out and "ISO/IEC 27001:2022" in out
    assert "·" not in out   # Windows consoles: ASCII separators


def test_short_id_and_platform_fix(capsys):
    assert main(["explain", "mgmt-001", "--vendor", "cisco_ios"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("LYSS-MGMT-001") and "transport input ssh" in out and "NIS2 Art. 21(2)(h)" in out


def test_list_and_unknown_control(capsys):
    assert main(["explain"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == len(CONTROLS)
    assert main(["explain", "LYSS-NOPE-999"]) == 2
