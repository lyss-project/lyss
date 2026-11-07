# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""The author attribution required by NOTICE (AGPL v3 section 7(b)) must stay in place."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "src" / "lyss" / "web" / "templates"
ATTRIBUTION = "LYSS by Mouad Lyaazale · Made in Morocco"


def test_notice_states_the_attribution_and_the_licence():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert ATTRIBUTION in notice
    assert "AGPL-3.0-only" in notice
    assert "section 7(b)" in notice


def test_licence_is_agpl_v3():
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_attribution_is_shown_in_footer_login_page_and_reports():
    for name in ("base.html", "_hero.html", "report.html"):
        assert ATTRIBUTION in (TEMPLATES / name).read_text(encoding="utf-8"), name


def test_only_legacy_ssh_is_also_mit():
    """src/lyss/legacy_ssh.py alone is dual-licensed (AGPL-3.0-only OR MIT), with the MIT text and
    the author's copyright in the file; every other source file stays AGPL only."""
    dual = ROOT / "src" / "lyss" / "legacy_ssh.py"
    text = dual.read_text(encoding="utf-8")
    assert text.startswith("# SPDX-License-Identifier: AGPL-3.0-only OR MIT\n# Copyright 2026 Mouad Lyaazale\n")
    assert "Permission is hereby granted, free of charge" in text and "THE SOFTWARE IS PROVIDED \"AS IS\"" in text
    others = [p for p in (ROOT / "src").rglob("*.py") if p != dual and "OR MIT" in p.read_text(encoding="utf-8")]
    assert not others, others
    assert "legacy_ssh.py" in (ROOT / "NOTICE").read_text(encoding="utf-8")


def test_author_name_in_arabic_is_spelled_by_the_author():
    """The author's own Arabic spelling (machine translations get it wrong)."""
    arabic = "معاد اليازل"
    assert arabic in (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert arabic in (TEMPLATES / "_hero.html").read_text(encoding="utf-8")
