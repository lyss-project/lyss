# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Packaging hook (everything else is in pyproject.toml): the specification, the vendor adapters
and the firmware data live at the top of the repository, where people read and edit them; a built
package carries a copy in lyss/_bundled/, which lyss.engine uses when it is not run from a checkout."""

import re
import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

BUNDLED = ("spec", "adapters", "data")
ROOT = Path(__file__).resolve().parent
GITHUB = "https://github.com/lyss-project/lyss/blob/main/"
RAW = "https://raw.githubusercontent.com/lyss-project/lyss/main/"


def long_description() -> str:
    """README for PyPI: relative links point at the repository (images at the raw files)."""
    def absolute(m):
        target = m.group(1)
        base = RAW if re.search(r"\.(gif|png|jpe?g|svg|webp)$", target, re.I) else GITHUB
        return f"]({base}{target})"
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    return re.sub(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)", absolute, text)


class BuildWithProjectFiles(build_py):
    def run(self):
        super().run()
        target = Path(self.build_lib) / "lyss" / "_bundled"
        for name in BUNDLED:
            if not (ROOT / name).is_dir():
                raise SystemExit(f"cannot build LYSS: {name}/ is missing")
            shutil.copytree(ROOT / name, target / name, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


setup(cmdclass={"build_py": BuildWithProjectFiles},
      long_description=long_description(), long_description_content_type="text/markdown")
