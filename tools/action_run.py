# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Entry point of the GitHub Action (action.yml). Runs LYSS from the action's own files, so the
version is exactly the ref the workflow pinned, and only PyYAML has to be installed.

Run it with "python -I": isolated mode, so no Python file of the audited repository (a pull
request could add lyss/, json.py, secrets.py...) can ever be imported instead of the real ones.

    python -I tools/action_run.py audit <lyss audit arguments>
    python -I tools/action_run.py outputs <results.json> <require-level or "">
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def outputs(results_file: str, required: str) -> int:
    """Lines for $GITHUB_OUTPUT: integers and the results path only (no text from configurations)."""
    from lyss import ci
    try:
        results = json.loads(Path(results_file).read_text(encoding="utf-8"))["results"]
    except (OSError, ValueError, KeyError):
        results = []
    low = ci.lowest_level(results)
    print(f"switches={len(results)}")
    print(f"lowest-level={'' if low is None else low}")
    print(f"failing={len(ci.failing(results, int(required) if required.isdigit() else None))}")
    print(f"results={results_file}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "audit":
        from lyss.__main__ import main
        sys.exit(main(["audit", *sys.argv[2:]]))
    if len(sys.argv) == 4 and sys.argv[1] == "outputs":
        sys.exit(outputs(sys.argv[2], sys.argv[3]))
    print(__doc__, file=sys.stderr)
    sys.exit(2)
