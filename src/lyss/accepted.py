# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Accepted risks: a reviewed, dated decision to live with a failed control for a while.

An acceptance never turns a failure into a pass: the finding stays "fail", the achieved level is
unchanged, and the report shows the acceptance next to it (reason, who approved it, until when).
Only the CI gate (--require-level) stops failing on an accepted control, until the acceptance
expires; an expired one counts as a normal failure again and is reported.

File (YAML, given explicitly with --accepted-risks, never picked up automatically):

    accepted_risks:
      - control: LYSS-VULN-001
        switches: ["sw-old-*"]          # configuration names or file names, * and ? allowed
        reason: End of life, no fixed release; web interface off; replacement ordered
        approved_by: Security officer
        expires: 2027-03-31             # at most one year ahead

The file is reviewed like code: in CI, a pull request that changes it must be read as carefully
as one that changes the configurations."""

from dataclasses import dataclass
from datetime import date, timedelta
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

import yaml

from .engine import load_spec

MAX_DAYS = 366          # an acceptance is reviewed at least once a year
MAX_ENTRIES = 500
MAX_BYTES = 1024 * 1024
MAX_PATTERNS = 100
FIELDS = {"control", "switches", "reason", "approved_by", "expires"}


@dataclass(frozen=True)
class Acceptance:
    control: str
    switches: tuple[str, ...]
    reason: str
    approved_by: str
    expires: date
    index: int                    # position in the file, for messages

    def covers(self, device: str) -> bool:
        names = {device, PurePosixPath(device).name, PurePosixPath(device).stem}
        return any(fnmatchcase(n, p) for p in self.switches for n in names)

    def as_dict(self) -> dict:
        return {"reason": self.reason, "approved_by": self.approved_by, "expires": self.expires.isoformat()}

    def label(self) -> str:
        return f"accepted risk #{self.index + 1} ({self.control})"


def _text(entry: dict, key: str, where: str, low: int, high: int) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not low <= len(value.strip()) <= high:
        raise ValueError(f"{where}: '{key}' must be a text of {low} to {high} characters")
    return " ".join(value.split())


def load(path: Path, today: date | None = None) -> list[Acceptance]:
    """Read and check the file. Any mistake raises ValueError: a broken file is never half-applied."""
    today = today or date.today()
    # in CI the file comes from the repository: a pull request could turn it into a link to a file of
    # the runner, and a parser message quoting it would print that file in the job log
    absolute = path.absolute()
    if any(p.is_symlink() for p in (absolute, *absolute.parents)):
        raise ValueError(f"{path.name}: goes through a symbolic link, not followed")
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError(f"{path.name}: not a regular file of at most {MAX_BYTES // 1024} KB")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        mark = getattr(e, "problem_mark", None)
        raise ValueError(f"{path.name}: not valid YAML" + (f" (line {mark.line + 1})" if mark else "")) from None
    if not isinstance(data, dict) or not isinstance(data.get("accepted_risks"), list):
        raise ValueError(f"{path.name}: expected a list under 'accepted_risks'")
    entries = data["accepted_risks"]
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"{path.name}: more than {MAX_ENTRIES} accepted risks")
    controls = {c["id"] for c in load_spec()["controls"]}
    out = []
    for i, entry in enumerate(entries):
        where = f"{path.name}, accepted risk #{i + 1}"
        if not isinstance(entry, dict):
            raise ValueError(f"{where}: expected control, switches, reason, approved_by, expires")
        missing, extra = FIELDS - set(entry), set(entry) - FIELDS
        if missing or extra:
            raise ValueError(f"{where}: " + "; ".join(
                ([f"missing {', '.join(sorted(missing))}"] if missing else [])
                + ([f"unknown {', '.join(sorted(map(str, extra)))}"] if extra else [])))
        control = entry["control"]
        if control not in controls:
            raise ValueError(f"{where}: unknown control {control!r}")
        switches = entry["switches"]
        if isinstance(switches, str):
            switches = [switches]
        if (not isinstance(switches, list) or not switches or len(switches) > MAX_PATTERNS
                or not all(isinstance(s, str) and 0 < len(s.strip()) <= 200 for s in switches)):
            raise ValueError(f"{where}: 'switches' must list 1 to {MAX_PATTERNS} names or patterns")
        expires = entry["expires"]
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                expires = None
        if not isinstance(expires, date):
            raise ValueError(f"{where}: 'expires' must be a date (YYYY-MM-DD)")
        if expires > today + timedelta(days=MAX_DAYS):
            raise ValueError(f"{where}: expires {expires.isoformat()}, more than one year ahead: "
                             "an accepted risk must be reviewed at least once a year")
        out.append(Acceptance(control, tuple(s.strip() for s in switches),
                              _text(entry, "reason", where, 10, 500), _text(entry, "approved_by", where, 2, 120),
                              expires, i))
    return out


def apply(device: str, findings: list[dict], acceptances: list[Acceptance], used: set[int],
          today: date | None = None) -> list[str]:
    """Mark the failed findings of one configuration that an acceptance covers ("accepted" key).
    Returns notes for expired acceptances; records the acceptances that matched in "used"."""
    today = today or date.today()
    notes = []
    for f in findings:
        if f["verdict"] != "fail":
            continue
        for a in acceptances:
            if a.control != f["control_id"] or not a.covers(device):
                continue
            used.add(a.index)
            if a.expires < today:
                notes.append(f"{device}: {a.label()} expired on {a.expires.isoformat()}: counted as a failure again")
                continue
            f["accepted"] = a.as_dict()
            break
    return notes


def unused(acceptances: list[Acceptance], used: set[int]) -> list[str]:
    """Acceptances that matched no failed control: the control passes now, or no switch matches."""
    return [f"{a.label()} for {', '.join(a.switches)} matched no failed control: remove it if the risk is gone"
            for a in acceptances if a.index not in used]
