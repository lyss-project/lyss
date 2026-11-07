# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Watch the CISA Known Exploited Vulnerabilities (KEV) catalog for the platforms LYSS knows.

    python tools/kev_watch.py [--kev known_exploited_vulnerabilities.json] [--summary FILE]

Reports KEV entries for those platforms (filters in data/kev-watch.yaml) that data/firmware.yaml
does not mention yet and that are not listed as not applicable in data/kev-watch.yaml:
  - NEW: added to KEV after reviewed_until -> exit code 1 (a scheduled CI run fails and notifies);
  - not yet reviewed: older entries, listed for information.
It reads only; firmware.yaml is updated by a person, with the vendor advisory as source.
Without --kev, the catalog is downloaded from CISA.
"""

import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lyss.ci import md_text  # noqa: E402

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
WATCH = ROOT / "data" / "kev-watch.yaml"
FIRMWARE = ROOT / "data" / "firmware.yaml"
CVE = re.compile(r"CVE-(\d{4})-(\d{4,})((?:/\d{4,})*)")


def known_cves(text: str) -> set[str]:
    """Every CVE mentioned in firmware.yaml, including the short form CVE-2023-20159/20160."""
    found = set()
    for year, first, more in CVE.findall(text):
        found.add(f"CVE-{year}-{first}")
        found.update(f"CVE-{year}-{n}" for n in more.split("/") if n)
    return found


def platform_of(entry: dict, filters: list[dict]) -> str | None:
    vendor, product = entry.get("vendorProject", ""), entry.get("product", "")
    for f in filters:
        if (re.search(f["vendor"], vendor, re.I) and re.search(f["product"], product, re.I)
                and not (f.get("exclude") and re.search(f["exclude"], product, re.I))):
            return f["platform"]
    return None


def load_kev(path: Path | None) -> dict:
    if path:
        return json.loads(path.read_text(encoding="utf-8"))
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "lyss-kev-watch"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.load(response)


def review(kev: dict, watch: dict, firmware_text: str) -> tuple[list[dict], list[dict], int]:
    since = str(watch["reviewed_until"])
    known = known_cves(firmware_text) | {str(n["cve"]) for n in watch.get("not_applicable") or []}
    new, backlog, covered = [], [], 0
    for entry in kev.get("vulnerabilities", []):
        platform = platform_of(entry, watch["filters"])
        if not platform:
            continue
        if entry.get("cveID") in known:
            covered += 1
            continue
        item = {**entry, "platform": platform}
        (new if str(entry.get("dateAdded", "")) > since else backlog).append(item)
    key = lambda e: (e["platform"], str(e.get("dateAdded", "")), e.get("cveID", ""))  # noqa: E731
    return sorted(new, key=key), sorted(backlog, key=key), covered


def markdown(kev: dict, watch: dict, new: list, backlog: list, covered: int) -> str:
    def rows(items):
        out = ["| Added | CVE | Platform | Vendor product | Vulnerability |", "|---|---|---|---|---|"]
        for e in items:
            out.append(f"| {md_text(e.get('dateAdded', ''))} | {md_text(e.get('cveID', ''))} | {md_text(e['platform'])} "
                       f"| {md_text(e.get('product', ''))} | {md_text(e.get('vulnerabilityName', ''))} |")
        return out
    out = [f"## CISA KEV watch: {len(new)} new, {len(backlog)} not yet reviewed, {covered} already reviewed", "",
           f"Catalog {md_text(kev.get('catalogVersion', '?'))} · reviewed until {md_text(watch['reviewed_until'])}", ""]
    if new:
        out += ["### New since the last review", "", *rows(new), "",
                "Check the vendor advisory (affected models, fixed releases), add the facts and their source "
                "to data/firmware.yaml, then move reviewed\\_until in data/kev\\-watch.yaml.", ""]
    if backlog:
        out += ["### Older entries not yet reviewed", "", *rows(backlog), ""]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kev", type=Path, help="a saved KEV JSON file (default: download from CISA)")
    ap.add_argument("--summary", type=Path, help="append a markdown report to this file (CI job summary)")
    args = ap.parse_args(argv)
    watch = yaml.safe_load(WATCH.read_text(encoding="utf-8"))
    kev = load_kev(args.kev)
    new, backlog, covered = review(kev, watch, FIRMWARE.read_text(encoding="utf-8"))
    def flat(value) -> str:   # feed text on one line: it can never start a line ("::command::")
        return " ".join(str(value).split())[:120]

    print(f"KEV {flat(kev.get('catalogVersion', '?'))}: {len(new)} new, {len(backlog)} not yet reviewed, "
          f"{covered} already reviewed (reviewed until {watch['reviewed_until']})")
    for label, items in (("NEW", new), ("not reviewed", backlog)):
        for e in items:
            print(f"  {label:12} {flat(e.get('dateAdded', ''))} {flat(e.get('cveID', '')):16} {e['platform']:13} "
                  f"{flat(e.get('product', ''))}")
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as out:
            out.write(markdown(kev, watch, new, backlog, covered))
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
