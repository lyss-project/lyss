# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Markdown summary of an offline audit, for CI job summaries (GitHub Actions, GitLab, ...).

Configurations in a repository are untrusted input (a pull request can change them), and the
summary is rendered by the CI platform: every value taken from a file (name, evidence) is
escaped, so it can never turn into a link, an image or HTML. Evidence is already redacted by
the engine and is shown only inside code spans."""

import re

from . import PROJECT_NAME, __version__

MAX_DETAILED = 100        # switches with failed controls detailed in full (job summaries are limited to 1 MiB)
MAX_ROWS = 500            # table rows; the JSON results always have everything
MAX_PROBLEMS = 50
MAX_NAME = 120            # characters of a configuration name shown
MAX_EVIDENCE = 160
MAX_SUMMARY = 900 * 1024  # bytes: below GitHub's 1 MiB limit for a step summary

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~&:])")


def md_text(value, limit: int = 400) -> str:
    """Plain text that markdown renders as itself: no link, image, HTML or table break."""
    text = " ".join(str(value).split())
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return _MD_SPECIAL.sub(r"\\\1", text)


def md_code(value) -> str:
    """A code span: never parsed as markdown or HTML. Backticks inside are replaced."""
    text = " ".join(str(value).split()).replace("`", "'")
    if len(text) > MAX_EVIDENCE:
        text = text[:MAX_EVIDENCE - 1] + "…"
    return f"`{text}`" if text else ""


def lowest_level(results: list[dict]) -> int | None:
    return min((r["summary"]["achieved_level"] for r in results), default=None)


MIN_ASSESSED = 0.5   # share of the applicable controls up to the required level that must be decided


def not_assessable(result: dict, required: int) -> bool:
    """True when most controls up to the required level could not be decided (pass or fail) from
    the file: e.g. a firmware-only platform, or a file mistaken for one. The gate cannot vouch for it."""
    relevant = [f for f in result["findings"] if f["level"] <= required and f["verdict"] != "not_applicable"
                and not f.get("advisory")]
    decided = [f for f in relevant if f["verdict"] in ("pass", "fail")]
    return bool(relevant) and len(decided) < MIN_ASSESSED * len(relevant)


def failing(results: list[dict], required: int | None) -> list[dict]:
    """Configurations with at least one FAILED control of level 1..required, or too few controls
    decided to be vouched for. A few unknown verdicts do not count: a saved file cannot show
    everything (automatic backups, firmware without state)."""
    if not required:
        return []
    return [r for r in results
            if any(f["verdict"] == "fail" and f["level"] <= required and not f.get("accepted") and not f.get("advisory")
                   for f in r["findings"])
            or not_assessable(r, required)]


def accepted_count(results: list[dict]) -> int:
    return sum(1 for r in results for f in r["findings"] if f["verdict"] == "fail" and f.get("accepted"))


def locate(text: str, evidence: list[str]) -> int | None:
    """Line number (1-based) of the first evidence line found in the configuration file. Evidence is
    "line", "block header / line" or a sentence; redacted parts ("<redacted>") match anything."""
    lines = [l.strip() for l in text.splitlines()]
    for item in evidence:
        part = item.rsplit(" / ", 1)[-1].strip()
        if not part:
            continue
        pieces = [re.escape(p) for p in part.split("<redacted>")]
        pattern = re.compile("^" + ".*".join(pieces) + "$")
        for n, line in enumerate(lines, 1):
            if line and pattern.match(line):
                return n
    return None


SEVERITY = {1: ("error", "8.0", "critical"), 2: ("warning", "5.0", "major"), 3: ("note", "3.0", "minor")}
MAX_RESULTS = 5000


def _failures(results: list[dict]):
    count = 0
    for r in results:
        for f in r["findings"]:
            if f["verdict"] == "fail":
                count += 1
                if count > MAX_RESULTS:
                    return
                yield r, f


def sarif(results: list[dict], spec: dict, uri_of) -> dict:
    """SARIF 2.1.0 for GitHub code scanning: one result per failed control, on the configuration
    line that proves it (line 1 when it is a missing setting). Accepted risks are suppressions.
    uri_of(result) gives the file path relative to the repository root."""
    rules = []
    for c in spec["controls"]:
        level, score, _ = SEVERITY[int(c["level"])]
        rules.append({
            "id": c["id"], "name": c["id"].replace("-", ""),
            "shortDescription": {"text": c["title"]},
            "fullDescription": {"text": " ".join(str(c.get("statement", c["title"])).split())},
            "help": {"text": " ".join(str(c.get("test_procedure", "")).split())
                     + f" Fix: lyss explain {c['id']} --vendor <platform>"},
            "helpUri": "https://lyss.dev",
            "defaultConfiguration": {"level": level},
            "properties": {"tags": ["security", "network-switch", f"lyss-level-{c['level']}"],
                           "security-severity": score, "precision": "high"},
        })
    out = []
    for r, f in _failures(results):
        level, _, _ = SEVERITY[int(f["level"])]
        evidence = f["evidence"][0] if f.get("evidence") else "setting missing from the configuration"
        if f.get("advisory"):   # reported, never an error: it does not count for conformance
            level, evidence = "note", f"{evidence} (advisory control: not counted for the level)"
        result = {
            "ruleId": f["control_id"], "level": level,
            "message": {"text": f"{f['title']}: {evidence}"[:1000]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri_of(r)},
                "region": {"startLine": f.get("line") or 1}}}],
            "partialFingerprints": {"lyssFinding/v1": f"{uri_of(r)}:{f['control_id']}"},
        }
        if f.get("accepted"):
            a = f["accepted"]
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": f"{a['reason']} (approved by {a['approved_by']}, until {a['expires']})"[:1000]}]
        out.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": PROJECT_NAME, "version": __version__,
                                          "semanticVersion": __version__, "informationUri": "https://lyss.dev",
                                          "rules": rules}},
                      "properties": {"specification": spec["spec_version"]},
                      "results": out}]}


def codequality(results: list[dict], uri_of) -> list[dict]:
    """GitLab Code Quality report (Code Climate format): shown in merge requests on every GitLab
    tier. Accepted risks are left out (GitLab has no suppression field); they stay in the JSON."""
    import hashlib
    out = []
    for r, f in _failures(results):
        if f.get("accepted"):
            continue
        evidence = f["evidence"][0] if f.get("evidence") else "setting missing from the configuration"
        path = uri_of(r)
        out.append({
            "type": "issue", "check_name": f["control_id"],
            "description": f"{f['control_id']} {f['title']}: {evidence}"[:1000],
            "categories": ["Security"], "severity": "info" if f.get("advisory") else SEVERITY[int(f["level"])][2],
            "fingerprint": hashlib.sha256(f"{path}:{f['control_id']}".encode()).hexdigest(),
            "location": {"path": path, "lines": {"begin": f.get("line") or 1}},
        })
    return out


def summary_markdown(results: list[dict], spec_version: str, level: int, required: int | None = None,
                     problems: list[str] | None = None) -> str:
    low = lowest_level(results)
    bad = failing(results, required)
    out = [f"## {PROJECT_NAME} audit: {len(results)} switch configuration(s)"
           + (f", lowest level {low}" if low is not None else ""), ""]
    facts = [f"assessed up to Level {level}", f"specification {md_text(spec_version)}", f"{PROJECT_NAME} {__version__}"]
    if required:
        facts.insert(0, f"**required: no failed control up to Level {required}, {len(bad)} configuration(s) fail it**")
    out += [" · ".join(facts), ""]
    if accepted_count(results):
        out += [f"{accepted_count(results)} failed control(s) are accepted risks: they still count as failed for "
                "the level, and do not fail the job until their expiry date.", ""]
    if any(r["summary"]["unknown"] for r in results):
        out += ["Level = the level the saved file alone proves. Unknown controls (for example automatic "
                "backups, which a file cannot show) are listed but never fail the job.", ""]
    problems = problems or []
    for problem in problems[:MAX_PROBLEMS]:
        out.append(f"> {md_text(problem)}")
    if len(problems) > MAX_PROBLEMS:
        out.append(f"> {len(problems) - MAX_PROBLEMS} more problem(s): see the job log.")
    if problems:
        out.append("")
    if not results:
        out.append("No switch configuration was assessed.")
        return "\n".join(out) + "\n"

    out += ["| Configuration | Platform | Level | Pass | Fail | Unknown |", "|---|---|---|---|---|---|"]
    order = sorted(results, key=lambda r: (r["summary"]["achieved_level"], r["device"]))
    bad_ids = {id(r) for r in bad}
    for r in order[:MAX_ROWS]:
        s = r["summary"]
        mark = ""
        if id(r) in bad_ids:
            mark = (f" **not assessable at Level {required}**" if not any(
                f["verdict"] == "fail" and f["level"] <= required and not f.get("accepted") and not f.get("advisory")
                for f in r["findings"])
                else f" **fails Level {required}**")
        out.append(f"| {md_text(r['device'], MAX_NAME)}{mark} | {md_text(r['vendor'])} | {s['achieved_level']} "
                   f"| {s['pass']} | {s['fail']} | {s['unknown']} |")
    if len(order) > MAX_ROWS:
        out.append(f"| {len(order) - MAX_ROWS} more: see the JSON results | | | | | |")
    out.append("")

    footer = ["Evidence is redacted (passwords, keys, communities, hashes). Fix for every control: https://lyss.dev"]
    size = sum(len(l.encode()) + 1 for l in out) + 200
    detailed = [r for r in order if r["summary"]["fail"]]
    shown = 0
    for r in detailed[:MAX_DETAILED]:
        fails = [f for f in r["findings"] if f["verdict"] == "fail"]
        block = [f"### {md_text(r['device'], MAX_NAME)}: {len(fails)} failed control(s)", ""]
        for f in fails:
            evidence = md_code(f["evidence"][0]) if f.get("evidence") else ""
            a = f.get("accepted")
            accepted = (f" _(accepted risk until {md_text(a['expires'])}, {md_text(a['approved_by'], 120)}: "
                        f"{md_text(a['reason'], 300)})_") if a else ""
            advisory = " _(advisory: not counted for the level)_" if f.get("advisory") else ""
            block.append(f"- **{md_text(f['control_id'])}** {md_text(f['title'])}" + (f": {evidence}" if evidence else "")
                         + accepted + advisory)
        block.append("")
        block_size = sum(len(l.encode()) + 1 for l in block)
        if size + block_size > MAX_SUMMARY:
            break
        out += block
        size += block_size
        shown += 1
    if len(detailed) > shown:
        out += [f"{len(detailed) - shown} more configuration(s) with failed controls: see the JSON results.", ""]
    return "\n".join(out + footer) + "\n"
