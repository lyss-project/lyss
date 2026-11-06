# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Evaluate a parsed configuration against LYSS controls through a vendor adapter."""

import os
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

import yaml

from .config import Config, parse

# project home (spec/, adapters/, data/): LYSS_HOME if set, else the source checkout
ROOT = Path(os.environ.get("LYSS_HOME") or Path(__file__).resolve().parents[2])
SPEC_FILE = ROOT / "spec" / "lyss-spec.yaml"
ADAPTER_DIR = ROOT / "adapters"


@dataclass
class Finding:
    control_id: str
    level: int
    title: str
    verdict: str        # pass | fail | unknown | not_applicable
    evidence: list[str]  # config lines that drove the verdict
    note: str
    remediation: str
    mappings: dict


def load_spec(path: Path = SPEC_FILE) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_adapter(vendor: str) -> dict:
    path = ADAPTER_DIR / f"{vendor}.yaml"
    if not path.exists():
        known = ", ".join(p.stem for p in ADAPTER_DIR.glob("*.yaml"))
        raise ValueError(f"unknown vendor '{vendor}' (available: {known})")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# Secret values never leave the engine: evidence keeps the keyword and type, not the value.
SECRET_VALUE = re.compile(
    r'(?i)\b(secret|password|key-string|key|sha1|sha256|plaintext|encrypted)'
    r'((?:\s+(?:\d{1,2}|level \d+))?)\s+("?)(?!<redacted>|<masked>)(?!(?:manager|operator|encrypted|level)\b)(?![^\s"]+\s+<masked>)[^\s"]+("?)'
)
# SNMPv3 users: "auth sha <pw> priv aes 128 <pw>" (Cisco), 'auth sha "<hash>" priv aes "<hash>"' (HP),
# "auth-sha <pw>" / "priv-aes <pw>" variants
SNMP_SECRET = re.compile(
    r'(?i)\b(auth[\s-]+(?:sha\d*|md5)|priv(?:[\s-]+(?:aes|des|3des)(?:\s+\d{3})?)?)\s+("?)(?!<redacted>)[^\s"]+("?)')
WEAK_COMMUNITY_OK = re.compile(r'(?i)\bcommunity\s+"?(public|private)"?(\s|$)')
COMMUNITY_VALUE = re.compile(r'(?i)\b(community)\s+("?)[^\s"]+("?)')


# JSON configurations flattened by config.flatten_json (SONiC): "passkey=...", "auth_password=...",
# and SNMP community names used as table keys ("SNMP_COMMUNITY|<name>")
# (also inside block evidence such as "TACPLUS|global / passkey=...")
FIELD_SECRET = re.compile(r"(?i)\b([\w-]*(?:passkey|password|secret|key)[\w-]*=)(?!<redacted>)\S+")
JSON_COMMUNITY = re.compile(r"(?i)(SNMP_COMMUNITY\|)(?!(?:public|private)(?:[\s/]|$))(?!<redacted>)[^\s/]+")


def redact(line: str) -> str:
    line = FIELD_SECRET.sub(r"\1<redacted>", line)
    line = JSON_COMMUNITY.sub(r"\1<redacted>", line)
    line = SECRET_VALUE.sub(r"\1\2 \3<redacted>\4", line)
    if re.search(r"(?i)^\s*(snmp-server user|snmpv3 user)\b", line):
        line = SNMP_SECRET.sub(r"\1 \2<redacted>\3", line)
    if not WEAK_COMMUNITY_OK.search(line):
        # well-known defaults stay visible (they are the finding); real communities are secrets
        line = COMMUNITY_VALUE.sub(r"\1 \2<redacted>\3", line)
    return line


def _line_hits(lines: list[str], rule: dict) -> list[str]:
    pattern = re.compile(rule["line"])
    hits = []
    for line in lines:
        m = pattern.search(line)
        if not m:
            continue
        if "gt" in rule and not (m.groups() and int(m.group(1)) > rule["gt"]):
            continue
        hits.append(line)
    return hits


def _state_lines(cfg: Config, section: str | None) -> list[str] | None:
    """Lines of one state section (None if it was not collected), or of all sections."""
    if section is None:
        return [line for lines in cfg.state.values() for line in lines] if cfg.state else None
    return cfg.state.get(section)


PORT_PREFIXES = (("tengigabitethernet", "te"), ("gigabitethernet", "gi"), ("fastethernet", "fa"))


def normalize_port(name: str) -> str:
    """"GigabitEthernet1/0/5", "gigabitethernet5", "Gig 1/0/5" and "gi5" style names -> "gi1/0/5"."""
    n = name.strip().lower().replace(" ", "")
    for long, short in PORT_PREFIXES:
        if n.startswith(long):
            return short + n[len(long):]
    return "gi" + n[3:] if n.startswith("gig") else n


def _port_sort(port: str) -> list:
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", port)]


def _ports(cfg: Config, spec: dict) -> set[str]:
    lines = _state_lines(cfg, spec.get("section")) or []
    pattern = re.compile(spec["line"])
    return {normalize_port(m.group(1)) for line in lines if (m := pattern.search(line))}


PORT_TOKEN = re.compile(r"^([A-Za-z]*)(\d+)$")


def expand_ports(text: str) -> set[str]:
    """HP-style port lists -> normalized names: "1-4,A1-A2,Trk1" -> {"1".."4", "a1", "a2", "trk1"}."""
    ports = set()
    for item in text.replace('"', "").split(","):
        item = item.strip()
        if not item:
            continue
        first, _, last = item.partition("-")
        a, b = PORT_TOKEN.match(first), PORT_TOKEN.match(last) if last else None
        if a and b and a.group(1).lower() == b.group(1).lower() and int(a.group(2)) <= int(b.group(2)):
            ports |= {f"{a.group(1).lower()}{n}" for n in range(int(a.group(2)), int(b.group(2)) + 1)}
        else:
            ports.add(normalize_port(item))
    return ports


def _listed_ports(cfg: Config, patterns) -> set[str]:
    """Ports named by port-list config lines; each regex's group 1 is a list ("1-24,Trk1")."""
    ports = set()
    for pattern in patterns if isinstance(patterns, list) else [patterns]:
        regex = re.compile(pattern)
        for line in cfg.lines:
            if m := regex.search(line):
                ports |= expand_ports(m.group(1))
    return ports


def _edge_ports_missing(cfg: Config, spec: dict) -> tuple[bool, list[str]]:
    """Edge ports (all ports minus uplinks seen in config or in neighbour tables) lacking a setting.
    Per-interface platforms (Cisco) use uplink_config / require on "interface" blocks; port-list
    platforms (HP) use uplink_lists / require_lists on global lines such as "trunk 25-26 trk1"."""
    ports = _ports(cfg, spec["ports"])
    if not ports:
        return False, []
    blocks = {normalize_port(b.header.split(None, 1)[1]): b.children
              for b in cfg.blocks if b.header.lower().startswith("interface ") and " " in b.header}
    uplink_config = re.compile(spec["uplink_config"]) if spec.get("uplink_config") else None
    require = re.compile(spec["require"]) if spec.get("require") else None
    uplinks = set()
    for source in spec.get("uplink_state", []):
        uplinks |= _ports(cfg, source)
    if uplink_config:
        uplinks |= {p for p, children in blocks.items() if any(uplink_config.search(c) for c in children)}
    if spec.get("uplink_lists"):
        uplinks |= _listed_ports(cfg, spec["uplink_lists"])
    covered = _listed_ports(cfg, spec["require_lists"]) if spec.get("require_lists") else set()
    missing = [p for p in sorted(ports - uplinks, key=_port_sort)
               if p not in covered and not (require and any(require.search(c) for c in blocks.get(p, [])))]
    edge = len(ports - uplinks)
    if missing:
        return True, [f"{len(missing)} of {edge} edge ports lack it: {', '.join(missing)}",
                      f"uplinks excluded: {', '.join(sorted(uplinks & ports, key=_port_sort)) or 'none'}"]
    return False, [f"all {edge} edge ports have it; uplinks excluded: "
                   f"{', '.join(sorted(uplinks & ports, key=_port_sort)) or 'none'}"]


def _captures(cfg: Config, source) -> dict[str, list[str]]:
    """Values (regex group 1) captured by a source, with the evidence lines of each value.
    Sources: {line: R} any config line; {block: H, where: W} the block header itself;
    {block: H, where: W, line: R} a line inside the block; {untagged_access_vlans: true} VLANs
    with untagged ports that are neither tagged elsewhere nor trunk groups (HP port lists).
    A list of sources is their union."""
    found: dict[str, list[str]] = {}
    if isinstance(source, list):
        for s in source:
            for value, evidence in _captures(cfg, s).items():
                found.setdefault(value, []).extend(evidence)
        return found
    if source.get("untagged_access_vlans"):
        vlan_blocks = [(m.group(1), b) for b in cfg.blocks if (m := re.match(r"^vlan (\d+)$", b.header))]
        tagged = set()
        for _, b in vlan_blocks:
            for c in b.children:
                if m := re.match(r"^tagged (\S+)", c):
                    tagged |= expand_ports(m.group(1))
        for vlan, b in vlan_blocks:
            for c in b.children:
                if m := re.match(r"^untagged (\S+)", c):
                    access = {p for p in expand_ports(m.group(1)) - tagged if not p.startswith("trk")}
                    if access:
                        found.setdefault(vlan, []).append(
                            f"vlan {vlan} / untagged access ports: {', '.join(sorted(access, key=_port_sort))}")
        return found
    if "block" not in source:
        regex = re.compile(source["line"])
        for line in cfg.lines:
            if m := regex.search(line):
                found.setdefault(m.group(1), []).append(line)
        return found
    header = re.compile(source["block"])
    where = re.compile(source["where"]) if source.get("where") else None
    line = re.compile(source["line"]) if source.get("line") else None
    for b in cfg.blocks:
        hm = header.search(b.header)
        if not hm or (where and not any(where.search(c) for c in b.children)):
            continue
        if line is None:
            found.setdefault(hm.group(1), []).append(b.header)
            continue
        for c in b.children:
            if m := line.search(c):
                found.setdefault(m.group(1), []).append(f"{b.header} / {c}")
    return found


def evaluate_rule(cfg: Config, rule: dict) -> tuple[bool, list[str]]:
    """Return (matched, evidence lines). A rule's "say" replaces the evidence with a sentence."""
    matched, evidence = _evaluate_rule(cfg, rule)
    if matched and rule.get("say"):
        evidence = [rule["say"]]
    return matched, evidence


def _evaluate_rule(cfg: Config, rule: dict) -> tuple[bool, list[str]]:
    if "edge_ports_missing" in rule:
        matched, evidence = _edge_ports_missing(cfg, rule["edge_ports_missing"])
        if rule.get("absent"):
            # pass form: ports were collected and none is missing the setting
            return (not matched and bool(evidence)), evidence
        return matched, evidence

    if "captures_in_both" in rule:
        # a value captured in two places, e.g. the management VLAN also used by access ports
        a_source, b_source = rule["captures_in_both"]
        a, b = _captures(cfg, a_source), _captures(cfg, b_source)
        common = sorted(set(a) & set(b), key=_port_sort)
        evidence = []
        for value in common:
            more = f" (+{len(b[value]) - 1} more)" if len(b[value]) > 1 else ""
            evidence.append(f"{a[value][0]}  <->  {b[value][0]}{more}")
        return bool(common), evidence

    if "ports_in_both" in rule:
        # ports present in two state tables, e.g. operationally down AND administratively up
        a, b = rule["ports_in_both"]
        ports = sorted(_ports(cfg, a) & _ports(cfg, b), key=_port_sort)
        if len(ports) > rule.get("gt", 0):
            return True, [f"{len(ports)} ports: {', '.join(ports)}"]
        return False, []

    if "state" in rule:
        lines = _state_lines(cfg, rule.get("section"))
        if lines is None:
            return False, []  # not collected: the rule can neither pass nor fail
        hits = _line_hits(lines, {**rule, "line": rule["state"]})
        if rule.get("absent"):
            return not hits, [f"{rule.get('section', 'state')}: no line matches {rule['state']}"] if not hits else []
        return bool(hits), hits

    if "block" not in rule:
        hits = _line_hits(cfg.lines, rule)
        return bool(hits), hits

    header = re.compile(rule["block"])
    blocks = [b for b in cfg.blocks if header.search(b.header)]
    if "where" in rule:
        # only blocks that contain a given line, e.g. access ports ("switchport mode access")
        where = re.compile(rule["where"])
        blocks = [b for b in blocks if any(where.search(c) for c in b.children)]

    if "every_contains" in rule:
        pattern = re.compile(rule["every_contains"])
        if not blocks:
            return False, []
        ok = all(any(pattern.search(c) for c in b.children) for b in blocks)
        evidence = [f"{b.header} / {c}" for b in blocks for c in b.children if pattern.search(c)]
        return ok, evidence

    evidence = [f"{b.header} / {hit}" for b in blocks for hit in _line_hits(b.children, rule)]
    return bool(evidence), evidence


def backup_verdict(backup: dict | None, max_age_days: int) -> tuple[str | None, list[str]]:
    """LYSS-BKP-001 from the configuration archive / attestation (None verdict = no evidence)."""
    if not backup:
        return None, []
    now = datetime.now()
    att = backup.get("attestation")
    if att and not att.get("expired"):
        return "pass", [f"external backup attested on {att['date'][:10]}: {att['reference']} "
                        f"(valid until {att['expires'][:10]})"]
    auto = backup.get("last_automatic")
    if auto:
        age = (now - datetime.fromisoformat(auto)).days
        if age <= max_age_days:
            return "pass", [f"automatic configuration backup by scheduled scan on {auto.replace('T', ' ')} "
                            f"({backup.get('versions', 0)} versions kept)"]
        return "fail", [f"last automatic backup {auto.replace('T', ' ')} is {age} days old (max {max_age_days})"]
    evidence = [f"only manual collections (last {backup['last'].replace('T', ' ')})"] if backup.get("last") else []
    if att and att.get("expired"):
        evidence.append(f"external backup attestation expired on {att['expires'][:10]}")
    return "fail", evidence or ["no configuration backup recorded"]


def evaluate_control(cfg: Config, control: dict, check: dict | None, facts: dict | None = None,
                     context: dict | None = None) -> Finding:
    def finding(verdict: str, evidence: list[str], from_default: bool = False) -> Finding:
        # The adapter note explains verdicts reached without evidence (vendor defaults, missing data)
        show_note = from_default and verdict != "pass"
        return Finding(
            control_id=control["id"],
            level=control["level"],
            title=control["title"],
            verdict=verdict,
            evidence=[redact(e) for e in evidence],
            note=(check or {}).get("note", "") if show_note else "",
            remediation=(check or {}).get("remediation", "").strip() if verdict == "fail" else "",
            mappings=control.get("mappings", {}),
        )

    if check is None:
        return finding("not_applicable", [])

    # every failing rule contributes evidence, so the report shows all the reasons at once
    failed = [ev for matched, ev in (evaluate_rule(cfg, r) for r in check.get("fail_if_any", [])) if matched]
    if failed:
        return finding("fail", [e for ev in failed for e in ev])

    if check.get("backup") and (context or {}).get("backup") is not None:
        max_age = (control.get("parameters") or {}).get("max_age_days", 7)
        verdict, evidence = backup_verdict(context["backup"], max_age)
        if verdict:
            return finding(verdict, evidence)

    if check.get("firmware"):
        verdict, evidence = firmware_verdict(facts or {})
        if verdict:
            return finding(verdict, evidence)
        if (facts or {}).get("model"):
            seen = f"model {facts['model']}, firmware {facts.get('version', '?')}: platform not in data/firmware.yaml yet"
            return finding("unknown", [seen])

    pass_rules = check.get("pass_if_all", [])
    if pass_rules:
        results = [evaluate_rule(cfg, r) for r in pass_rules]
        if all(matched for matched, _ in results):
            return finding("pass", [e for _, ev in results for e in ev])

    for rule in check.get("pass_if_any", []):
        matched, evidence = evaluate_rule(cfg, rule)
        if matched:
            return finding("pass", evidence)

    return finding(check.get("otherwise", "unknown"), [], from_default=True)


def extract_facts(cfg: Config, adapter: dict) -> dict:
    """Model, firmware version... from device state, as declared by the adapter."""
    facts = {"vendor": adapter["adapter"]}
    for name, specs in adapter.get("facts", {}).items():
        # a fact may list several sources; the first one that matches wins
        for spec in specs if isinstance(specs, list) else [specs]:
            pattern = re.compile(spec["line"])
            # "config comments": header comments of the configuration itself (HP release line)
            source = cfg.comments if spec.get("section") == "config comments" else _state_lines(cfg, spec.get("section"))
            for line in source or []:
                if m := pattern.search(line):
                    facts[name] = spec.get("format", "{0}").format(*m.groups()).strip()
                    break
            if name in facts:
                break
    return facts


def _version_tuple(version: str) -> tuple[int, ...]:
    # "2.5.9.16" -> (2, 5, 9, 16); "15.2(7)E8" -> (15, 2, 7, 8): compare within one release train only
    return tuple(int(n) for n in re.findall(r"\d+", version))


def firmware_verdict(facts: dict) -> tuple[str | None, list[str]]:
    """Compare model/version facts with data/firmware.yaml. None verdict = no data, fall through."""
    model, version = facts.get("model"), facts.get("version")
    if not model or not version:
        return None, []
    for entry in load_firmware_data():
        if entry["vendor"] != facts.get("vendor") or not re.search(entry["models"], model):
            continue
        evidence = [f"model {model}, firmware {version}"]
        problems = []
        eos = entry.get("end_of_support")
        if eos and str(eos) <= date.today().isoformat():
            problems.append(f"vendor support ended {eos}")
        for adv in entry.get("advisories", []):
            fixed = adv.get("fixed_in")
            if fixed is None or _version_tuple(version) < _version_tuple(fixed):
                exploited = ", exploited in the wild (CISA KEV)" if adv.get("kev") else ""
                problems.append(f"{adv['id']} (CVSS {adv['cvss']}{exploited}): "
                                + (f"fixed in {fixed}" if fixed else "no fix for this model"))
        if problems:
            return "fail", evidence + problems
        return "pass", evidence + [f"no critical advisory in LYSS data ({entry['source']})"]
    return None, []


def load_firmware_data() -> list[dict]:
    path = ROOT / "data" / "firmware.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))["platforms"] if path.exists() else []


def audit(text: str, vendor: str, max_level: int = 1, state_text: str = "",
          context: dict | None = None) -> list[Finding]:
    """Assess one device. context carries evidence from outside the device (e.g. "backup")."""
    spec = load_spec()
    adapter = load_adapter(vendor)
    cfg = parse(text, state_text)
    facts = extract_facts(cfg, adapter)
    checks = adapter.get("checks", {})
    return [
        evaluate_control(cfg, control, checks.get(control["id"]), facts, context)
        for control in spec["controls"]
        if control["level"] <= max_level
    ]


def conformance(findings: list[Finding]) -> dict:
    """Highest level for which every applicable control passes (0 if Level 1 is not met)."""
    achieved = 0
    for level in sorted({f.level for f in findings}):
        relevant = [f for f in findings if f.level == level and f.verdict != "not_applicable"]
        if relevant and all(f.verdict == "pass" for f in relevant):
            achieved = level
        else:
            break
    return {
        "achieved_level": achieved,
        "pass": sum(f.verdict == "pass" for f in findings),
        "fail": sum(f.verdict == "fail" for f in findings),
        "unknown": sum(f.verdict == "unknown" for f in findings),
    }
