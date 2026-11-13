# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Generate docs/LYSS-Specification.md and docs/MAPPINGS.md (crosswalk) from spec/lyss-spec.yaml
(the normative source).

    python tools/build_spec.py          write the documents
    python tools/build_spec.py --check  exit 1 if a document is out of date (CI, tests)
"""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "lyss-spec.yaml"
OUT = ROOT / "docs" / "LYSS-Specification.md"
CROSSWALK = ROOT / "docs" / "MAPPINGS.md"
# NIS2 = Directive (EU) 2022/2555, Article 21(2): short labels of points (a)-(j), Official Journal
# L 333, 27.12.2022 (EUR-Lex CELEX:32022L2555)
NIS2_POINTS = {
    "a": "Policies on risk analysis and information system security",
    "b": "Incident handling",
    "c": "Business continuity, such as backup management and disaster recovery, and crisis management",
    "d": "Supply chain security",
    "e": "Security in network and information systems acquisition, development and maintenance, "
         "including vulnerability handling and disclosure",
    "f": "Policies and procedures to assess the effectiveness of cybersecurity risk-management measures",
    "g": "Basic cyber hygiene practices and cybersecurity training",
    "h": "Policies and procedures regarding the use of cryptography and, where appropriate, encryption",
    "i": "Human resources security, access control policies and asset management",
    "j": "Multi-factor or continuous authentication, secured voice, video and text communications "
         "and secured emergency communication systems",
}
FRAMEWORKS = (  # key in the specification, title, how a reference is shown
    ("nis2_art21", "NIS2 Directive, Article 21(2)", lambda v: f"21(2)({v})"),
    ("iso27001_2022", "ISO/IEC 27001:2022, Annex A", str),
    ("nist_800_53r5", "NIST SP 800-53 revision 5", str),
    ("cis_v8", "CIS Controls v8 (safeguards)", str),
)
LEVEL_PROSE = {
    1: "the minimum every managed switch must meet: no cleartext management, no default or recoverable credentials, supported firmware, automatic backups.",
    2: "a hardened management plane: central authentication, restricted and modern management access, remote logging and time, basic access-port hygiene.",
    3: "access-layer protections against attacks from user ports: DHCP snooping, ARP inspection, port authentication, storm control, no neighbor discovery towards users.",
}


def mapping(values) -> str:
    return ", ".join(str(v) for v in values) if values else "—"


def build() -> str:
    spec = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    controls = spec["controls"]
    out = [
        "<!-- Generated from spec/lyss-spec.yaml by tools/build_spec.py. Do not edit by hand. -->",
        "",
        "# LYSS Specification: security controls for network switches",
        "",
        f"**Version {spec['spec_version']}** · Status: {spec.get('status', 'draft')} · "
        "Licence: [CC BY 4.0](../LICENSE-SPEC) · Author: Mouad Lyaazale",
        "",
        "## 1. Scope",
        "",
        "LYSS (Lyaazale Switch Security) defines, once and independently of any vendor, what a securely",
        "managed network switch looks like, and how conformance is assessed and claimed. It applies to",
        "managed Ethernet switches of any vendor, whatever their age. How each control is verified on a",
        "given platform is defined by *adapters*, maintained separately from this document.",
        "",
        "This document is generated from `spec/lyss-spec.yaml`, which is the normative source.",
        "",
        "## 2. Conventions and terms",
        "",
        "The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in",
        "RFC 2119 and RFC 8174 when, and only when, they appear in capitals.",
        "",
        "- **Control**: a security requirement with a stable identifier (`LYSS-<DOMAIN>-<NNN>`), a level,",
        "  a statement, a rationale and a vendor-neutral test procedure.",
        "- **Adapter**: the interpretation of the controls for one platform family (how to check, how to fix).",
        "- **Evidence**: the data a verdict is based on: `config` (running configuration), `state` (read-only",
        "  device state such as listening ports, SSH banner, port status), `external_data` (vendor advisories,",
        "  end-of-life bulletins), `backup_system` (configuration archive or attested backup system).",
        "- **Verdict**: the result of one control on one device: `pass`, `fail`, `unknown` or `not_applicable`.",
        "- **Uplink**: a link to another switch: a port configured as a trunk (on platforms without a trunk",
        "  mode, a tagged port), or a member port of a link aggregation that is a trunk. Any port configured",
        "  this way is treated as an uplink, whatever is connected to it: review trunk ports separately.",
        "- **Edge port**: any switch port that is neither an uplink nor a routed port. A link aggregation that",
        "  is not a trunk (for example towards a server) is one edge port, assessed on its logical interface.",
        "- **Access port**: an edge port that is administratively enabled. Its untagged VLAN is a **user VLAN**.",
        "- **Management VLAN**: the VLAN that carries the switch's in-band management address. A dedicated",
        "  out-of-band management port belongs to no VLAN.",
        "- **Advisory control**: a control added within a MAJOR version (see section 8). It is assessed and",
        "  reported like any control but does not count for conformance until the next MAJOR version, where it",
        "  becomes a normal control or is withdrawn.",
        "",
        "## 3. Verdicts",
        "",
        "- `pass`: the evidence shows that the control is met.",
        "- `fail`: the evidence shows that the control is not met.",
        "- `unknown`: the available evidence cannot decide. An assessment MUST report `unknown` rather than",
        "  guess, and MUST NOT turn a missing evidence into a pass.",
        "- `not_applicable`: the control does not apply to the device, because what it protects does not",
        "  exist there, for example the Level 3 controls on a switch without access ports. A missing security",
        "  feature is not a reason for `not_applicable`: unless a control says otherwise, it fails.",
        "",
        "## 4. Conformance levels",
        "",
        "| Level | Name | Intent |",
        "|---|---|---|",
    ]
    for level, name in spec["levels"].items():
        out.append(f"| {level} | {name} | {LEVEL_PROSE.get(level, '')} |")
    out += [
        "",
        "A device is **LYSS Level N conformant** when every control of levels 1 to N, advisory controls",
        "aside, is `pass` or `not_applicable`. An `unknown` verdict is not a pass. A conformance claim MUST",
        "state the device,",
        "the specification version, the assessment date and the tool and version used, for example:",
        "",
        f"> core-sw-01 is LYSS Level 1 conformant (specification {spec['spec_version']}), assessed 2026-11-11 with LYSS 0.20.",
        "",
        "A claim is valid for the configuration and firmware assessed; any change requires a new assessment.",
        "",
        "Controls with parameters (for example `max_idle_minutes`) are assessed with the values given in",
        "this document. An organisation MAY assess with stricter values; the claim then states them. An",
        "assessment with a looser value does not support a LYSS conformance claim.",
        "",
        "## 5. Control catalogue",
        "",
        "| ID | Level | Title |",
        "|---|---|---|",
    ]
    for c in controls:
        advisory = " (advisory)" if c.get("status") == "advisory" else ""
        out.append(f"| [{c['id']}](#{c['id'].lower()}) | {c['level']}{advisory} | {c['title']} |")
    out.append("")
    for level, name in spec["levels"].items():
        out += [f"### Level {level}: {name}", ""]
        for c in (c for c in controls if c["level"] == level):
            m = c.get("mappings", {})
            out += [f"#### {c['id']}", "", f"**{c['title']}**", ""]
            if c.get("status") == "advisory":
                out += [f"*Advisory control (added in {c.get('added', 'this version')}): reported, not counted for "
                        "conformance until the next MAJOR version.*", ""]
            if c.get("statement"):
                out += [f"- **Requirement.** {c['statement']}"]
            if c.get("rationale"):
                out += [f"- **Rationale.** {c['rationale']}"]
            if c.get("test_procedure"):
                out += [f"- **Test procedure.** {c['test_procedure']}"]
            if c.get("parameters"):
                out += ["- **Parameters.** " + ", ".join(f"`{k}` = {v}" for k, v in c["parameters"].items())]
            out += [f"- **Evidence.** {', '.join(c.get('evidence', []))}",
                    f"- **References (informative).** ISO/IEC 27001:2022 {mapping(m.get('iso27001_2022'))}"
                    f" · NIST SP 800-53 r5 {mapping(m.get('nist_800_53r5'))}"
                    f" · CIS Controls v8 {mapping(m.get('cis_v8'))}"
                    f" · NIS2 Art. {mapping([f'21(2)({p})' for p in m.get('nis2_art21') or []])}", ""]
            if not c.get("test_procedure"):
                out += ["*Draft: requirement text and checks to be written.*", ""]
    out += [
        "## 6. Requirements for adapters",
        "",
        "An adapter for a platform family:",
        "",
        "1. MUST identify the platform it covers and the specification version it implements.",
        "2. MUST map each check to an existing control identifier and MUST NOT change a control's meaning.",
        "3. MUST yield `unknown` when the platform hides a default or the evidence is missing.",
        "4. SHOULD provide, for each failing control, a remediation that an administrator can review.",
        "5. MUST be accompanied by test cases in which each implemented control passes and fails.",
        "",
        "## 7. Requirements for assessment tools",
        "",
        "1. Collection MUST be read-only: no command that changes the device configuration or state.",
        "2. Secrets (password hashes, keys, SNMP communities) MUST be redacted from stored and reported evidence;",
        "   well-known default values MAY remain visible because they are the finding.",
        "3. Credentials used for collection MUST be stored encrypted.",
        "4. Reports MUST state the specification version, the evidence of each verdict and the assessment date.",
        "",
        "### 7.1 Optional remediation",
        "",
        "A tool MAY offer to apply fixes. If it does, remediation:",
        "",
        "1. MUST be disabled by default and MUST never run without an explicit action of an administrator.",
        "2. MUST show the exact commands and their rollback before they are applied.",
        "3. MUST be limited to changes that cannot cut management or user access; credentials, access",
        "   lists, VLANs, authentication, spanning tree and port shutdowns remain manual changes.",
        "4. MUST back up the configuration first, apply one device at a time, and roll back on the first",
        "   rejected command.",
        "5. MUST verify the result over a new management connection and roll back fixes whose control",
        "   does not pass, and MUST only save the configuration after verification.",
        "6. MUST record every change (date, device, commands, outcome) in a change log.",
        "",
        "## 8. Versioning",
        "",
        "From 1.0.0 the specification follows semantic versioning:",
        "",
        "- **MAJOR**: a control is withdrawn, made stricter in a way that can turn a pass into a fail, or moved",
        "  to another level, or an advisory control becomes a normal control.",
        "- **MINOR**: an advisory control is added to an existing level, a level is added above the existing",
        "  ones (its controls are normal controls of that new level), or a wording changes without changing",
        "  any verdict.",
        "- **PATCH**: typos and references.",
        "",
        "A control added to an existing level within a MAJOR version is always advisory (section 2), so a device that conforms to",
        "1.x Level N still conforms to every later 1.y Level N with the same configuration and firmware",
        "(newly published vulnerabilities aside: LYSS-VULN-001 follows the vulnerability data, not the version).",
        "",
        "Control identifiers are never reused, renamed or renumbered. A withdrawn control keeps its identifier, marked withdrawn.",
        "Versions below 1.0.0 were drafts and could change without a MAJOR increment. A release candidate",
        "(1.0.0-rc.N) is the text proposed for 1.0.0, open for public review (docs/REVIEW-1.0.md): it MAY still",
        "change; each change gives a new release-candidate number and is listed in the changelog (see",
        "docs/VERSIONING.md).",
        "",
        "## 9. References (informative)",
        "",
        "Mappings to ISO/IEC 27001:2022 Annex A, NIST SP 800-53 revision 5, CIS Controls v8 and",
        "Article 21(2) of the NIS2 Directive (EU) 2022/2555 are informative: they help reuse LYSS",
        "results as audit evidence and do not change the requirements. The same mappings, read from each",
        "framework, are in [MAPPINGS.md](MAPPINGS.md).",
        "",
    ]
    return "\n".join(out)


def _natural(ref: str) -> list:
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", ref)]


def build_crosswalk() -> str:
    spec = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    controls = spec["controls"]
    out = [
        "<!-- Generated from spec/lyss-spec.yaml by tools/build_spec.py. Do not edit by hand. -->",
        "",
        "# Crosswalk: frameworks to LYSS controls",
        "",
        f"Specification {spec['spec_version']}. For each requirement of a framework, the LYSS controls",
        "whose results can serve as **part** of the evidence for it.",
        "",
        "**Informative only.**",
        "- These mappings are the author's interpretation. They are not endorsed by ISO, NIST, CIS or",
        "  the European Union, and they are not legal advice.",
        "- A LYSS pass covers the configuration of switches only. It never satisfies a framework",
        "  requirement on its own: policies, people, processes and every other kind of system remain",
        "  in scope.",
        "- For NIS2, the obligations that apply to an entity come from the national law transposing the",
        "  Directive.",
        "",
    ]
    for key, title, show in FRAMEWORKS:
        refs: dict[str, list[dict]] = {}
        for c in controls:
            for ref in c.get("mappings", {}).get(key) or []:
                refs.setdefault(str(ref), []).append(c)
        out += [f"## {title}", ""]
        if key == "nis2_art21":
            out += ["Directive (EU) 2022/2555, Article 21(2): the measures shall include at least points",
                    "(a) to (j). Points without a LYSS control are outside what a switch configuration shows.", "",
                    "| Point | Measure | LYSS controls |", "|---|---|---|"]
            for point, label in NIS2_POINTS.items():
                linked = ", ".join(f"{c['id']} (L{c['level']})" for c in refs.get(point, [])) or "—"
                out.append(f"| {show(point)} | {label} | {linked} |")
        else:
            out += ["| Reference | LYSS controls |", "|---|---|"]
            for ref in sorted(refs, key=_natural):
                out.append(f"| {show(ref)} | " + ", ".join(f"{c['id']} (L{c['level']})" for c in refs[ref]) + " |")
        unmapped = [c["id"] for c in controls if not c.get("mappings", {}).get(key)]
        if unmapped:
            out += ["", "No direct reference: " + ", ".join(unmapped) + "."]
        out.append("")
    return "\n".join(out)


def main() -> int:
    documents = {OUT: build(), CROSSWALK: build_crosswalk()}
    if "--check" in sys.argv:
        stale = [p for p, content in documents.items()
                 if not p.exists() or p.read_text(encoding="utf-8") != content]
        for p in stale:
            print(f"{p.relative_to(ROOT).as_posix()} is out of date: run python tools/build_spec.py")
        if not stale:
            print("specification documents up to date")
        return 1 if stale else 0
    for path, content in documents.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"written {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
