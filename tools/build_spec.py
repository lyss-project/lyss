# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Generate docs/LYSS-Specification.md from spec/lyss-spec.yaml (the normative source).

    python tools/build_spec.py          write the document
    python tools/build_spec.py --check  exit 1 if the document is out of date (CI, tests)
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "lyss-spec.yaml"
OUT = ROOT / "docs" / "LYSS-Specification.md"
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
        "",
        "## 3. Verdicts",
        "",
        "- `pass`: the evidence shows that the control is met.",
        "- `fail`: the evidence shows that the control is not met.",
        "- `unknown`: the available evidence cannot decide. An assessment MUST report `unknown` rather than",
        "  guess, and MUST NOT turn a missing evidence into a pass.",
        "- `not_applicable`: the control does not apply to the platform (e.g. the feature does not exist).",
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
        "A device is **LYSS Level N conformant** when every control of levels 1 to N is `pass` or",
        "`not_applicable`. An `unknown` verdict is not a pass. A conformance claim MUST state the device,",
        "the specification version, the assessment date and the tool and version used, for example:",
        "",
        f"> core-sw-01 is LYSS Level 1 conformant (specification {spec['spec_version']}), assessed 2026-11-03 with LYSS 0.3.0.",
        "",
        "A claim is valid for the configuration and firmware assessed; any change requires a new assessment.",
        "",
        "## 5. Control catalogue",
        "",
        "| ID | Level | Title |",
        "|---|---|---|",
    ]
    for c in controls:
        out.append(f"| [{c['id']}](#{c['id'].lower()}) | {c['level']} | {c['title']} |")
    out.append("")
    for level, name in spec["levels"].items():
        out += [f"### Level {level}: {name}", ""]
        for c in (c for c in controls if c["level"] == level):
            m = c.get("mappings", {})
            out += [f"#### {c['id']}", "", f"**{c['title']}**", ""]
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
                    f" · CIS Controls v8 {mapping(m.get('cis_v8'))}", ""]
            if c["level"] == 3:
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
        "The specification follows semantic versioning:",
        "",
        "- **MAJOR**: a control is removed, or its requirement becomes stricter or changes meaning.",
        "- **MINOR**: controls are added, or a level gains controls.",
        "- **PATCH**: editorial changes, references, test procedure clarifications.",
        "",
        "Control identifiers are never reused. A withdrawn control keeps its identifier, marked withdrawn.",
        "While the version is below 1.0.0 the specification is a draft and MAY change without a MAJOR increment.",
        "",
        "## 9. References (informative)",
        "",
        "Mappings to ISO/IEC 27001:2022 Annex A, NIST SP 800-53 revision 5 and CIS Controls v8 are",
        "informative: they help reuse LYSS results as audit evidence and do not change the requirements.",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    content = build()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != content:
            print("docs/LYSS-Specification.md is out of date: run python tools/build_spec.py")
            return 1
        print("specification document up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(content, encoding="utf-8", newline="\n")
    print(f"written {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
