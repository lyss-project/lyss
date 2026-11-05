# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Generate the CISO Assistant libraries of the LYSS specification from spec/lyss-spec.yaml.

CISO Assistant (intuitem, https://github.com/intuitem/ciso-assistant-community) imports YAML
libraries. Upstream keeps frameworks and requirement mapping sets in separate library files
(mapping-<a>-and-<b>.yaml), so two files are written to integrations/ciso-assistant/:

    lyss-<spec_version>.yaml                              the LYSS framework
    mapping-lyss-and-iso27001-2022-<spec_version>.yaml    LYSS <-> ISO/IEC 27001:2022 Annex A

    python tools/build_ciso_library.py                   write both files
    python tools/build_ciso_library.py --check           exit 1 if they are missing or out of date
    python tools/build_ciso_library.py --out-dir DIR     write elsewhere (tests)
    python tools/build_ciso_library.py --date 2026-11-05 set the publication date (default: today)

The structure follows what upstream's tools/convert_library_v2.py emits (key names and order,
URN rules), with one deliberate difference: the mapping goes LYSS -> ISO only (no "-revert" set).
See integrations/ciso-assistant/README.md.
"""

import argparse
import datetime
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "lyss-spec.yaml"
OUT_DIR = ROOT / "integrations" / "ciso-assistant"

# --- Identity ----------------------------------------------------------------------------
# URNs carry no version (upstream advice), so a newer library version updates the loaded one.
PACKAGER_URN = "lyss"  # "intuitem" is reserved upstream; third parties use their own value
LIBRARY_URN = f"urn:{PACKAGER_URN}:risk:library:lyss"
FRAMEWORK_URN = f"urn:{PACKAGER_URN}:risk:framework:lyss"
NODE_BASE = f"urn:{PACKAGER_URN}:risk:req_node:lyss"
MAPPING_REF = "mapping-lyss-and-iso27001-2022"
MAPPING_LIBRARY_URN = f"urn:{PACKAGER_URN}:risk:library:{MAPPING_REF}"
MAPPING_SET_URN = f"urn:{PACKAGER_URN}:risk:req_mapping_set:{MAPPING_REF}"

NAME = "LYSS — Lyaazale Switch Security"
PROVIDER = "Mouad Lyaazale"
PACKAGER = "LYSS project"
COPYRIGHT = "LYSS specification © 2026 Mouad Lyaazale, CC BY 4.0"
LOCALE = "en"

# --- ISO/IEC 27001:2022 as packaged upstream (backend/library/libraries/iso27001-2022.yaml) ---
ISO_LIBRARY_URN = "urn:intuitem:risk:library:iso27001-2022"
ISO_FRAMEWORK_URN = "urn:intuitem:risk:framework:iso27001-2022"
ISO_NODE_BASE = "urn:intuitem:risk:req_node:iso27001-2022"
# Annex A: number of controls per theme (5 organizational, 6 people, 7 physical, 8 technological).
ANNEX_A = {5: 37, 6: 8, 7: 14, 8: 34}
ANNEX_A_REF = re.compile(r"^A\.(\d+)\.(\d+)$")
# A LYSS control is one specific, testable part of the broader ISO control it is mapped to.
RELATIONSHIP = "subset"

# --- Checks shared with tests/test_ciso_library.py (mirror the CISO Assistant v4.1 loader) ---
URN_REGEX = re.compile(  # backend/core/models.py URN_REGEX
    r"^urn:([a-zA-Z0-9_-]+):([a-zA-Z0-9_-]+):([a-zA-Z0-9_-]+)(?::([a-zA-Z0-9_-]+))?:([0-9A-Za-z\[\]\(\)\-\._:]+)$")
NAME_MAX_LENGTH = 200  # convert_library_v2.py NAME_MAX_LENGTH
RELATIONSHIPS = {"equal", "subset", "superset", "intersect", "not_related"}

EVIDENCE_TEXT = {
    "config": "Running configuration of the switch",
    "state": "Read-only device state (listening services, SSH identification and algorithms, port status)",
    "external_data": "Vendor security advisories, end-of-life bulletins and CISA KEV entries for the model and firmware",
    "backup_system": "Records of the configuration backup system, or an administrator attestation of it",
}


def library_version(spec_version: str) -> int:
    """CISO Assistant library versions are integers and must grow for an update to be offered.
    MAJOR.MINOR.PATCH[-pre] -> ((MAJOR*1000 + MINOR)*1000 + PATCH)*10, +1 for a final release,
    so 0.4.0-draft = 40000 < 0.4.0 = 40001 < 0.4.1-draft = 40010."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.]+)?$", spec_version)
    if not m:
        raise ValueError(f"spec_version {spec_version!r} is not MAJOR.MINOR.PATCH[-pre]")
    major, minor, patch = (int(x) for x in m.groups()[:3])
    return ((major * 1000 + minor) * 1000 + patch) * 10 + (0 if m.group(4) else 1)


def urn_suffix(ref_id: str) -> str:
    """URN suffix from a ref_id, as convert_library_v2.py clean_urn_suffix() (default mode)."""
    return re.sub(r"[^a-z0-9_\-\.\[\]\(\):]", "_", ref_id.lower().replace(" ", "-"))


def node_urn(ref_id: str) -> str:
    return f"{NODE_BASE}:{urn_suffix(ref_id)}"


def iso_node_urn(ref: str) -> str:
    m = ANNEX_A_REF.match(ref)
    if not m or int(m.group(1)) not in ANNEX_A or not 1 <= int(m.group(2)) <= ANNEX_A[int(m.group(1))]:
        raise ValueError(f"{ref!r} is not an ISO/IEC 27001:2022 Annex A control")
    return f"{ISO_NODE_BASE}:{urn_suffix(ref)}"


def is_draft(control: dict) -> bool:
    return not control.get("statement")


def level_groups(level: int, levels) -> list[str]:
    """Levels are cumulative: a level-1 control is part of the Level 1, 2 and 3 audits."""
    return [f"L{n}" for n in sorted(levels) if n >= level]


def annotation(control: dict, spec_version: str) -> str:
    parts = []
    if is_draft(control):
        parts.append(f"Draft control (LYSS specification {spec_version}): requirement text, rationale "
                     "and test procedure are not written yet.")
    if control.get("rationale"):
        parts.append(f"Rationale: {control['rationale']}")
    if control.get("test_procedure"):
        parts.append(f"Test procedure: {control['test_procedure']}")
    if control.get("parameters"):
        parts.append("Parameters: " + ", ".join(f"{k} = {v}" for k, v in control["parameters"].items()))
    m = control.get("mappings", {})
    refs = [(label, m.get(key)) for key, label in (("iso27001_2022", "ISO/IEC 27001:2022"),
                                                  ("nist_800_53r5", "NIST SP 800-53 r5"),
                                                  ("cis_v8", "CIS Controls v8"))]
    refs = [f"{label} {', '.join(str(v) for v in values)}" for label, values in refs if values]
    if refs:
        parts.append("Informative references: " + "; ".join(refs) + ".")
    return "\n\n".join(parts)


def typical_evidence(control: dict) -> str:
    lines = [f"- {EVIDENCE_TEXT.get(e, e)}" for e in control.get("evidence", [])]
    lines.append(f"- LYSS assessment report showing the verdict and evidence for {control['id']}")
    return "\n".join(lines)


DRAFT_NOTE = "DRAFT: controls, identifiers and mappings may still change before LYSS 1.0. "


def spec_is_draft(spec: dict) -> bool:
    return "draft" in str(spec.get("spec_version", "")) or spec.get("status", "draft") == "draft"


def display_name(spec: dict) -> str:
    """Library / framework name; drafts say so in the name, visible in every list of the UI."""
    number = str(spec["spec_version"]).split("-")[0]
    return f"{NAME} (draft {number})" if spec_is_draft(spec) else f"{NAME} {number}"


def library_header(ref_id: str, name: str, description: str, version: int, date) -> dict:
    # Key order of convert_library_v2.py (without its own convert_library_version marker).
    return {
        "urn": None, "locale": LOCALE, "ref_id": ref_id, "name": name, "description": description,
        "copyright": COPYRIGHT, "version": version, "publication_date": date,
        "provider": PROVIDER, "packager": PACKAGER,
    }


def build_framework_library(spec: dict, date) -> dict:
    version = spec["spec_version"]
    levels = {int(k): v for k, v in spec["levels"].items()}
    domains = spec["domains"]
    controls = spec["controls"]
    description = (
        f"LYSS (Lyaazale Switch Security) specification {version} ({spec.get('status', 'draft')}): "
        "vendor-neutral security controls for managed network switches, in three cumulative "
        "conformance levels (" + ", ".join(f"{n} {levels[n]}" for n in sorted(levels)) + "). "
        "Each requirement is one control (LYSS-<DOMAIN>-<NNN>); its annotation gives the rationale, "
        "vendor-neutral test procedure and informative references. A device is LYSS Level N "
        "conformant when every control of levels 1 to N is met or not applicable. "
        + (DRAFT_NOTE if spec_is_draft(spec) else "")
        + "Author: Mouad Lyaazale. Generated from spec/lyss-spec.yaml by tools/build_ciso_library.py."
    )
    lib = library_header("LYSS", display_name(spec), description, library_version(version), date)
    lib["urn"] = LIBRARY_URN

    nodes = []
    for level in sorted(levels):
        in_level = [c for c in controls if int(c["level"]) == level]
        if not in_level:
            continue
        groups = level_groups(level, levels)
        level_ref = f"L{level}"
        nodes.append({
            "urn": node_urn(level_ref), "assessable": False, "depth": 1,
            "ref_id": level_ref, "name": f"Level {level} - {levels[level]}",
            "implementation_groups": groups,
        })
        for domain, domain_name in domains.items():
            in_domain = [c for c in in_level if c["id"].split("-")[1] == domain]
            if not in_domain:
                continue
            domain_ref = f"{level_ref}.{domain}"
            nodes.append({
                "urn": node_urn(domain_ref), "assessable": False, "depth": 2,
                "parent_urn": node_urn(level_ref), "ref_id": domain_ref, "name": domain_name,
                "implementation_groups": groups,
            })
            for c in in_domain:
                node = {
                    # a control whose text is not written yet cannot be met: not assessable
                    "urn": node_urn(c["id"]), "assessable": not is_draft(c), "depth": 3,
                    "parent_urn": node_urn(domain_ref), "ref_id": c["id"], "name": c["title"],
                }
                if c.get("statement"):
                    node["description"] = " ".join(str(c["statement"]).split())
                node["annotation"] = annotation(c, version)
                node["typical_evidence"] = typical_evidence(c)
                node["implementation_groups"] = groups
                nodes.append(node)

    lib["objects"] = {"framework": {
        "urn": FRAMEWORK_URN,
        "ref_id": "LYSS",
        "name": display_name(spec),
        "description": description,
        "implementation_groups_definition": [
            {"ref_id": f"L{n}", "name": f"Level {n} - {levels[n]}",
             "description": f"Controls required for LYSS Level {n} conformance "
                            + ("(Level 1 controls)." if n == 1 else f"(levels 1 to {n}).")}
            for n in sorted(levels)
        ],
        "requirement_nodes": nodes,
    }}
    return lib


def build_mapping_library(spec: dict, date) -> dict:
    version = spec["spec_version"]
    description = (
        f"Mapping between LYSS (Lyaazale Switch Security) specification {version} and ISO/IEC "
        "27001:2022 Annex A, from the informative references of the specification. Each LYSS control "
        "is a specific, testable part (subset) of the ISO control it maps to: a compliant LYSS "
        "requirement gives at most partial coverage of the ISO control, a non-compliant one makes it "
        "non-compliant. One direction only: an ISO control judged compliant proves nothing about a "
        "given switch. " + (DRAFT_NOTE if spec_is_draft(spec) else "")
        + "Generated from spec/lyss-spec.yaml by tools/build_ciso_library.py."
    )
    name = f"{display_name(spec).replace(NAME, 'LYSS')} -> ISO/IEC 27001:2022"
    lib = library_header(MAPPING_REF, name, description, library_version(version), date)
    lib["urn"] = MAPPING_LIBRARY_URN
    lib["dependencies"] = [LIBRARY_URN, ISO_LIBRARY_URN]

    # one direction only, LYSS -> ISO: a LYSS audit can prefill an ISO 27001 audit (partial coverage).
    # No ISO -> LYSS set: an ISO control judged compliant proves nothing about a given switch.
    forward = []
    for c in spec["controls"]:
        if is_draft(c):
            continue  # not assessable yet: nothing to infer from it
        for ref in c.get("mappings", {}).get("iso27001_2022", []) or []:
            forward.append({"source_requirement_urn": node_urn(c["id"]),
                            "target_requirement_urn": iso_node_urn(str(ref)), "relationship": RELATIONSHIP})
    lib["objects"] = {"requirement_mapping_sets": [
        {"urn": MAPPING_SET_URN, "ref_id": MAPPING_REF, "name": name, "description": description,
         "source_framework_urn": FRAMEWORK_URN, "target_framework_urn": ISO_FRAMEWORK_URN,
         "requirement_mappings": forward},
    ]}
    return lib


# --- Validation ----------------------------------------------------------------------------

def validate(framework_lib: dict, mapping_lib: dict) -> list[str]:
    """Structural checks of what the CISO Assistant loader and converter enforce, plus
    consistency between the two files. Returns a list of errors (empty when valid)."""
    errors = []
    for lib in (framework_lib, mapping_lib):
        where = lib.get("urn", "?")
        for key in ("urn", "locale", "ref_id", "name", "description", "copyright", "version",
                    "publication_date", "provider", "packager", "objects"):
            if lib.get(key) in (None, ""):
                errors.append(f"{where}: missing library field {key}")
        if not isinstance(lib.get("version"), int):
            errors.append(f"{where}: version must be an integer")

    def check_urn(urn, where):
        if not isinstance(urn, str) or not URN_REGEX.match(urn):
            errors.append(f"{where}: badly formatted URN {urn!r}")
        elif urn != urn.lower():
            errors.append(f"{where}: URN not lowercase {urn!r}")

    for lib in (framework_lib, mapping_lib):
        check_urn(lib.get("urn"), "library")

    fw = framework_lib.get("objects", {}).get("framework", {})
    for key in ("urn", "ref_id", "name", "description", "requirement_nodes"):
        if not fw.get(key):
            errors.append(f"framework: missing {key}")
    check_urn(fw.get("urn"), "framework")
    groups = {g["ref_id"] for g in fw.get("implementation_groups_definition", [])}
    seen = {}
    for node in fw.get("requirement_nodes", []):
        urn = node.get("urn")
        where = f"node {node.get('ref_id', urn)}"
        check_urn(urn, where)
        if urn in seen:
            errors.append(f"{where}: duplicate URN {urn}")
        if not isinstance(node.get("assessable"), bool):
            errors.append(f"{where}: assessable must be a boolean")
        if len(node.get("name") or "") > NAME_MAX_LENGTH:
            errors.append(f"{where}: name longer than {NAME_MAX_LENGTH} characters")
        parent = node.get("parent_urn")
        if parent is None:
            if node.get("depth") != 1:
                errors.append(f"{where}: no parent but depth {node.get('depth')}")
        elif parent not in seen:
            errors.append(f"{where}: parent {parent} missing or listed after the node")
        elif node.get("depth") != seen[parent]["depth"] + 1:
            errors.append(f"{where}: depth {node.get('depth')} under a depth {seen[parent]['depth']} parent")
        unknown = set(node.get("implementation_groups", [])) - groups
        if unknown:
            errors.append(f"{where}: unknown implementation groups {sorted(unknown)}")
        seen[urn] = node

    sets = mapping_lib.get("objects", {}).get("requirement_mapping_sets", [])
    if not sets:
        errors.append("mapping library: no requirement_mapping_sets")
    iso_targets = set()
    for rms in sets:
        where = f"mapping set {rms.get('urn')}"
        check_urn(rms.get("urn"), where)
        for key in ("urn", "ref_id", "name", "source_framework_urn", "target_framework_urn"):
            if not rms.get(key):
                errors.append(f"{where}: missing {key}")
        if not rms.get("requirement_mappings"):
            errors.append(f"{where}: no requirement_mappings")
        if {rms.get("source_framework_urn"), rms.get("target_framework_urn")} != {FRAMEWORK_URN, ISO_FRAMEWORK_URN}:
            errors.append(f"{where}: must map {FRAMEWORK_URN} and {ISO_FRAMEWORK_URN}")
        lyss_side = "source" if rms.get("source_framework_urn") == FRAMEWORK_URN else "target"
        iso_side = "target" if lyss_side == "source" else "source"
        for m in rms.get("requirement_mappings", []):
            if m.get("relationship") not in RELATIONSHIPS:
                errors.append(f"{where}: invalid relationship {m.get('relationship')!r}")
            lyss_urn, iso_urn = m.get(f"{lyss_side}_requirement_urn"), m.get(f"{iso_side}_requirement_urn")
            check_urn(lyss_urn, where)
            check_urn(iso_urn, where)
            if lyss_urn not in seen or not seen[lyss_urn].get("assessable"):
                errors.append(f"{where}: {lyss_urn} is not an assessable LYSS requirement")
            iso_targets.add(iso_urn)
    for iso_urn in iso_targets:
        ref = iso_urn.rsplit(":", 1)[-1].upper() if isinstance(iso_urn, str) else ""
        try:
            if iso_node_urn(ref) != iso_urn:
                raise ValueError
        except ValueError:
            errors.append(f"mapping: {iso_urn} is not an ISO/IEC 27001:2022 Annex A requirement node")
    return errors


# --- Output --------------------------------------------------------------------------------

def file_names(spec_version: str) -> tuple[str, str]:
    return f"lyss-{spec_version}.yaml", f"{MAPPING_REF}-{spec_version}.yaml"


class _NoAliasDumper(yaml.SafeDumper):
    """Upstream libraries never use YAML anchors/aliases: write repeated values in full."""

    def ignore_aliases(self, data):
        return True


def dump(lib: dict) -> str:
    # Same settings as upstream convert_library_v2.py (sort_keys=False, allow_unicode=False).
    return yaml.dump(lib, Dumper=_NoAliasDumper, sort_keys=False, allow_unicode=False)


# --- Excel v2 workbooks (upstream's editable source format) ---------------------------------
# Upstream keeps libraries as Excel "v2" workbooks (tools/excel/) and generates the YAML with
# tools/convert_library_v2.py. These workbooks carry the same content as the YAML above, for a
# contribution upstream. Note: upstream's converter always adds a reverse ("-revert") mapping set.

def _sheet(wb, title: str, rows: list[list]) -> None:
    ws = wb.create_sheet(title)
    for row in rows:
        ws.append(["" if v is None else v for v in row])


def _meta_rows(lib: dict, keys: list[str]) -> list[list]:
    return [[k, lib[k]] for k in keys if lib.get(k) not in (None, "", [])]


def excel_workbooks(spec: dict, framework_lib: dict, mapping_lib: dict) -> dict:
    """{file name: openpyxl Workbook} for the framework and the mapping libraries."""
    from openpyxl import Workbook  # optional dependency, only for --excel

    lib_keys = ["urn", "version", "locale", "ref_id", "name", "description", "copyright", "provider", "packager"]
    fw = framework_lib["objects"]["framework"]
    wb_fw = Workbook()
    wb_fw.remove(wb_fw.active)
    _sheet(wb_fw, "library_meta", [["type", "library"]] + _meta_rows(framework_lib, lib_keys))
    _sheet(wb_fw, "fwk_meta", [["type", "framework"], ["base_urn", NODE_BASE], ["urn", fw["urn"]],
                               ["ref_id", fw["ref_id"]], ["name", fw["name"]], ["description", fw["description"]],
                               ["implementation_groups_definition", "imp_grp"]])
    columns = ["assessable", "depth", "ref_id", "name", "description", "annotation", "typical_evidence",
               "implementation_groups"]
    rows = [columns]
    for n in fw["requirement_nodes"]:
        rows.append(["x" if n["assessable"] else "", n["depth"], n["ref_id"], n.get("name"), n.get("description"),
                     n.get("annotation"), n.get("typical_evidence"), ",".join(n.get("implementation_groups", []))])
    _sheet(wb_fw, "fwk_content", rows)
    _sheet(wb_fw, "imp_grp_meta", [["type", "implementation_groups"], ["name", "imp_grp"]])
    _sheet(wb_fw, "imp_grp_content", [["ref_id", "name", "description"]]
           + [[g["ref_id"], g["name"], g.get("description")] for g in fw["implementation_groups_definition"]])

    ms = mapping_lib["objects"]["requirement_mapping_sets"][0]
    wb_map = Workbook()
    wb_map.remove(wb_map.active)
    _sheet(wb_map, "library_meta", [["type", "library"]] + _meta_rows(mapping_lib, lib_keys)
           + [["dependencies", ", ".join(mapping_lib["dependencies"])]])
    _sheet(wb_map, "mappings_meta", [["type", "requirement_mapping_set"], ["urn", ms["urn"]], ["ref_id", ms["ref_id"]],
                                     ["name", ms["name"]], ["description", ms["description"]],
                                     ["source_framework_urn", ms["source_framework_urn"]],
                                     ["target_framework_urn", ms["target_framework_urn"]],
                                     ["source_node_base_urn", NODE_BASE], ["target_node_base_urn", ISO_NODE_BASE]])
    _sheet(wb_map, "mappings_content", [["source_node_id", "target_node_id", "relationship"]]
           + [[m["source_requirement_urn"].split(NODE_BASE + ":")[1],
               m["target_requirement_urn"].split(ISO_NODE_BASE + ":")[1], m["relationship"]]
              for m in ms["requirement_mappings"]])
    names = file_names(spec["spec_version"])
    return {names[0].replace(".yaml", ".xlsx"): wb_fw, names[1].replace(".yaml", ".xlsx"): wb_map}


def build(date) -> tuple[dict, dict, dict]:
    spec = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    return spec, build_framework_library(spec, date), build_mapping_library(spec, date)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the files are missing or out of date")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR, help="output folder")
    parser.add_argument("--date", type=datetime.date.fromisoformat, default=datetime.date.today(),
                        help="publication date YYYY-MM-DD (default: today)")
    parser.add_argument("--excel", type=Path, metavar="DIR",
                        help="also write the Excel v2 workbooks (upstream source format) to DIR (needs openpyxl)")
    args = parser.parse_args(argv)

    spec, framework_lib, mapping_lib = build(args.date)
    if errors := validate(framework_lib, mapping_lib):
        print("invalid CISO Assistant library:\n  " + "\n  ".join(errors))
        return 1
    outputs = list(zip(file_names(spec["spec_version"]), (framework_lib, mapping_lib)))

    if args.check:
        stale = []
        for name, lib in outputs:
            path = args.out_dir / name
            if not path.exists():
                stale.append(name)
                continue
            current = yaml.safe_load(path.read_text(encoding="utf-8"))
            # The publication date is the only field allowed to differ.
            expected = dict(lib, publication_date=current.get("publication_date"))
            if dump(current) != dump(expected):
                stale.append(name)
        if stale:
            print("CISO Assistant library out of date (" + ", ".join(stale) + "): "
                  "run python tools/build_ciso_library.py")
            return 1
        print("CISO Assistant library up to date")
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, lib in outputs:
        path = args.out_dir / name
        path.write_text(dump(lib), encoding="utf-8", newline="\n")
        print(f"written {path}")
    if args.excel:
        args.excel.mkdir(parents=True, exist_ok=True)
        for name, wb in excel_workbooks(spec, framework_lib, mapping_lib).items():
            wb.save(args.excel / name)
            print(f"written {args.excel / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
