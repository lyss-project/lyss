# LYSS in CISO Assistant

These files package the LYSS specification as libraries for
[CISO Assistant](https://github.com/intuitem/ciso-assistant-community) (intuitem, open-source GRC),
so switch-security audits can be run and tracked next to ISO/IEC 27001:2022.

| File | Content |
|---|---|
| `lyss-<spec_version>.yaml` | Framework **LYSS — Lyaazale Switch Security**: one requirement per control, grouped by level (L1 Baseline, L2 Hardened, L3 Advanced) and domain. Statement in the description; rationale, test procedure, parameters and informative references (ISO 27001, NIST SP 800-53, CIS v8) in the annotation; expected evidence in *typical evidence*. Levels are also implementation groups (cumulative), so an audit can be limited to Level 1 or Level 2, or include Level 3 (Advanced, access-layer protection). |
| `mapping-lyss-and-iso27001-2022-<spec_version>.yaml` | Requirement mapping set LYSS → ISO/IEC 27001:2022 Annex A (each LYSS control is a `subset` of the ISO control it is mapped to). One direction only, on purpose: an ISO control judged compliant proves nothing about a given switch, so it must never mark LYSS controls compliant. |

Both are generated from `spec/lyss-spec.yaml`; do not edit them by hand.

**Included in CISO Assistant:** the LYSS framework and its ISO/IEC 27001:2022 mapping (library
version 1, specification 0.7.0-draft) were merged into CISO Assistant on 2026-11-09
([intuitem/ciso-assistant-community#5246](https://github.com/intuitem/ciso-assistant-community/pull/5246)).
From CISO Assistant v4.2.3, load them from the built-in libraries store
(search "LYSS"); the manual import below is only needed for older versions or newer LYSS versions.
The files in this folder are library version 5 (specification 1.0.0-rc.1, the 1.0 release
candidate; same requirements as version 4), an update of the merged version 1; CISO Assistant
itself still ships version 1.

## Import into CISO Assistant (v4.x)

1. **Governance > Libraries** (sidebar of v4.1; the upstream docs say *Catalog > Libraries*), click
   the upload button (file icon with a "+", top right) and upload `lyss-<spec_version>.yaml`. Load it
   from the libraries store if it is not loaded automatically. The framework then appears under
   **Catalog > Frameworks**.
2. The ISO/IEC 27001:2022 library must be loaded (it is a dependency of the mapping).
3. Upload `mapping-lyss-and-iso27001-2022-<spec_version>.yaml` the same way. It then appears under
   **Catalog > Mappings** and can be used to create an ISO 27001 audit from a LYSS audit.
   Because the relationship is `subset`, a compliant LYSS requirement gives at most partial
   coverage of the ISO control.

Library URNs carry no version (`urn:lyss:risk:library:lyss`). The library `version` is a plain
counter, as in the other CISO Assistant libraries: 1 for specification 0.7.0-draft, then +1 for each
specification that changes the library (table `LIBRARY_VERSIONS` in tools/build_ciso_library.py), so
a newer specification is offered as an update of the loaded library. Two builds of the same
`spec_version` have the same version: bump `spec_version` before re-importing.

## What CISO Assistant does with the mapping

Tested on a clean CISO Assistant 4.1.1 with the fictitious LYSS demo lab: a LYSS audit (Level 2)
answered from LYSS results, then an ISO/IEC 27001:2022 audit created with the LYSS audit as baseline.

- CISO Assistant treats `subset` (and `intersect`) the same way: a compliant LYSS requirement makes
  the mapped ISO control at most **partially compliant**; non-compliant ones make it
  **non-compliant** when none of the LYSS requirements mapped to it is compliant. In 4.1.1 the most
  restrictive result won when several LYSS requirements map to one ISO control; the current mapping
  engine (November 2026) gives **partially compliant** when some are compliant and some are not.
  This comes from CISO Assistant's mapping engine, not from the library.
- Evidence attached to LYSS requirements is carried over to the ISO controls, and every ISO result
  links to the LYSS requirements it was inferred from. Observations are not copied.
- On the demo lab (CISO Assistant 4.1.1, specification 0.6.0-draft), 12 ISO controls were
  prefilled (A.5.10, A.5.16, A.5.17, A.8.5, A.8.8, A.8.15, A.8.16, A.8.17, A.8.20, A.8.21, A.8.22,
  A.8.24). Since specification 0.6.1-draft nothing maps to A.5.10 any more.

## Updating the library upstream

The library in CISO Assistant is the YAML file (its source of truth). For an update, open a pull
request with the two regenerated YAML files, converted with upstream's own tools:
`python tools/build_ciso_library.py --excel DIR` writes the Excel "v2" workbooks (needs
`openpyxl`); upstream's `check_library_v2.py` accepts them, and `convert_library_v2.py` produces
the same content as the YAML files here (37 nodes, 43 mappings) plus a reverse mapping set
(ISO → LYSS, `superset`) that must be removed, because the mapping is one-way on purpose (see
above). Do not add the workbooks to the pull request. Every update needs the next
`LIBRARY_VERSIONS` number, and control identifiers must never disappear
(`tests/data/ciso_published.yaml`). Upstream asks contributors to sign its CLA.

## Regenerate

```
python tools/build_ciso_library.py           # write both files
python tools/build_ciso_library.py --check   # exit 1 if they are out of date (run by the tests)
```

## Licence and author

The LYSS specification and these libraries are licensed under
[CC BY 4.0](../../LICENSE-SPEC). Author: Mouad Lyaazale. The generator script is AGPL-3.0-only
(see `NOTICE`). ISO/IEC 27001 is referenced by control number only; CISO Assistant is a
trademark of intuitem.
