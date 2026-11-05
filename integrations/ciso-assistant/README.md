# LYSS in CISO Assistant

These files package the LYSS specification as libraries for
[CISO Assistant](https://github.com/intuitem/ciso-assistant-community) (intuitem, open-source GRC),
so switch-security audits can be run and tracked next to ISO/IEC 27001:2022.

| File | Content |
|---|---|
| `lyss-<spec_version>.yaml` | Framework **LYSS — Lyaazale Switch Security**: one requirement per control, grouped by level (L1 Baseline, L2 Hardened, L3 Advanced) and domain. Statement in the description; rationale, test procedure, parameters and informative references (ISO 27001, NIST SP 800-53, CIS v8) in the annotation; expected evidence in *typical evidence*. Levels are also implementation groups (cumulative), so an audit can be limited to Level 1 or Level 2. Level 3 controls are drafts. |
| `mapping-lyss-and-iso27001-2022-<spec_version>.yaml` | Requirement mapping set LYSS → ISO/IEC 27001:2022 Annex A (each LYSS control is a `subset` of the ISO control it is mapped to). One direction only, on purpose: an ISO control judged compliant proves nothing about a given switch, so it must never mark LYSS controls compliant. |

Both are generated from `spec/lyss-spec.yaml`; do not edit them by hand.

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

Library URNs carry no version (`urn:lyss:risk:library:lyss`). The library `version` is derived from
`spec_version` (0.4.0-draft → 40000, 0.4.0 → 40001, 0.4.1-draft → 40010), so a newer specification
is offered as an update of the loaded library. Two builds of the same `spec_version` have the same
version: bump `spec_version` before re-importing.

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
