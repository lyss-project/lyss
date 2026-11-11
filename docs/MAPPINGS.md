<!-- Generated from spec/lyss-spec.yaml by tools/build_spec.py. Do not edit by hand. -->

# Crosswalk: frameworks to LYSS controls

Specification 0.8.0-draft. For each requirement of a framework, the LYSS controls
whose results can serve as **part** of the evidence for it.

**Informative only.**
- These mappings are the author's interpretation. They are not endorsed by ISO, NIST, CIS or
  the European Union, and they are not legal advice.
- A LYSS pass covers the configuration of switches only. It never satisfies a framework
  requirement on its own: policies, people, processes and every other kind of system remain
  in scope.
- For NIS2, the obligations that apply to an entity come from the national law transposing the
  Directive.

## NIS2 Directive, Article 21(2)

Directive (EU) 2022/2555, Article 21(2): the measures shall include at least points
(a) to (j). Points without a LYSS control are outside what a switch configuration shows.

| Point | Measure | LYSS controls |
|---|---|---|
| 21(2)(a) | Policies on risk analysis and information system security | — |
| 21(2)(b) | Incident handling | LYSS-LOG-010 (L2), LYSS-LOG-011 (L2) |
| 21(2)(c) | Business continuity, such as backup management and disaster recovery, and crisis management | LYSS-BKP-001 (L1) |
| 21(2)(d) | Supply chain security | — |
| 21(2)(e) | Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure | LYSS-VULN-001 (L1) |
| 21(2)(f) | Policies and procedures to assess the effectiveness of cybersecurity risk-management measures | — |
| 21(2)(g) | Basic cyber hygiene practices and cybersecurity training | LYSS-MGMT-001 (L1), LYSS-AUTH-001 (L1), LYSS-ACC-010 (L2), LYSS-ACC-011 (L2), LYSS-ACC-020 (L3), LYSS-ACC-021 (L3), LYSS-ACC-023 (L3), LYSS-ACC-024 (L3) |
| 21(2)(h) | Policies and procedures regarding the use of cryptography and, where appropriate, encryption | LYSS-MGMT-001 (L1), LYSS-MGMT-002 (L1), LYSS-MGMT-003 (L1), LYSS-AUTH-002 (L1), LYSS-AUTH-003 (L1), LYSS-AUTH-004 (L1), LYSS-AUTH-011 (L2), LYSS-MGMT-013 (L2) |
| 21(2)(i) | Human resources security, access control policies and asset management | LYSS-MGMT-004 (L1), LYSS-AUTH-001 (L1), LYSS-AUTH-002 (L1), LYSS-AUTH-003 (L1), LYSS-AUTH-010 (L2), LYSS-AUTH-011 (L2), LYSS-MGMT-010 (L2), LYSS-MGMT-011 (L2), LYSS-ACC-010 (L2), LYSS-ACC-022 (L3) |
| 21(2)(j) | Multi-factor or continuous authentication, secured voice, video and text communications and secured emergency communication systems | — |

No direct reference: LYSS-MGMT-012.

## ISO/IEC 27001:2022, Annex A

| Reference | LYSS controls |
|---|---|
| A.5.15 | LYSS-ACC-022 (L3) |
| A.5.16 | LYSS-AUTH-010 (L2) |
| A.5.17 | LYSS-AUTH-001 (L1), LYSS-AUTH-002 (L1), LYSS-AUTH-003 (L1), LYSS-AUTH-004 (L1) |
| A.8.5 | LYSS-MGMT-004 (L1), LYSS-AUTH-002 (L1), LYSS-AUTH-003 (L1), LYSS-AUTH-010 (L2), LYSS-MGMT-012 (L2) |
| A.8.6 | LYSS-ACC-023 (L3) |
| A.8.8 | LYSS-VULN-001 (L1) |
| A.8.9 | LYSS-BKP-001 (L1) |
| A.8.13 | LYSS-BKP-001 (L1) |
| A.8.15 | LYSS-LOG-010 (L2) |
| A.8.16 | LYSS-LOG-010 (L2) |
| A.8.17 | LYSS-LOG-011 (L2) |
| A.8.20 | LYSS-MGMT-001 (L1), LYSS-MGMT-010 (L2), LYSS-ACC-010 (L2), LYSS-ACC-011 (L2), LYSS-ACC-020 (L3), LYSS-ACC-021 (L3), LYSS-ACC-022 (L3), LYSS-ACC-023 (L3), LYSS-ACC-024 (L3) |
| A.8.21 | LYSS-MGMT-001 (L1), LYSS-MGMT-002 (L1), LYSS-MGMT-003 (L1), LYSS-AUTH-001 (L1), LYSS-AUTH-011 (L2), LYSS-MGMT-013 (L2) |
| A.8.22 | LYSS-MGMT-010 (L2), LYSS-MGMT-011 (L2), LYSS-ACC-020 (L3), LYSS-ACC-021 (L3) |
| A.8.24 | LYSS-MGMT-001 (L1), LYSS-MGMT-002 (L1), LYSS-MGMT-003 (L1), LYSS-AUTH-004 (L1), LYSS-AUTH-011 (L2), LYSS-MGMT-013 (L2) |

## NIST SP 800-53 revision 5

| Reference | LYSS controls |
|---|---|
| AC-2 | LYSS-AUTH-010 (L2) |
| AC-3 | LYSS-ACC-022 (L3) |
| AC-4 | LYSS-MGMT-011 (L2) |
| AC-8 | LYSS-MGMT-012 (L2) |
| AC-12 | LYSS-MGMT-004 (L1) |
| AC-17 | LYSS-MGMT-010 (L2) |
| AC-17(2) | LYSS-MGMT-001 (L1), LYSS-MGMT-002 (L1), LYSS-MGMT-003 (L1) |
| AU-4(1) | LYSS-LOG-010 (L2) |
| AU-6 | LYSS-LOG-010 (L2) |
| AU-8 | LYSS-LOG-011 (L2) |
| CM-2(3) | LYSS-BKP-001 (L1) |
| CM-6 | LYSS-AUTH-001 (L1), LYSS-ACC-011 (L2) |
| CM-7 | LYSS-MGMT-001 (L1), LYSS-MGMT-003 (L1), LYSS-ACC-010 (L2), LYSS-ACC-024 (L3) |
| CP-9 | LYSS-BKP-001 (L1) |
| IA-2 | LYSS-AUTH-010 (L2) |
| IA-3 | LYSS-ACC-022 (L3) |
| IA-5 | LYSS-AUTH-001 (L1), LYSS-AUTH-004 (L1), LYSS-AUTH-011 (L2) |
| IA-5(1) | LYSS-AUTH-002 (L1), LYSS-AUTH-003 (L1) |
| RA-5 | LYSS-VULN-001 (L1) |
| SA-22 | LYSS-VULN-001 (L1) |
| SC-5 | LYSS-ACC-011 (L2), LYSS-ACC-023 (L3) |
| SC-7 | LYSS-MGMT-010 (L2), LYSS-MGMT-011 (L2), LYSS-ACC-020 (L3), LYSS-ACC-021 (L3) |
| SC-8 | LYSS-MGMT-001 (L1), LYSS-MGMT-002 (L1), LYSS-MGMT-003 (L1), LYSS-AUTH-011 (L2), LYSS-MGMT-013 (L2) |
| SC-10 | LYSS-MGMT-004 (L1) |
| SC-13 | LYSS-MGMT-002 (L1), LYSS-AUTH-011 (L2), LYSS-MGMT-013 (L2) |
| SC-28 | LYSS-AUTH-004 (L1) |
| SC-45 | LYSS-LOG-011 (L2) |
| SI-2 | LYSS-VULN-001 (L1) |
| SI-4 | LYSS-ACC-020 (L3), LYSS-ACC-021 (L3) |

## CIS Controls v8 (safeguards)

| Reference | LYSS controls |
|---|---|
| 2.2 | LYSS-VULN-001 (L1) |
| 3.10 | LYSS-MGMT-013 (L2) |
| 3.11 | LYSS-AUTH-002 (L1), LYSS-AUTH-003 (L1), LYSS-AUTH-004 (L1) |
| 4.3 | LYSS-MGMT-004 (L1) |
| 4.7 | LYSS-AUTH-001 (L1) |
| 4.8 | LYSS-MGMT-001 (L1), LYSS-MGMT-003 (L1), LYSS-ACC-024 (L3) |
| 8.2 | LYSS-LOG-010 (L2) |
| 8.4 | LYSS-LOG-011 (L2) |
| 8.9 | LYSS-LOG-010 (L2) |
| 11.2 | LYSS-BKP-001 (L1) |
| 12.1 | LYSS-VULN-001 (L1) |
| 12.2 | LYSS-MGMT-011 (L2), LYSS-ACC-011 (L2) |
| 12.3 | LYSS-MGMT-010 (L2), LYSS-ACC-010 (L2) |
| 12.5 | LYSS-AUTH-010 (L2) |
| 12.6 | LYSS-MGMT-001 (L1), LYSS-MGMT-002 (L1), LYSS-MGMT-003 (L1), LYSS-AUTH-011 (L2), LYSS-MGMT-013 (L2) |
| 13.9 | LYSS-ACC-022 (L3) |

No direct reference: LYSS-MGMT-012, LYSS-ACC-020, LYSS-ACC-021, LYSS-ACC-023.
