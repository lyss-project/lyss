# Versioning policy

LYSS has two things with versions: the **specification** (`spec_version`, the controls and their
test procedures) and the **tool** (the `lyss` package: engine, adapters, collector, web interface).
Until 1.0 they are released together.

This page describes the maintainer's intentions, on a best-effort basis. It is not a commitment,
a support agreement or a schedule: LYSS is provided without warranty (see [LICENSE](../LICENSE)).

## Before 1.0 (now)

- **The specification is a draft** (`0.x.y-draft`). Controls can still be added, reworded,
  re-levelled or removed, and a verdict can change between versions when a test procedure becomes
  stricter. Every change is listed in [CHANGELOG.md](../CHANGELOG.md), with the reason.
- **Control IDs are never reused, renamed or renumbered.** A new control gets a new ID. If a control
  is removed, its ID (`LYSS-MGMT-001`, …) stays retired and the control is marked withdrawn, so an
  old report never means something different, and tools that store answers per control (such as
  CISO Assistant audits) keep them.
- **Every result records the specification version** it was assessed against (`spec_version`
  in each switch result, in exported reports and in JSON output). A conformance level is only
  meaningful together with that version: "Level 2 against 0.8.0-draft".
- **Pin a version** for a stable baseline: `pip install "lyss==0.19.0"`. Upgrade on purpose,
  read the changelog, then rescan. The history keeps the previous results for comparison.

## Planned from 1.0

- **Semantic versioning for the specification:**
  - MAJOR: a control withdrawn (its ID stays, marked withdrawn), made stricter in a way that can
    turn a pass into a fail, or moved to another level, or an advisory control made normal;
  - MINOR: an advisory control added to an existing level, a new level above the existing ones
    (with its own normal controls), or a wording that does not change any verdict;
  - PATCH: typos and references.
- **Advisory controls:** a control added within a MAJOR version is advisory. LYSS assesses and
  reports it like any control, but it does not count for conformance or for a CI gate until the
  next MAJOR version, where it becomes a normal control or is withdrawn.
- **Deprecation window:** the aim is to mark a control deprecated for at least one MINOR version
  (and about 3 months) before removing it in the next MAJOR version.
- **Tool and specification** may then be released separately. The tool states which specification
  versions it can assess; adapters can be added or improved in MINOR tool releases without
  changing the specification.
- **No breaking change of the specification within a MAJOR version.** A switch that conforms to
  1.x Level 2 still conforms to every later 1.y Level 2, unless its configuration or firmware
  changed, or a vulnerability was published for its firmware (LYSS-VULN-001 follows the data).

## Platform support labels

Each platform is labelled in its adapter (`support`, `tested_on`), in the README and in
[VALIDATION.md](VALIDATION.md):

- **Stable**: the Level 1 and 2 checks were verified on the vendor's own software, on real switches
  (`real`) or on the vendor's official virtual image (`virtual`: MikroTik CHR, SONiC-VS, Arista
  cEOS-lab, the AOS-CX simulator). A virtual image can still differ from hardware (models,
  defaults, switch-chip features), and the validation matrix says what was not covered.
- **Preview**: written from the vendor's documentation, or verified only on the LYSS simulator.
  Its verdicts may change in any release. A preview platform becomes stable in a normal release
  once its outputs are confirmed on the vendor's software; reports from owners are welcome.

## Goals before calling it 1.0 (no date)

1.0 is about the **specification**: the controls and their test procedures stop changing in
incompatible ways. It does not wait for every platform to be stable; the labels say which are.

- Level 3 assessed on every platform where it applies, or reported as not applicable with the
  reason.
- A release candidate of the specification (1.0.0-rc) published for public review; comments from
  people other than its author answered.
- No change to the controls or their test procedures for about four weeks after the release
  candidate (one full release cycle).
- Scale figures published ([docs/SCALE.md](SCALE.md)) and a threat model for the tool
  ([docs/THREAT-MODEL.md](THREAT-MODEL.md)): done.
- Wished, not required: a co-maintainer, so that the project does not depend on a single person.
