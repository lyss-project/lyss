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
- **Control IDs are never reused.** If a control is removed, its ID (`LYSS-MGMT-001`, …) stays
  retired, so an old report never means something different.
- **Every result records the specification version** it was assessed against (`spec_version`
  in each switch result, in exported reports and in JSON output). A conformance level is only
  meaningful together with that version: "Level 2 against 0.6.0-draft".
- **Pin a version** for a stable baseline: `pip install "lyss==0.15.0"`. Upgrade on purpose,
  read the changelog, then rescan. The history keeps the previous results for comparison.

## Planned from 1.0

- **Semantic versioning for the specification:**
  - MAJOR: a control removed, made stricter in a way that can turn a pass into a fail, or moved
    to another level;
  - MINOR: a control added at the top level, a new level, or a wording that does not change any
    verdict;
  - PATCH: typos and references.
- **Deprecation window:** the aim is to mark a control deprecated for at least one MINOR version
  (and about 3 months) before removing it in the next MAJOR version.
- **Tool and specification** may then be released separately. The tool states which specification
  versions it can assess; adapters can be added or improved in MINOR tool releases without
  changing the specification.
- **No breaking change of the specification within a MAJOR version.** A switch that conforms to
  1.x Level 2 still conforms to every later 1.y Level 2, unless its configuration changed.

## Goals before calling it 1.0 (no date)

- Every advertised platform validated on real hardware, not only simulators or virtual
  appliances. HPE Aruba, MikroTik switch chips, SONiC and Arista still need this: reports from
  owners are welcome.
- The specification has been reviewed by people other than its author, and stays unchanged for one
  full release cycle.
- Scale figures published ([docs/SCALE.md](SCALE.md)) and a threat model for the tool
  ([docs/THREAT-MODEL.md](THREAT-MODEL.md)).
- At least one co-maintainer, so that the project does not depend on a single person.
