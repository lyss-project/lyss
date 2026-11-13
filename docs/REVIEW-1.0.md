# Public review of the LYSS 1.0 specification

Specification **1.0.0-rc.1** is the text proposed for LYSS 1.0.0: 25 controls in three levels
(Baseline, Hardened, Advanced) for managed network switches. Before it becomes 1.0.0, it is open to
review by anyone who runs or audits switches.

- Read it: [LYSS-Specification.md](LYSS-Specification.md) (generated from
  [spec/lyss-spec.yaml](../spec/lyss-spec.yaml), the normative source).
- Comment: open a GitHub issue on [lyss-project/lyss](https://github.com/lyss-project/lyss/issues)
  whose title starts with `[1.0 review]` and names the control (for example
  `[1.0 review] LYSS-MGMT-010: ...`), or reply to the review issue linked from the release notes.
  Please never paste a real configuration, password or address: describe the case, or use the
  fictitious examples in `tests/` and `demo/`.

## What is most useful

1. **A control that is wrong for your switches**: a requirement that cannot be met on a common
   platform, or that would make a secure switch fail.
2. **A missing control** that every managed switch should meet. From 1.0, a control added within
   1.x is advisory (it never changes a conformance level), so a control that belongs in a level
   should be proposed now.
3. **The level of a control** (Baseline, Hardened, Advanced): too strict or too lax for that level.
4. **A test procedure that can be read two ways**: two auditors could reach different verdicts.
5. **Terms and verdicts** (sections 2 and 3): uplink, edge port, access port, "not applicable",
   "unknown".

Verdicts of a given platform's adapter (how LYSS checks a control on Cisco, Aruba, MikroTik, ...)
are welcome too, but they are not part of the specification: they can be fixed in any release.

## What cannot change

- **Control identifiers** (`LYSS-MGMT-001`, ...): never renamed, renumbered or reused, as before 1.0.
  CISO Assistant audits keep their answers per control.
- The structure: three cumulative levels; a level is met when each of its controls up to that
  level passes or is not applicable.

## How comments are handled

Each comment is answered in its issue, on a best-effort basis: accepted (with the change), deferred
to a later version, or declined with the reason. A change to a control or its test procedure gives a
new release candidate (1.0.0-rc.2, ...) and is listed in [CHANGELOG.md](../CHANGELOG.md). 1.0.0 is
intended once the controls and test procedures have not changed for about four weeks
([VERSIONING.md](VERSIONING.md)); no date is promised.
