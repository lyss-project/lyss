# Contributing to LYSS

LYSS has two parts that evolve differently: the **specification** (what a secure switch is) and
the **tool and adapters** (how it is checked on each platform). Both are welcome.

## Ground rules

- **Be respectful:** see the [code of conduct](CODE_OF_CONDUCT.md).
- **Never commit real device data.** Configurations contain password hashes, keys, SNMP
  communities and topology. Test cases are synthetic: documentation addresses
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), fake names, fake hashes. `private/` is git-ignored.
- **Read-only collection only.** A collector command must never change the device.
- **Unknown, never guess.** When evidence is missing, a check yields `unknown`.
- **Every fact in `data/firmware.yaml` cites its source** (vendor advisory, end-of-life bulletin,
  CISA KEV) and the date it was verified. `python tools/kev_watch.py` lists the CISA KEV entries
  for LYSS platforms that `firmware.yaml` does not cover yet: a good place to start.

## Proposing a change to the specification

1. Open an issue describing the control (new, changed or withdrawn), with its rationale and
   references.
2. Edit `spec/lyss-spec.yaml`. A Level 1-2 control needs: `title`, `statement`, `rationale`,
   `test_procedure`, `evidence` and the `iso27001_2022`, `nist_800_53r5` and `cis_v8` mappings.
3. Regenerate the document: `python tools/build_spec.py`.
4. Bump `spec_version` following the versioning policy (section 8 of the specification) and add
   a line to `CHANGELOG.md`.
5. Control identifiers are never reused.

## Adding or improving an adapter (a vendor / platform family)

1. Create or edit `adapters/<platform>.yaml`: one entry per control id, using the rule forms
   documented at the top of `adapters/cisco_ios.yaml`.
2. If device state is needed, add the read-only commands for the platform in
   `src/lyss/collector.py` (`COMMANDS`).
3. Add test cases in `tests/cases/<name>/` (`config.cfg`, optional `state.txt`, `expected.yaml`).
   For a fully supported platform, every Level 1-2 control must have a case where it passes and
   one where it fails: `tests/test_controls.py` enforces it.
4. Validate the rules on real devices you are authorised to assess, then contribute only
   synthetic cases derived from them.

## Development

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"        # Windows: .venv\Scripts\pip ...
git config core.hooksPath tools/git-hooks  # the test suite runs before each commit
python -m pytest tests -q
```

`tests/test_private.py` compares the verdicts of the switches in your local `private/` data with
`private/golden.json`. When a rule change alters a real verdict, review it, then accept it with
`python -m pytest tests/test_private.py --update-golden`.

## Licences

Contributions to the specification and the firmware data are accepted under CC BY 4.0, and
contributions to the software under the GNU AGPL v3 with the additional terms in `NOTICE`
(inbound = outbound: you keep your copyright, nothing is transferred). Keep the attribution
"LYSS by Mouad Lyaazale · Made in Morocco" where it appears.

### Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the change, or
otherwise have the right to submit it under the licence of the file it changes.

```sh
git commit -s -m "Describe the change"   # adds: Signed-off-by: Your Name <you@example.com>
```

The sign-off must use your real name and an address you control. Pull requests with unsigned
commits are checked automatically and cannot be merged; `git commit --amend -s` or
`git rebase --signoff main` fixes them.

## Security issues

Never open a public issue for a vulnerability: see [SECURITY.md](SECURITY.md).
