# Checking switch configurations in CI

If your switch configurations live in a Git repository (an Oxidized git output, or configurations
kept by hand), LYSS can assess them at every push or pull request. A weakening change, such as
Telnet back on or a default SNMP community, then shows up before it reaches a switch.

This runs the **offline** audit (`lyss audit`): it reads files and never connects to a device.

## GitHub Actions

```yaml
# .github/workflows/switches.yml
name: switch configurations
on:
  push:
  pull_request:          # never pull_request_target: see "Safety" below
permissions:
  contents: read
jobs:
  lyss:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4            # in production, pin actions to a full commit SHA
        with:
          persist-credentials: false         # the audit needs no token
      - uses: lyss-project/lyss@v0.20.0     # same here: the commit SHA of that tag
        with:
          path: configs
          level: "2"
          require-level: "2"
```

The job summary shows a table of every configuration and, for each configuration with a failed
control, the controls that failed and the redacted line that proves it.

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | File or folder to assess |
| `vendor` | `auto` | Adapter name, or `auto` to recognise each file |
| `level` | `2` | Highest level to assess (1, 2 or 3) |
| `require-level` | (empty) | Fail the job if any control of level 1..N **fails**. Empty: report only |
| `pattern` | (empty) | File name pattern. Empty: `.cfg .conf .txt .rsc .json` |
| `recursive` | `true` | Also look in subfolders (hidden ones, such as `.git`, are skipped) |
| `skip-unrecognised` | `false` | Skip files whose platform is not recognised instead of failing |
| `accepted-risks` | (empty) | YAML file of accepted risks (see below). Empty: none |
| `sarif` | `false` | `"true"` also writes the failed controls as SARIF (see "Code scanning") |

Outputs: `switches`, `lowest-level`, `failing` (configurations with a failed control up to
`require-level`), `results` (path of the JSON results, for `actions/upload-artifact`) and `sarif`
(path of the SARIF file, empty unless `sarif: "true"`).

**Oxidized git output** stores one file per node, without a suffix, in one folder per group:

```yaml
        with:
          pattern: "*"
          skip-unrecognised: "true"    # README and other non-configuration files
          require-level: "1"
```

### Why "require-level" looks at failed controls, not at the level reached

A saved file cannot show everything. Automatic backups (LYSS-BKP-001), for example, can only be
checked on the live switch, and so can the firmware when no `show version` output is saved next to
the configuration (see [OFFLINE.md](OFFLINE.md)). These controls are **unknown** offline, so a
configuration file alone usually proves Level 0. The CI gate therefore fails on controls that
**fail**, and a few unknown ones stay in the summary without failing the job.

The gate never vouches for a file it could hardly check. A configuration fails it as
**not assessable** when fewer than half of its controls up to the required level could be decided.
That happens with a firmware-only platform such as Zyxel GS1900, or a file that does not look
like a running configuration. A file whose format matches two platforms is not guessed either:
give its platform with `vendor`.

## Accepted risks

Some failures are accepted on purpose for a while: an end-of-life switch waiting for its
replacement, a legacy device that needs Telnet. Write them in a file and give it with
`--accepted-risks` (action input `accepted-risks`):

```yaml
accepted_risks:
  - control: LYSS-VULN-001
    switches: ["sw-old-*"]        # configuration or file names; * and ? allowed
    reason: End of life, no fixed release; web interface off; replacement ordered (change 1234)
    approved_by: Security officer
    expires: 2027-03-31           # required, at most one year ahead
```

- An accepted failure **stays a failure**: same verdict, same level, shown with its reason, approver
  and expiry date. Only the gate (`require-level`) stops failing on it.
- After the expiry date it counts as a normal failure again, and the report says so. An entry that
  matches no failed control is reported, so that stale exceptions get removed.
- A malformed file stops the audit (exit code 2): it is never half-applied. The file is never read
  automatically: a pull request cannot add one without the workflow naming it.
- **Review changes to this file like code**: a pull request that accepts a risk changes what the
  gate lets through. A `CODEOWNERS` entry for it is a good idea.

## Code scanning (SARIF)

With `sarif: "true"`, the action also writes the failed controls as SARIF (output `sarif`). Upload
it to show them in the repository's **Security > Code scanning** page and on the configuration
lines of pull requests (free for public repositories; private ones need GitHub Advanced Security):

```yaml
permissions:
  contents: read
  security-events: write                   # only for the upload step
jobs:
  lyss:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - id: lyss
        uses: lyss-project/lyss@v0.20.0
        with:
          path: configs
          sarif: "true"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.lyss.outputs.sarif }}
          category: lyss
```

Each result sits on the line that proves the failure, or on line 1 when a setting is missing.
Accepted risks are uploaded as suppressed results, with their reason. Outside GitHub:
`lyss audit --sarif lyss.sarif --report-root . configs/`.

## GitLab CI

[integrations/gitlab](../integrations/gitlab/README.md) has a job to copy into a repository: failed
controls appear in the merge request widget (Code Quality report, every GitLab tier), and the job
fails when a required level is not met. Outside the template: `lyss audit --codequality FILE`.

## Any other CI (Jenkins, ...)

```sh
pip install "lyss==0.20.0"
lyss audit --recursive --level 2 --require-level 2 --summary lyss-summary.md --json-file lyss.json configs/
```

Exit codes:
- 0: no failed control up to the required level;
- 1: at least one failed control;
- 2: a file could not be assessed, or no configuration was found.

## Safety

- **Keep real configurations in a private repository.** Job summaries, logs and artifacts are
  visible to everyone who can read the repository (everyone, for a public one). Evidence is
  redacted (passwords, keys, communities and hashes), but the report still lists each switch's
  weaknesses.
- **Use `pull_request`, not `pull_request_target`.** With `pull_request`, a pull request from a
  fork runs without your secrets and with a read-only token. The action needs no secret and no
  token.
- **Inputs and configurations are treated as untrusted.**
  - Inputs reach the action's scripts only as environment variables.
  - GitHub workflow commands are disabled while the report is printed.
  - Every value taken from a configuration is escaped in the job summary: it cannot become a link,
    an image or HTML.
- **Files of the audited repository never run.** Every Python call of the action is isolated
  (`python -I`) and starts in the runner's temporary folder, so a pull request adding `lyss/` or
  `json.py` cannot replace LYSS's code. Symbolic links are never followed.
- **Pin a version.** The action runs LYSS from its own files at the ref you use, so pinning a
  tag or, better, a commit SHA pins LYSS too. The only package it installs is PyYAML, pinned by
  hash (`.github/action-requirements.txt`).
- **Do not leave a token on disk:** use `actions/checkout` with `persist-credentials: false`; the
  audit needs no token.
