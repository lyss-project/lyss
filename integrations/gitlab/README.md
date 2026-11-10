# LYSS in GitLab CI

`lyss.gitlab-ci.yml` audits the saved switch configurations of a repository at every push and
merge request, offline (it never connects to a device). It works on every GitLab tier, on
gitlab.com and self-managed:

- failed controls appear in the **merge request widget** (Code Quality report), with the file and
  the line that proves each one;
- the job **fails** when `LYSS_REQUIRE_LEVEL` is set and a control up to that level fails;
- `lyss-results.json` (every finding, redacted evidence) and `lyss-summary.md` are kept as job
  artifacts for 30 days.

## Use

1. Copy `lyss.gitlab-ci.yml` into your repository (copying keeps the job under your review; an
   `include: remote:` would run whatever that URL serves later).
2. Include it and set the variables in your `.gitlab-ci.yml`:

```yaml
include:
  - local: lyss.gitlab-ci.yml

variables:
  LYSS_PATH: configs            # file or folder of saved configurations
  LYSS_REQUIRE_LEVEL: "1"       # fail the pipeline on a failed Level 1 control
```

| Variable | Default | Meaning |
|---|---|---|
| `LYSS_VERSION` | the release this file comes from | LYSS version installed from PyPI |
| `LYSS_PATH` | `.` | File or folder to assess (subfolders included, hidden ones skipped) |
| `LYSS_LEVEL` | `2` | Highest level to assess (1, 2 or 3) |
| `LYSS_REQUIRE_LEVEL` | (empty) | Fail the job if a control of level 1..N fails. Empty: report only |
| `LYSS_PATTERN` | (empty) | File name pattern, e.g. `*` for Oxidized git output; with a pattern, files whose platform is not recognised are skipped |
| `LYSS_ACCEPTED_RISKS` | (empty) | YAML file of accepted risks ([docs/CI.md](../../docs/CI.md#accepted-risks)) |

## Safety

- LYSS is installed outside the checkout and runs with `python -I`: a merge request that adds
  Python files (`lyss/`, `json.py`...) cannot replace LYSS's code. Symbolic links are not followed.
- Keep real configurations in a **private** project: job logs, artifacts and the merge request
  widget show each switch's weaknesses (evidence is redacted: passwords, keys, communities, hashes).
- Accepted risks are left out of the Code Quality report (it has no "accepted" field) and stay in
  `lyss-results.json` with their reason and expiry date.

Tested in the `python:3.12-slim` image with fictitious configurations (the job script as GitLab
runs it). Not yet published as a GitLab CI/CD catalog component.
