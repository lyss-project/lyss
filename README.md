# LYSS: Lyaazale Switch Security

[![tests](https://github.com/lyss-project/lyss/actions/workflows/tests.yml/badge.svg)](https://github.com/lyss-project/lyss/actions/workflows/tests.yml)
[![licence: AGPL-3.0](https://img.shields.io/badge/licence-AGPL--3.0-blue)](LICENSE)
[![specification: CC BY 4.0](https://img.shields.io/badge/specification-CC%20BY%204.0-lightgrey)](LICENSE-SPEC)
[![python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab)](https://www.python.org/downloads/)
[![made in Morocco](https://img.shields.io/badge/made%20in-Morocco-c1272d)](https://lyss.dev)

**Telnet still on. SNMP "public". Firmware with an exploited flaw. Would you find them on your
switches?**

LYSS is an open, vendor-neutral security standard for network switches, and a free, read-only
tool that checks your switches against it, shows the evidence and gives the fix.

![LYSS demo: one-click read-only scan, evidence and fix for every finding, topology, control matrix, low-risk fixes verified by a new scan](docs/media/lyss-demo.gif)

<sub>Demo on a fictitious network. Cisco IOS · Cisco Business · HPE Aruba AOS-S · Website: [lyss.dev](https://lyss.dev)</sub>

LYSS defines **what** a securely managed switch looks like, once, independently of any vendor
(the [specification](docs/LYSS-Specification.md)), and **how to verify it** on each platform
(adapters). Switches are assessed against conformance levels:

- **Level 1, Baseline**: no cleartext management, no default or recoverable credentials,
  supported firmware without known critical or exploited vulnerabilities, automatic backups.
- **Level 2, Hardened**: central authentication, restricted and modern management access,
  remote logging and time synchronization, access-port hygiene.
- **Level 3, Advanced**: access-layer protections (draft).

> Status: **0.6.0, draft specification, preview.** The specification and the tool may still change
> before 1.0. Feedback and adapters for other platforms are welcome.
> Author: Mouad Lyaazale (معاد اليازل).

## Try it in two minutes (no switch needed)

```sh
git clone https://github.com/lyss-project/lyss.git && cd lyss
python -m venv .venv
.venv/bin/pip install -e .              # Windows: .venv\Scripts\pip install -e .
.venv/bin/python -m lyss demo --open    # Windows: .venv\Scripts\python -m lyss demo --open
```

This starts a simulated network of six fictitious switches (Cisco IOS, Cisco Small Business,
HPE Aruba) on 127.0.0.1 and the LYSS web interface on a separate demo data folder. Everything
you see is invented. See [docs/DEMO.md](docs/DEMO.md). On Windows, double-click
`Start-LYSS-Demo.cmd` instead (the first start installs LYSS).

**Testing LYSS on your switches?** Start with [docs/TESTERS.md](docs/TESTERS.md), and tell me what
you found in the [issues](https://github.com/lyss-project/lyss/issues). Website: https://lyss.dev

## Platform support

| Platform | Level 1 | Level 2 | Device state | Remediation | Firmware data |
|---|---|---|---|---|---|
| Cisco IOS / IOS-XE (Catalyst) | yes | yes | yes | yes | Catalyst 1000 |
| Cisco Small Business / Business (SG200-550X, CBS) | yes | yes | yes | yes | SG200/300/500, 350, CBS250/350 |
| HP ProCurve / HPE Aruba AOS-S | yes | yes | yes | basic | AOS-S 16.x |

Cisco IOS and Cisco Small Business are validated on real switches; HPE Aruba AOS-S on the
simulator and synthetic outputs so far (reports from real AOS-S switches are welcome).

## What the tool does

- **Read-only collection** over SSH, in parallel, optionally through an SSH jump host.
- **Assessment** with evidence for every verdict (secrets redacted) and recommended fixes.
- **Discovery** of unmanaged switches from LLDP/CDP neighbours and SSH range scans.
- **Topology map** built from neighbour tables.
- **History**: configuration versions with diffs, scan trends, regression alerts.
- **Scheduled scans**, **e-mail alerts**, **CISO Assistant** evidence push (disabled by default).
- **SIEM events** over syslog or a JSON-lines file, with ready Wazuh decoder and rules
  ([integrations/wazuh](integrations/wazuh/README.md)).
- **Oxidized**: assess the configurations Oxidized already backs up, without SSH
  ([integrations/oxidized](integrations/oxidized/README.md)).
- **CISO Assistant library**: the LYSS framework and its ISO 27001:2022 mapping, ready to import
  ([integrations/ciso-assistant](integrations/ciso-assistant/README.md)).
- **Reports**: standalone HTML (printable to PDF) and JSON, with ISO 27001 / NIST / CIS mappings.
- **Optional remediation** (off by default): low-risk fixes only, previewed, applied one switch at
  a time, verified over a new connection, rolled back automatically, saved only after
  verification, and logged.
- **Switch simulator** (`python -m lyss sim`) to test collection, topology and remediation
  without hardware.

## Getting started

Windows: double-click `Start-LYSS.cmd`; http://127.0.0.1:8765 opens. The first start installs LYSS
into `.venv` (needs Python 3.10+) and asks for an administrator password.

From source (any OS):

```sh
python -m venv .venv
.venv/bin/pip install -e .           # Windows: .venv\Scripts\pip install -e .
.venv/bin/python -m lyss ui          # local web interface on 127.0.0.1:8765
```

Docker (Linux): `docker compose up -d`, then http://127.0.0.1:8765. Data lives in the `lyss-data`
volume; back up `/data/master.key`, which encrypts the stored credentials.

Command line:

```sh
python -m lyss collect                 # collect and assess every switch (read-only)
python -m lyss collect --scheduled     # same, from cron / Task Scheduler (automatic backup)
python -m lyss audit --vendor cisco_sb --level 2 path/to/configs/
```

## Repository layout

| Path | Content | Licence |
|---|---|---|
| `spec/lyss-spec.yaml` | The specification (normative source) | CC BY 4.0 |
| `docs/LYSS-Specification.md` | Specification document, generated by `tools/build_spec.py` | CC BY 4.0 |
| `data/firmware.yaml` | Firmware knowledge base, every fact sourced | CC BY 4.0 |
| `adapters/` | Per-platform checks and remediations | AGPL-3.0-only + terms |
| `src/lyss/` | Engine, collector, discovery, topology, history, web interface | AGPL-3.0-only + terms |
| `tests/` | Synthetic test cases and test suite | AGPL-3.0-only + terms |

## Licence and attribution

LYSS is free software: you can use, study, modify and share it. The software is licensed under
the GNU Affero General Public License v3 (AGPL-3.0-only) with additional terms under its section 7,
and the specification under CC BY 4.0. In short:

- Every copy and every modified version, including one offered to users over a network, must keep
  the attribution **LYSS by Mouad Lyaazale · Made in Morocco** where the original shows it: the
  footer of the web interface, the login page and the reports. Keep the `NOTICE` file.
- A modified version must be marked as modified and must publish its source code to its users
  (AGPL).
- The names "LYSS" and "Lyaazale Switch Security" and the LYSS logo are not licensed for modified
  versions: see [TRADEMARKS.md](TRADEMARKS.md).

The exact terms are in [LICENSE](LICENSE), [LICENSE-SPEC](LICENSE-SPEC) and [NOTICE](NOTICE).

## Support LYSS

LYSS is free and built on personal time. If it helps you secure your network, you can support its
development on [Ko-fi](https://ko-fi.com/lyaazale). Reporting wrong verdicts and sharing the
project help just as much.

## Data handling

Real switch configurations contain password hashes, keys and topology. They stay in `private/`
(or `LYSS_DATA_DIR`), which is never committed. See [SECURITY.md](SECURITY.md) for the security
design and [CONTRIBUTING.md](CONTRIBUTING.md) to contribute controls or adapters.
