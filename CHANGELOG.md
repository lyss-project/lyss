# Changelog

Specification versions (`spec_version`) and tool versions are tracked together until 1.0.

## Unreleased

Contributors
- Thanks to **juanmig7890** for the first outside contribution: Linux and macOS quick start in
  the tester guide (#5).

Integrations
- SIEM events: after each scan, JSON events per switch (level, counts), per failed control,
  regression, fix and collection error, plus discovered switches; sent over syslog (UDP/TCP,
  RFC 3164, program "lyss") and/or appended to a JSON-lines file for a local agent. Settings →
  SIEM events, with a test event. Wazuh decoder, rules (100800-100809) and install script in
  integrations/wazuh, tested with wazuh-logtest and end to end (syslog UDP) on Wazuh 4.14.
- CISO Assistant library (integrations/ciso-assistant), generated from the specification by
  tools/build_ciso_library.py: the LYSS framework (levels, domains, controls with rationale and
  test procedure; levels as implementation groups) and a LYSS → ISO/IEC 27001:2022 mapping (one
  direction only: an ISO control judged compliant proves nothing about a switch). Draft
  specifications say so in the library name. Imported and checked in CISO Assistant 4.1, including
  an ISO 27001 audit prefilled from a LYSS audit; `--excel` writes upstream's Excel v2 source
  workbooks, validated with upstream's checker and converter.
- Oxidized: `python -m lyss oxidized --url ...` assesses the configurations Oxidized backs up
  (REST API, read-only, no SSH to the switches); a recent successful Oxidized backup is evidence
  for LYSS-BKP-001; secrets hidden by Oxidized give "unknown", never a false verdict; `--events`
  sends the results to the SIEM.

## 0.6.0 (2026-11-05): first public release

Licence
- The software moves from Apache 2.0 to the GNU AGPL v3 (AGPL-3.0-only) with additional terms
  (section 7): the attribution "LYSS by Mouad Lyaazale · Made in Morocco" must be kept in the web
  interface footer, the login page and the reports; modified versions must be marked as such;
  no rights to the LYSS names and logo (TRADEMARKS.md). The specification stays CC BY 4.0.
  SPDX headers in every source file; a test guards the attribution.

Public release
- The source code is public. Vulnerabilities are reported privately (SECURITY.md); contributions
  are signed off under the Developer Certificate of Origin (CONTRIBUTING.md, checked on pull
  requests); issue templates for wrong verdicts, errors and new platforms.

Early access
- Tester guide (docs/TESTERS.md). `Start-LYSS.cmd` installs LYSS on the first start;
  `Start-LYSS-Demo.cmd` starts the demo with one double-click.
- `tools/sync_export.py`: updates the export repository with the current version as one new
  commit, after the same checks as the first export (internal terms, private addresses, secrets).

Tool
- Sites (head office, agencies, subsidiaries): named address ranges in Settings; each switch
  belongs to the site containing its address (most specific range wins) unless a site is set on
  the switch. Dashboard per-site totals and filter, "Scan this site", per-site HTML/JSON reports,
  site shown on discovered switches and on the switch page.
- Discovery: "Scan a site" at a gentle rate (6 parallel probes, pause between probes) so VPN
  tunnels and remote firewalls/IPS stay quiet; site ranges larger than /20 are skipped.

## 0.5.0 (2026-11)

Tool
- HPE Aruba AOS-S (HP ProCurve) adapter complete: every Level 1 and Level 2 control, device
  state collection, model/firmware from the device or from the configuration header, port-list
  rules (trunks and tagged ports are uplinks, "spanning-tree <ports> bpdu-protection"), LLDP
  neighbours on the topology map, basic remediation (Telnet, plain HTTP, idle timeout, default
  community, banner, syslog).
- Switch simulator (`python -m lyss sim`): fictitious Cisco IOS, Cisco Small Business and HPE
  Aruba switches over SSH, faithful enough for the real collector, topology and remediation.
- Demo mode (`python -m lyss demo`): simulated network + web interface on a separate data folder,
  only invented data.
- SNMPv3 user secrets (`auth sha ... priv aes ...`) are now redacted in evidence and reports.
- The SSH host key algorithm is recorded from an unbiased handshake (LYSS-MGMT-013 no longer
  reports `ssh-rsa` for switches that support rsa-sha2).
- First parallel scan: each SSH session reads a private copy of the pinned host key (no more
  intermittent "not found in known_hosts").
- `tools/export_public.py`: builds a public repository without history, with internal-term,
  private-address and secret checks.

## 0.4.0 (2026-11-04)

Specification 0.4.0-draft
- Section 7.1: requirements for optional remediation (off by default, preview, low-risk only,
  backup, rollback, verification before save, change log).

Tool
- Remediation module (disabled by default): low-risk fixes for Cisco IOS and Cisco SB with
  generated rollbacks (Telnet, plain HTTP, default SNMP communities, SSH v2, idle timeout, banner,
  syslog, NTP) and a web-interface mitigation for unpatchable Cisco SB models; one switch at a
  time, automatic rollback, verification over a new connection, save only after verification,
  change log. Scans and remediation never run at the same time.
- Firmware upgrade for Cisco Catalyst 1000: image upload checked against Cisco's MD5/SHA-512, staging without reboot (temporary SCP server, verify /md5, archive download-sw /safe /no-set-boot, boot variable checked unchanged), separate activation confirmed by typing the switch name (boot system, reload, wait, version check, scan); links cut during the reboot shown from the topology.
- Discovery no longer lists dropbear SSH servers (access points, IoT) as switches.

## 0.3.0 (2026-11-04)

Specification 0.3.0-draft
- Every Level 1-2 control has a requirement, rationale, vendor-neutral test procedure and
  informative mappings to ISO/IEC 27001:2022, NIST SP 800-53 r5 and CIS Controls v8.
- LYSS-VULN-001 also covers known-exploited vulnerabilities (CISA KEV) and the end of
  security support.
- LYSS-BKP-001 is evaluable: automatic (scheduled) configuration backups or an attested external
  backup system.
- LYSS-AUTH-002 passes when there is no enable credential and privileged access only uses hashed
  local accounts.
- New document `docs/LYSS-Specification.md` (generated), conformance claims, adapter and tool
  requirements, versioning policy.

Tool
- Configuration archive with redacted diffs, scan history and trends, regression detection.
- Scheduled scans (in the interface, or `lyss collect --scheduled` with cron / Task Scheduler).
- E-mail alerts and CISO Assistant evidence push (disabled by default).
- Portable AES-256-GCM vault for Linux; Dockerfile and docker-compose; `LYSS_DATA_DIR`, `LYSS_HOME`.
- Firmware knowledge base: Catalyst 1000 (KEV CVE-2025-20352, end of security support 2028),
  SG350 and SG300 end of support, Cisco Business 250/350, HPE Aruba AOS-S (HPESBNW05156).
- Test suite: per-control pass/fail cases, unit, web and private regression tests; pre-commit
  hook and CI workflow (Windows and Linux).
- Fixes: Cisco SB `enable password level 15 encrypted` false failure; redaction of the word "level".

## 0.2.0 (2026-11-03)

- Level 2 controls, device state collection, firmware check (LYSS-VULN-001), SSH crypto control
  (LYSS-MGMT-013), edge-port BPDU guard detection.
- Web interface, parallel read-only collector, reports, control matrix, topology map, discovery
  (neighbours and SSH range scan), credential profiles, platform auto-detection.

## 0.1.0 (2026-11-03)

- First draft: Level 1 controls, Cisco IOS / Cisco SB / HP ProCurve adapters, command-line audit.
