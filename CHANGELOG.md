# Changelog

Specification versions (`spec_version`) and tool versions are tracked together until 1.0.

## 0.10.0 (2026-11-08)

Level 3 (Advanced) and Zyxel GS1900. Specification 0.6.0-draft.
- **Level 3 controls written and assessed** (they were drafts): LYSS-ACC-020 DHCP snooping on
  user VLANs, ACC-021 dynamic ARP inspection, ACC-022 802.1X / MAC authentication on access
  ports, ACC-023 broadcast storm control, ACC-024 no CDP/LLDP sent towards users (IP phone ports
  exempt). Each has a statement, rationale, test procedure and ISO 27001 / NIST SP 800-53 / CIS
  references; not applicable on a switch without access ports (core, spine).
- Checks on every platform: Cisco IOS, Cisco Business, HPE Aruba AOS-S, Arista EOS (802.1X and
  LLDP checked on cEOS-lab; the rest needs switching hardware, syntax from Arista's manual and
  the DISA STIG), MikroTik RouterOS 7 (bridge DHCP snooping and ARP inspection, 802.1X server,
  neighbour discovery: checked on CHR 7.25.1). Not applicable on SONiC (data-centre fabric, no
  user ports).
- Level 3 is opt-in: `lyss audit --level 3`, the "1 + 2 + 3" choice of the browser audit, or
  Settings > Assessment in the web interface (switches are re-assessed from their last
  collection).
- Engine: rule forms `any`, `not`, `captured`, `uncovered` (VLAN or port coverage, with VLAN
  ranges such as `10,20-30`) and `not_applicable_if_any`.
- **Zyxel GS1900 (preview, firmware only)**: CVE-2026-7273, the pre-authentication flaw of the web
  interface exploited on about 1,000 GS1900 switches since August 2026 (CISA KEV), with the
  patched firmware of each of the 10 models in Zyxel's advisory. Paste `show version` or the
  System Information page; the firmware code alone identifies the model. Configuration controls
  stay "unknown" (never "not applicable") until the format is verified on a real switch.
- SECURITY.md: why the low-severity paramiko advisory (SHA-1 RSA signatures, CVE-2026-44405) is
  accepted instead of moving to paramiko 5, which cannot talk to legacy switches.

## 0.9.0 (2026-11-07)

Arista EOS (preview), validated on cEOS-lab 4.37.0F. Specification unchanged (0.5.0-draft).
- New adapter `arista_eos`: every Level 1 and Level 2 control, from the configuration and
  read-only `show` commands (`show version`, `show management telnet` / `ssh`,
  `show interfaces status`, `show lldp neighbors detail`, `show ntp status`). Checked on two
  cEOS containers with the factory configuration, an insecure one and a hardened one.
- EOS defaults are taken into account: Telnet and eAPI off, SSH v2 only, no idle timeout
  (`idle-timeout 0` is not shown), RADIUS / TACACS+ keys converted to type 7.
- Topology: EOS LLDP neighbours (`show lldp neighbors detail`), also used by discovery.
- `lyss audit` and the in-browser audit recognise an EOS `show running-config`; Oxidized model
  `eos` is assessed; new-device discovery recognises Arista in LLDP descriptions.
- docs/ACCOUNTS.md: read-only EOS account (role `network-operator`). EOS enforces roles only
  with `aaa authorization commands all default local`, checked in the lab.
- Evidence also hides EOS-style secrets (`secret sha512 …`, `password md5 …`, `key 8a …`).
- Firmware: the one EOS flaw in the CISA KEV catalogue (CVE-2026-7473, Security Advisory 0137)
  has no fixed release, so LYSS-VULN-001 stays "unknown" on EOS; the control's note gives the
  mitigation.

## 0.8.2 (2026-11-07)

Audit in the browser, nothing uploaded.
- New page [lyss.dev/audit.html](https://lyss.dev/audit.html): paste or open a saved
  configuration and get the assessment, with evidence and fixes. The same engine, adapters and
  firmware data run inside the page on Pyodide (Python for WebAssembly), served from lyss.dev
  itself; the page's Content-Security-Policy (`connect-src 'self'`) forbids any other server.
  Optional device state, fictitious examples, English/French. Built by
  `tools/build_web_audit.py` (Pyodide files pinned by SHA-256).
- `lyss audit` recognises the platform from the configuration's own format: `--vendor` is now
  optional (default `auto`), a folder can mix platforms, and a file that is not recognised is
  reported, never guessed.
- `lyss --version`.

## 0.8.1 (2026-11-06)

Offline audit made first-class, after a question from the MikroTik community ("why not analyse a
copy of /export, with nothing touching the router?"): it already worked, now it is documented and
works better.
- docs/OFFLINE.md and a README section: how to save the configuration on each platform
  (RouterOS 6: `/export hide-sensitive`), what a configuration alone can and cannot tell, and how
  to add device state by hand in `<name>.state.txt` (a test keeps the documented command lists
  identical to what a scan collects).
- `lyss audit <folder>` reads `.cfg`, `.conf`, `.txt`, `.rsc` and `.json` files (was `.cfg`
  only); a missing path is reported.
- A configuration saved with Windows Notepad (byte-order mark) is read correctly: the RouterOS
  version in the export header was lost.
- New rule form `{comment: R}`: LYSS-AUTH-003 on RouterOS is decided from the export header
  (`by RouterOS 7.x`). A pasted RouterOS export now settles 13 of the 20 Level 1 + 2 controls.
- The website lists MikroTik RouterOS and SONiC.
## 0.8.0 (2026-11-06)

Two more platforms (MikroTik RouterOS and SONiC, preview), both in the demo; `pip install lyss`;
Oxidized backups of MikroTik routers; a least-privilege account guide. Specification unchanged
(0.5.0-draft).

- `pip install lyss`: the wheel bundles the specification, the adapters and the firmware data
  (copied by setup.py at build time from the top of the repository, where they stay). An installed
  LYSS keeps its data in `%LOCALAPPDATA%\LYSS` (Windows) or `$XDG_DATA_HOME/lyss`
  (`~/.local/share/lyss`), never next to its code. Releases are published to PyPI by
  `.github/workflows/release.yml` with Trusted Publishing (no stored token), after a smoke test of
  the wheel outside the repository.

- Demo lab: two more simulated switches, DEMO-CRS-01 (MikroTik CRS326, RouterOS factory defaults,
  7.24.1 = one point release before the CISA KEV fixes) and demo-leaf-01 (SONiC campus switch,
  `public` SNMP community and cleartext TACACS+ key); read-only simulator platforms with fixed
  outputs. Topology reads RouterOS and SONiC host names.
- docs/ACCOUNTS.md: a least-privilege LYSS account per platform. Verified in the lab: a RouterOS
  group with `ssh,read` only (no `sensitive`) and a SONiC user without sudo collect exactly what
  `admin` collects, and cannot change anything. Finding: on SONiC every local account can read
  the whole config_db, cleartext TACACS+/RADIUS keys included.
- Oxidized: `routeros` nodes are assessed (MikroTik adapter). Hierarchical RouterOS exports are
  rewritten one command per line; Oxidized's `# version:` / `# board-name:` comments give the
  firmware facts; configuration-only rules use the fact that an export lists every non-default
  setting (engine: `absent: true` on configuration line rules, never decisive on an empty file).

- MikroTik RouterOS adapter (preview), validated on CHR 7.25.1: configuration from
  `/export terse` (secrets never collected), device state from `print terse` (services, SSH,
  SNMP, NTP, logging, users, RADIUS, note, Ethernet ports, bridge ports, MAC-Winbox). Factory
  defaults it reports: Telnet/FTP/HTTP/API open to every address, `strong-crypto=no`,
  MAC-Winbox on every interface, no NTP, no remote syslog. Discovery recognises `SSH-2.0-ROSSSH`
  and MikroTik LLDP descriptions. No automatic remediation.
- RouterOS has no SSH pre-authentication banner (checked on 7.25.1): LYSS-MGMT-012 needs the note
  both before the console/Telnet login (`show-at-cli-login`) and at SSH/Winbox login (`show-at-login`).
- Firmware data: RouterOS advisories checked against NVD and the CISA KEV catalog (2026.11.04),
  including CVE-2026-86060/67277/67279 (KEV), CVE-2026-84411 (9.8), CVE-2026-67278 (9.1),
  CVE-2023-30799, CVE-2018-7445 and CVE-2018-14847. `fixed_in` can now list the first fixed
  version of each release line (e.g. 6.49.21 / 7.23.4 long-term / 7.24.2 stable), with an optional
  `affected_from`.
- Engine: `{all: [rules]}` combinator; RouterOS SNMP community names are redacted from evidence
  (`public`/`private` stay visible, being the finding).

- SONiC adapter (preview), validated on SONiC-VS 202505: the config_db JSON
  (`show runningconfiguration all`) is flattened into one block per table entry
  (`TABLE|key` + `field=value` lines); device state from `show version`, `show interfaces status`,
  `show ntp`, `show ssh` and `ss -tlnH`. Collection is read-only (no sudo). Discovery recognises
  SONiC from its LLDP description; it has no automatic remediation.
- Findings from the lab: `config tacacs add --key` stores the key in cleartext in config_db
  (LYSS-AUTH-004 fails), and the SNMP community "public" comes back after
  `config snmp community del public` while /etc/sonic/snmp.yml still holds `snmp_rocommunity`
  (the remediation removes it first).
- SONiC LYSS-AUTH-004: an encrypted global TACACS+ key (`TACPLUS|global` `key_encrypt=true`,
  `config tacacs passkey <key> --encrypt`) passes; per-server and RADIUS keys stay cleartext and
  fail. Engine: new block filter `where_not`. The SNMP note cites sonic-buildimage#18061 / #26952.
- Redaction covers JSON fields (`passkey=`, `*password*=`, `*secret*=`, `*key*=`) and
  non-default SNMP community names in `SNMP_COMMUNITY|<name>` headers.
- Tests: preview adapters must show each control both ways or give the reason why not.

## 0.7.0 (2026-11-05)

Specification 0.5.0-draft
Test procedures tightened where they were looser than their statements (review of the CISO
Assistant library, intuitem/ciso-assistant-community#5246); verdicts can change from pass to fail.
- LYSS-AUTH-002: strong hash only (SHA-256 or stronger: scrypt, PBKDF2-SHA-256, SHA-256/512
  crypt). MD5 (Cisco type 5), SHA-1 (40-hex values on Cisco Business, HPE "sha1") and Cisco type 4
  fail; a full-privilege local account with a weak or reversible password fails too.
- LYSS-AUTH-004: the procedure no longer depends on the level (reversible encodings are not
  cleartext; irreversible storage is planned as a separate Level 2 control).
- LYSS-AUTH-010: every login list used for remote access must start with RADIUS/TACACS+.
- LYSS-AUTH-011: SNMPv3 groups or users below authPriv fail.
- LYSS-MGMT-011: an access port in the management VLAN fails.
- LYSS-MGMT-012: the pre-login banner must state the authorized-use restriction; exec banners
  (after login) do not count.
- LYSS-LOG-010: "no logging on" fails. LYSS-LOG-011: an unsynchronized clock fails (device state).
- LYSS-ACC-011: only trunk / aggregation ports are uplinks; neighbour discovery never exempts a port.
- LYSS-VULN-001, LYSS-BKP-001: procedures aligned with their statements.
- Level 3 controls without text are not assessable in the CISO Assistant library.

Tool
- New rule form `captures_in_both` (a value found in two places, e.g. the management VLAN on
  access ports); `show ntp status` (IOS) and `show sntp status` (Cisco Business) collected.

Wazuh
- Per-control rules (100810-100869) generated from the specification, with NIST SP 800-53 groups:
  LYSS findings appear in Wazuh's NIST 800-53 compliance dashboard. `install.sh --regression-level`.
- Dashboard "LYSS - Switch security" (lyss-dashboard.ndjson); agent group script for the events file.
- Decoders for Cisco IOS timestamps with a time zone offset and for Cisco Business messages, with
  rules for management sessions, refused logins and password guessing.
- Rescan on change (Settings): LYSS reads configuration-change and session-end alerts from the Wazuh
  dashboard with a read-only account (reader-account.sh) and rescans the switch at once; LYSS's own
  sessions are ignored.

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
