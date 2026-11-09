# Changelog

Specification versions (`spec_version`) and tool versions are tracked together until 1.0.

## Unreleased

**Specification 0.7.0-draft: stricter test procedures**, after the automated reviews (CodeRabbit,
Qodo) of the CISO Assistant pull request. Control IDs are unchanged. Some verdicts can change from
pass to fail or unknown, so rescan after upgrading.

- **LYSS-AUTH-010:** local accounts are the only accepted fallback after the AAA server. A
  list such as `group radius none` (no authentication when the server does not answer) now
  fails, as do `line`/`enable` fallbacks (Cisco IOS, Cisco Business, Arista; `none`/`authorized`
  on HPE). Console logins are explicitly out of scope: the console is the recovery path.
- **LYSS-LOG-010:** Cisco IOS `no logging trap` (forwarding to syslog hosts turned off) fails.
- **LYSS-LOG-011:** a configured time server without device state is now **unknown**, not pass.
  This matches the offline guide. On HPE AOS-S, synchronization is not collected yet, so the
  control stays unknown there.
- **LYSS-BKP-001:** the gap between the last two automatic backups must not exceed the
  parameter (7 days). A monthly schedule no longer passes in the days after a run.
- **LYSS-ACC-011:** a link aggregation that is not a trunk (e.g. towards a server) is an edge
  port, checked on its port-channel interface (Cisco IOS, Arista). Not yet checked on Cisco
  Business, HPE and RouterOS (stated in the adapters).
- **LYSS-ACC-020 / 021:** an access port trusted for DHCP snooping or ARP inspection fails
  (Cisco IOS, Cisco Business, Arista ARP, RouterOS `trusted=yes` / `trusted-arp=yes`).
- **LYSS-ACC-022:** Cisco IOS `authentication open` (traffic before authentication) fails.
- **LYSS-ACC-023:** a 100 % broadcast threshold limits nothing and fails (Cisco IOS, Cisco
  Business, Arista; RouterOS `storm-rate=100` no longer counts).
- **Wording only:** LYSS-AUTH-002 names salted hashes and unsalted SHA-256 (Cisco type 4);
  LYSS-AUTH-004 explains why a reversible encoding still passes Level 1.
- **CISO Assistant mapping description:** with mixed results, CISO Assistant's current mapping
  engine gives *partially compliant* (one compliant and one non-compliant LYSS requirement on the
  same ISO control). The description and integrations/ciso-assistant/README.md now say so. Library
  version 70000.
- The demo simulator answers `show ntp status` (Cisco IOS) and `show sntp status` (Cisco Business).

## 0.15.1 (2026-11-09)

**Specification 0.6.1-draft:** three informative ISO/IEC 27001:2022 references corrected after the
CISO Assistant maintainers' review. No requirement or verdict changes. These references matter
because a failed LYSS control marks the mapped ISO control non-compliant in a mapped audit.
- LYSS-MGMT-012 (login banner): A.5.10 → **A.8.5** Secure authentication. ISO/IEC 27002 includes
  the pre-login notice in secure log-on procedures.
- LYSS-AUTH-003 (local passwords not stored in cleartext): **A.8.5** added, next to A.5.17, like
  LYSS-AUTH-002.
- LYSS-ACC-024 (no CDP/LLDP towards users): A.8.9 Configuration management removed; A.8.20 kept.

The CISO Assistant library is regenerated (version 60010, 43 mappings). VERSIONING.md now says
explicitly that control IDs are never renamed or renumbered, as the specification's versioning
rules already did.

- **MikroTik offline audit:** `/export verbose` is now the recommended export. It writes every
  value, defaults included, so nothing has to be inferred. LYSS already reads it, with identical
  verdicts on all 25 controls (tested on CHR 7.25.1). Suggested on the MikroTik forum.

## 0.15.0 (2026-11-08)

- **Management reachability.** `lyss probe`, run on a PC of the network to test, opens and closes
  TCP connections to the management ports of the switches. It sends nothing else. Its result is
  imported in the new **Reachability** page or with `lyss reachability import`. Probes of the last
  90 days are evidence:
  - a management port answering from a network not allowed to manage fails LYSS-MGMT-010;
  - Telnet answering fails LYSS-MGMT-001;
  - plain HTTP answering fails LYSS-MGMT-003.

  A probe never makes a control pass. See [docs/REACHABILITY.md](docs/REACHABILITY.md).
- **Exploited-vulnerability backlog reviewed.** The 43 CISA KEV entries the first watch run
  listed for Cisco IOS (and one for Zyxel) were checked against Cisco's and CISA's descriptions,
  and each is now recorded as not applicable with its reason in `data/kev-watch.yaml`:
  - 12 concern other products: IOS XE only, Catalyst 4500/6800, industrial switches, routers,
    email appliances, Zyxel firewalls;
  - one needs GET VPN to be enabled;
  - the others were published in 2018 or earlier, before the first Catalyst 1000 software
    (15.2(7)E1).

  No firmware verdict changes.
- **Second security review.** Fresh reviewers tried to bypass the 0.14.0 fixes; each finding has a
  regression test.
  - **Incomplete changes:** a switch whose last change may be incomplete stays blocked until a real
    new scan. A re-assessment of the stored files no longer clears it, a long change log no longer
    hides it, and refused attempts keep it.
  - **Banners and macros:**
    - a delimiter inside the banner text (`Press ^C to quit`) no longer ends the banner;
    - IOS `macro name` bodies are not read as configuration.
  - **Hand-made files (offline, CI)** are refused, not read with a guess, when they contain:
    - a banner that never ends;
    - indented block headers;
    - device state with repeated sections;
    - (under the gate) almost no configuration.
  - **Speed:** section headers are parsed without a regular expression, so a crafted state line can
    no longer stall an assessment.
  - **Redaction** now also covers IOS passwords and keys containing spaces, `priv aes256` / `des56`,
    `snmp-server host ... vrf X`, escaped quotes in RouterOS, HSRP/VRRP/GLBP keys, IKEv2
    `pre-shared-key local|remote`, and `Password:` / `community:` forms in device output.
  - **Retention "no time limit"** keeps every distinct version; two versions archived in the same
    second no longer overwrite each other.
  - **Settings:** saving merges nested sections too, so a concurrent save can no longer turn
    firmware upgrades back on.
  - **Smaller fixes:**
    - Host headers need a numeric port;
    - remediation refuses 0.0.0.0, loopback, broadcast and multicast servers;
    - the NTP verification ignores banner text;
    - the CI audit refuses a path that goes through a linked folder.
- **Reachability** (reviewed too): see above; the import keeps only the open management ports of
  inventory switches, caps future dates, and runs off the web server's main loop.

## 0.14.0 (2026-11-07)

Switch configurations checked in CI, encryption at rest of configurations and results, NIS2
mapping and crosswalk, watch of exploited vulnerabilities, supply-chain hardening. Specification
0.6.0-draft: requirements unchanged, informative references added.

- **Security review** of the whole tool before this release (SSH collection, storage, web
  interface, assessment engine, remediation and firmware, CI). Fixed:
  - **Command injection through IPv6 scope ids.** Python accepts `fe80::1%<anything>` as an
    address, so a switch address or the jump host source could carry shell characters into the
    `nc` command on the jump host, and the syslog setting could carry new lines into the
    configuration sent to switches. Addresses are now checked exactly (no scope id, no spaces or
    control characters), remediation servers must be IPv4, settings are re-checked when fixes are
    built, and the collector refuses any configuration command that contains control characters.
  - **GitHub Action:** every Python call runs isolated (`-I`), from the runner's temporary
    folder, so files of the audited repository (a pull request) can never be imported. LYSS runs
    from the action's own files and only PyYAML is installed, pinned by hash. Symbolic links and
    special files are never followed, very large files are skipped, and the job summary stays
    under GitHub's limit.
  - **Web interface:**
    - requests for an unknown host name are refused (DNS rebinding); `LYSS_ALLOWED_HOSTS` adds names;
    - in remote mode, creating the administrator needs a token printed on the console;
    - parallel password guesses can no longer exceed the limit;
    - POSTs without a session are refused before their body is read, and bodies are size-capped;
    - deleting a device never builds a path from the name in the URL;
    - network (UNC) paths are refused;
    - sessions have a 12-hour maximum, and cookies are Secure over HTTPS.
  - **Remediation:**
    - a rejected rollback is no longer reported as done, and nothing is saved after it;
    - any error while sending or verifying triggers the rollback;
    - a syslog or NTP server already on the switch is never re-sent, so never removed by a rollback;
    - NTP fixes are verified on the configuration (synchronisation takes minutes);
    - the suggested servers need a majority of switches, and are no longer pre-filled;
    - a switch whose last change may be incomplete is refused until it has been scanned again.
  - **Assessment engine.** Several inputs could make a failing switch look compliant:
    - **Forged device state.** Text a neighbour sends over CDP/LLDP and the switch prints could
      imitate a section header and replace `show version` or the SSH evidence. Collected
      headers now carry a random value per collection; in hand-made state files, a duplicated
      section is dropped.
    - **Platform auto-detection** could be steered: an IOS banner quoting a Zyxel line made
      every control "unknown". Text matching two platforms is no longer guessed. The CI gate
      also fails a file whose controls are mostly undecided.
    - **Banner text** counted as configuration: a multi-line banner containing
      `logging host ...` passed LYSS-LOG-010. Banner lines are now kept apart. The RouterOS
      rewrite runs only for MikroTik, and SONiC JSON names can no longer inject lines.
    - **A state command that failed** (`% Unrecognized command`) no longer passes an "absent" check.
    - **Cisco IOS:**
      - `username ... nopassword`, `server-private ... key`, `pac key` and `exec-timeout 0 86400` now fail;
      - AAA must cover the login list the vty lines really use.
    - **MikroTik:** a later `/ip service enable telnet`, a `comment="disabled=yes"`, or a quoted
      `name="public"` no longer fool the configuration checks.
  - **Redaction** now also covers:
    - SNMPv3 keys in configuration differences and in Cisco SB `encrypted` lines;
    - `snmp-server host ... <community>`;
    - RouterOS community names;
    - `md5` keys (NTP, OSPF);
    - quoted multi-word secrets;
    - pre-shared keys and passphrases;
    - `Password:` in state output;
    - private-key blocks in differences.
  - **Denial of service:** the regular expressions that could take minutes on a crafted long line
    are linear now, lines are capped, and huge port ranges are not expanded.
  - **Collection:**
    - `known_hosts` is locked across processes and rewritten atomically;
    - a wrong Cisco SB password is tried once, never retried (account lockout);
    - the shell session caps its output and recognises the switch's own prompt only;
    - discovery probes have an overall deadline;
    - platform auto-detection probes the device's own SSH port.
  - **Firmware upgrades** have their own setting, off by default. Activation checks that the new
    image is in flash and keeps the previous image as a fallback in the boot path. If the switch
    does not confirm the reload, LYSS restores the previous boot variable instead of leaving it
    armed for the next reboot.
  - **Remediation never guesses the previous state.** The Cisco SB web mitigation needs the
    collected list of services. A fix that would delete an existing (non-compliant) login banner
    is left to the administrator, because LYSS could not put the original text back.
  - **Discovery:** "Scan them right away" is off by default, with a warning. A discovered device
    is not verified, and the first scan sends the profile's password to it. Candidates outside
    your sites are flagged.
  - **Settings** saved at the same time by two writers (two tabs, the web interface and the
    command line) keep both changes.
  - **Hand-made files:** the offline audit refuses a Cisco IOS, Cisco SB or Arista file whose
    block commands are not indented as the switch prints them, because such a line could escape
    its block (CI).
  - **HPE AOS-S:** `console idle-timeout serial-usb 0` now fails LYSS-MGMT-004.
  - **Storage:**
    - configuration archive updates are locked across processes;
    - every write uses its own temporary file;
    - retention always keeps the last 3 distinct versions;
    - a missing master key with existing encrypted data stops LYSS instead of silently creating a new one;
    - DPAPI file encryption is separated from credentials;
    - data files are owner-only on Linux.
  - **Releases:** build tools are pinned (`.github/build-constraints.txt`).
- **Encryption at rest, on by default.** Collected configurations, device state, archived
  configuration versions and results are encrypted with the same key as the credentials:
  Windows DPAPI (current user) or AES-256-GCM (master key). Plain files of earlier versions stay
  readable and are encrypted at the next scan; tampered files are refused.
  - Settings > Data protection shows the state, can turn encryption off for new files, and sets a
    **retention period** for configuration versions and scan history. The current configuration
    is always kept.
  - `lyss data status | seal | unseal --yes | config <switch> [--list | --version FILE]`. `config`
    prints a stored configuration to restore it on a switch; the web interface keeps showing
    redacted differences only.
  - Data files are written with owner-only permissions where the system supports it.
- **Supply chain.** Every third-party GitHub Action is pinned to a commit SHA, and a test refuses
  unpinned ones. Each release gets a CycloneDX SBOM of the installed wheel and its dependencies,
  next to the signed provenance PyPI already records (this repository, this workflow). The
  release jobs keep least privilege, also checked by a test.
- **Validation matrix** [docs/VALIDATION.md](docs/VALIDATION.md): for each platform, whether it was
  validated on real hardware, a virtual switch, the simulator or synthetic data, per level, and
  what is not validated yet.
- **Version consistency.** A test checks that the package, pyproject, README status, site
  metadata, changelog and every adapter state the same versions. The README still said 0.12.

- **GitHub Action** (`uses: lyss-project/lyss@<tag>`): runs the offline audit on the
  configurations of a repository and writes a job summary. With `require-level: N`, the job fails
  when a control of level 1..N fails. Unknown verdicts, such as automatic backups that a saved file
  cannot show, never fail the job. See [docs/CI.md](docs/CI.md).
  - Configurations and inputs are treated as untrusted:
    - inputs reach the scripts only as environment variables;
    - workflow commands are disabled while the report is printed;
    - every value from a configuration is escaped in the summary (no link, image or HTML).
  - The action installs LYSS from its own files at the pinned ref.
- **`lyss audit` for any CI:**
  - `--require-level N` (exit code 1 on a failed control);
  - `--summary FILE` (markdown, appended);
  - `--json-file FILE`;
  - `--pattern` (e.g. `"*"` for Oxidized git output, whose files have no suffix);
  - `--recursive` (hidden folders such as `.git` skipped);
  - `--skip-unrecognised`.
  - `--vendor` and `--level` now refuse unknown values. Arista EOS and Zyxel GS1900 are listed in
    the help.
- **NIS2 mapping.** Every control now also refers to the points of Article 21(2) of Directive (EU)
  2022/2555 that it supports, next to ISO/IEC 27001:2022, NIST SP 800-53 r5 and CIS Controls v8.
  The new [docs/MAPPINGS.md](docs/MAPPINGS.md) reads the same mappings from each framework (for
  example: which LYSS controls support NIS2 21(2)(h), cryptography). These references are
  informative: the author's interpretation, not legal advice. The requirements and verdicts of
  0.6.0-draft are unchanged.
- The specification document no longer calls the Level 3 controls "to be written": their
  requirements and test procedures have been complete since 0.10.0.
- **Exploited vulnerabilities watch.** `tools/kev_watch.py` compares the CISA Known Exploited
  Vulnerabilities catalog with `data/firmware.yaml`, for the platforms LYSS knows. A weekly
  read-only workflow fails when a new entry concerns one of them, and the maintainer then updates
  `firmware.yaml` from the vendor advisory. The firmware data stays curated by a person; the watch
  only says what to look at. Older entries not yet reviewed are listed too: 43 at the first run,
  almost all Cisco IOS / IOS XE.

## 0.13.0 (2026-11-07)

Production readiness. Specification unchanged (0.6.0-draft).

- **LYSS health.** Every scan records when it ran and how many switches failed. If scheduled scans
  stop (no scheduled scan within the longest gap of the schedule plus 2 hours), the dashboard shows
  a warning, and `GET /health` (no login, no switch data) returns `stale` with HTTP 503 for an
  uptime monitor. Optional heartbeat: after each scheduled scan, LYSS calls an external
  dead-man's-switch URL (Settings → Health monitoring). The URL is stored but never shown again.
- **Load test** `tools/load_test.py`: a full scan of N fictitious switches cloned from the demo lab.
  Figures in [docs/SCALE.md](docs/SCALE.md): 1,008 switches collected and assessed, no failure,
  about 110 ms of assessment per switch.
- **Threat model** [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and **versioning policy**
  [docs/VERSIONING.md](docs/VERSIONING.md), including what has to be true for 1.0.

## 0.12.0 (2026-11-07)

Current paramiko, with legacy SSH only where a switch needs it. Specification unchanged
(0.6.0-draft). Checked on simulated legacy and modern switches, on MikroTik CHR 7.25.1 and on
Arista cEOS-lab 4.37.0F (which now negotiates the post-quantum mlkem768x25519-sha256).

- **paramiko 5** (was pinned below 4.0). paramiko 5 dropped the SHA-1 algorithms that old
  switches still need, so the new `lyss.legacy_ssh` module adds back exactly three of them:
  `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1` and `ssh-rsa` host keys.
  Every connection first runs modern-only. Only a switch that has no algorithm in common gets a
  second connection with them allowed, and the scan records it ("legacy: required" in the
  negotiated algorithms, LYSS-MGMT-013). SHA-1 RSA signatures are accepted only when `ssh-rsa`
  was negotiated, and the jump host is always modern-only. This closes the low-severity paramiko
  advisory CVE-2026-44405, and SHA-1 is no longer offered on every connection as before.
- The simulator's modern switches refuse the SHA-1 algorithms, like real modern switches.

## 0.11.1 (2026-11-07)

Same content as 0.11.0, which was never published to PyPI: the release check expected the demo
to have exactly eight switches. It now compares the installed package with the repository (whole
demo lab, every adapter).

## 0.11.0 (2026-11-07, not published to PyPI)

Arista EOS firmware data and a Level 3 switch in the demo. Specification unchanged (0.6.0-draft).

- Arista EOS firmware data: the two critical EOS advisories with fixed releases, SA-0072
  (CVE-2021-28503, eAPI certificate authentication bypass) and SA-0071 (CVE-2021-28506, gNOI
  factory reset), so LYSS-VULN-001 now gives a verdict on EOS.
- Demo: a ninth switch in the simulated network, an Arista campus switch (`demo-eos-01`)
  hardened up to Level 3; Level 3 is on in the demo. The simulator speaks EOS (read-only).
- Level 3 counts only enabled access ports: a shut-down port is not an access risk (Cisco IOS,
  Arista EOS).
- Web interface and reports: Level 3 has its own colour in the topology map and the level
  badges, and the dashboard / report text says "Levels 1 to 3" when Level 3 is assessed.

## 0.10.0 (2026-11-07)

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
