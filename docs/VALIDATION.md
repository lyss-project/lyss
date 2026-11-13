# Validation matrix

Where each platform's checks have been verified, and what has not been verified yet. "Synthetic"
means configurations and device outputs written for the test suite. "Simulator" means the LYSS
switch simulator (`python -m lyss sim`), which answers over real SSH like the platform does.

Last reviewed: November 2026 (LYSS 0.19). To add a platform or a model, see
[TESTERS.md](TESTERS.md): a report from a real switch is the most useful contribution.

| Platform | Support | Level 1–2 | Level 3 | Firmware data | Not validated yet |
|---|---|---|---|---|---|
| Cisco IOS / IOS-XE | **Stable** (real) | **Real switches** (Catalyst access switches, including images that only speak SHA-1 SSH), simulator, synthetic | Synthetic | Vendor advisories, end-of-support bulletins, CISA KEV | IOS-XE on larger Catalyst families; Level 3 on a real switch |
| Cisco Small Business / Business | **Stable** (real) | **Real switches** (older Small Business series, legacy SSH), simulator, synthetic | Synthetic | Vendor advisories, end-of-support bulletins | Cisco Business CBS on real hardware; Level 3 on a real switch |
| HPE Aruba AOS-S | Preview | **Real configurations** (a 2930F and a 3810M stack, checked by a user, 12/11/2026), simulator, synthetic | Real configurations (same report: DHCP snooping, ARP protection, broadcast limit), synthetic | HPE bulletin (AOS-S 16.x) | **Live collection (SSH) on a real switch**; other AOS-S and ProCurve models |
| MikroTik RouterOS | **Stable** (virtual) | **Virtual: CHR 7.25.1** (export, state, read-only group), simulator, synthetic; RouterOS 6 synthetic only | CHR 7.25.1 (bridge DHCP snooping, ARP inspection, discovery), synthetic | Vendor advisories, CISA KEV | CRS / RouterBOARD hardware (switch chip offload) |
| SONiC | **Stable** (virtual) | **Virtual: SONiC-VS 202505**, simulator, synthetic | Not applicable | None (no published end of support) | Hardware builds |
| Arista EOS | **Stable** (virtual) | **Virtual: cEOS-lab 4.37.0F** (default, insecure and hardened configurations, LLDP between two switches), simulator, synthetic | Synthetic: cEOS-lab does not support DHCP snooping, ARP inspection and storm control | Arista security advisories, CISA KEV | Any physical 7000-series switch |
| HPE Aruba AOS-CX | **Stable** (virtual) | **Virtual: AOS-CX 10.17 simulator** (collection, factory default and hardened configurations, read-only account), synthetic | Virtual: AOS-CX 10.17 simulator (DHCP snooping, 802.1X / MAC authentication, broadcast rate limit, LLDP); ARP inspection from the documentation (the virtual platform has none), synthetic | None yet | Any physical CX switch; ARP inspection; the "synchronized" line of `show ntp status` (the lab had no reachable NTP server) |
| Huawei S series (VRP) | Preview | Synthetic only (written from the VRP documentation) | Synthetic only (written from the VRP configuration and hardening guides) | None yet | **Any real S series switch**: collection, outputs, every verdict |
| Juniper EX (Junos) | Preview | Synthetic only (written from the Junos documentation; `display set` and curly-brace formats) | Synthetic only (ELS syntax from the Junos documentation; storm control unknown without a profile, as most EX models apply 80 % by default) | None yet | **Any real EX switch or vJunos-switch**: collection, outputs, every verdict |
| Zyxel GS1900 | Preview | Not assessed (firmware only) | Not assessed | Zyxel advisory, CISA KEV | Configuration format; any real GS1900 output |

## What every platform shares

- **Test cases.** Each implemented control has synthetic test cases in which it passes and fails
  (`tests/cases`), and the suite checks that no secret reaches the evidence.
- **Remediation** (Cisco IOS, Cisco Small Business, basic HPE) is verified on the simulator: fix,
  verification over a new connection, rollback on failure. Run it on a real switch only under your
  own change management.
- **Scale** is measured on the simulator: see [SCALE.md](SCALE.md).

## Reading this table

**Stable** means the Level 1 and 2 checks were verified on the vendor's own software: on real
switches ("real"), or on the vendor's official virtual image ("virtual": CHR, SONiC-VS, cEOS-lab,
AOS-CX simulator). **Preview** means written from the vendor's documentation or verified only on
the LYSS simulator. The label is also in each adapter (`support`, `tested_on`); a test keeps this
table, the README and the website in line with it. A preview platform becomes stable in a normal
release once its outputs have been confirmed on the vendor's software.

A platform validated on the vendor's virtual image can still behave differently on hardware:
hardware models expose different defaults, ports and switch-chip features. Please report any
difference. Treat the verdicts of a preview platform as "probably right, please confirm".
