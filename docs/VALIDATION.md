# Validation matrix

Where each platform's checks have been verified, and what has not been verified yet. "Synthetic"
means configurations and device outputs written for the test suite. "Simulator" means the LYSS
switch simulator (`python -m lyss sim`), which answers over real SSH like the platform does.

Last reviewed: November 2026 (LYSS 0.16). To add a platform or a model, see
[TESTERS.md](TESTERS.md): a report from a real switch is the most useful contribution.

| Platform | Level 1–2 | Level 3 | Firmware data | Not validated yet |
|---|---|---|---|---|
| Cisco IOS / IOS-XE | **Real switches** (Catalyst access switches, including images that only speak SHA-1 SSH), simulator, synthetic | Synthetic | Vendor advisories, end-of-support bulletins, CISA KEV | IOS-XE on larger Catalyst families; Level 3 on a real switch |
| Cisco Small Business / Business | **Real switches** (older Small Business series, legacy SSH), simulator, synthetic | Synthetic | Vendor advisories, end-of-support bulletins | Cisco Business CBS on real hardware; Level 3 on a real switch |
| HPE Aruba AOS-S | Simulator, synthetic | Synthetic | HPE bulletin (AOS-S 16.x) | **Any real AOS-S or ProCurve switch** |
| MikroTik RouterOS | **Virtual: CHR 7.25.1** (export, state, read-only group), simulator, synthetic; RouterOS 6 synthetic only | CHR 7.25.1 (bridge DHCP snooping, ARP inspection, discovery), synthetic | Vendor advisories, CISA KEV | CRS / RouterBOARD hardware (switch chip offload) |
| SONiC | **Virtual: SONiC-VS 202505**, simulator, synthetic | Not applicable | None (no published end of support) | Hardware builds |
| Arista EOS | **Virtual: cEOS-lab 4.37.0F** (default, insecure and hardened configurations, LLDP between two switches), simulator, synthetic | Synthetic: cEOS-lab does not support DHCP snooping, ARP inspection and storm control | Arista security advisories, CISA KEV | Any physical 7000-series switch |
| Zyxel GS1900 | Not assessed (firmware only) | Not assessed | Zyxel advisory, CISA KEV | Configuration format; any real GS1900 output |

## What every platform shares

- **Test cases.** Each implemented control has synthetic test cases in which it passes and fails
  (`tests/cases`), and the suite checks that no secret reaches the evidence.
- **Remediation** (Cisco IOS, Cisco Small Business, basic HPE) is verified on the simulator: fix,
  verification over a new connection, rollback on failure. Run it on a real switch only under your
  own change management.
- **Scale** is measured on the simulator: see [SCALE.md](SCALE.md).

## Reading this table

A platform validated on a virtual switch can still behave differently on hardware: hardware
models expose different defaults, ports and features. Until a platform has been validated on real
hardware, treat its verdicts as "probably right, please confirm", and report any difference.
