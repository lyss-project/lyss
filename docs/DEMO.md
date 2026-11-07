# LYSS demo and switch simulator

LYSS ships with a **switch simulator** and a **fictitious demo network**, so you can try every
feature (collection, audit, reports, topology, discovery, remediation) without touching real
equipment. **All demo data is invented**: company "Demo Corp", host names `DEMO-*`, IPv4
documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24), MAC addresses from the
documentation block `00:00:5e:00:53:xx` (RFC 7042), fake serial numbers and secrets.

## Run the demo

```
python -m lyss demo --open
```

- Starts the nine simulated switches on `127.0.0.1:2201-2209` (SSH).
- Uses its **own data directory** (`<temp>/lyss-demo`, or `--data-dir`); the demo refuses to run in,
  or inside, your real LYSS data directory (`private/` or `LYSS_DATA_DIR`).
- At the first start it creates the organisation "Demo Corp", a credential profile for the
  simulated switches, the nine devices, and an **admin account whose random password is printed
  once** in the console. `--reset` starts again from an empty demo directory.
- Runs a first scan, recorded as a *scheduled* scan (the simulated "nightly" scan), so the
  configuration-backup control has evidence; then opens the web interface on
  `http://127.0.0.1:8766` (`--port`).
- Remediation is enabled in the demo (it only ever talks to the simulated switches), with
  example syslog/NTP servers, so fixes can be applied, verified and saved end to end.

Options: `--base-port 2301` if the SSH ports are busy, `--lab <name|folder>` for another lab.

## The demo network

| Switch | Platform | Model / firmware | Designed result |
|---|---|---|---|
| demo-core | Cisco IOS | C1000-48P-4G-L, 15.2(7)E14 | Level 2 (hardened) |
| demo-acc-01 | Cisco IOS | C1000-24P-4G-L, 15.2(7)E14 | Level 0: only a 30-minute idle timeout misses Level 1 |
| demo-acc-02 | Cisco IOS | C1000-24T-4G-L, 15.2(7)E8 | Level 0: Telnet, HTTP, SSHv1, `public` SNMP, cleartext passwords, firmware with a known-exploited vulnerability, weak SSH crypto |
| demo-sb-01 | Cisco SB | CBS350-24P-4G, 3.3.0.16 | Level 1; Level 2 gaps (management ACL, banner, unused ports, BPDU guard) |
| demo-sb-02 | Cisco SB | SG300-28P, 1.4.11.5 | Level 0: end of support, unpatchable web vulnerability, Telnet/HTTP on |
| demo-hp-01 | HPE Aruba AOS-S | 2930F JL253A, WC.16.10.0012 | Level 0: firmware before HPESBNW05156 fix, Telnet/HTTP on |
| demo-crs-01 | MikroTik RouterOS | CRS326-24G-2S+, 7.24.1 | Level 0: RouterOS factory defaults (Telnet/FTP/HTTP/API open to all, MAC-Winbox on every port, `strong-crypto=no`), one point release before the CISA KEV fixes of 7.24.2 |
| demo-leaf-01 | SONiC | Accton AS4630-54PE, 202411.45 | Level 0: well run (TACACS+, control-plane ACL, banner, syslog, NTP), but SONiC's own `public` SNMP community and a TACACS+ key stored in cleartext |

Cabling: the core switch connects the two Catalyst access switches, the CBS350 and the HPE
switch; DEMO-SB-02, DEMO-CRS-01 and demo-leaf-01 hang off DEMO-ACC-01. Neighbour tables also show a wireless access point
(DEMO-AP-01) and an unmanaged Catalyst (DEMO-LAB-SW, 198.51.100.40), which the discovery page
proposes to add.

## Simulator only

```
python -m lyss sim [--lab demo] [--base-port 2201]
```

Prints the switches and their SSH ports; log in with `lyss-demo` / `demo`. The simulated CLI
supports the read-only commands LYSS collects, configuration mode (changes are applied to the
running configuration and reflected in the `show` outputs), and saving. It imitates each platform
closely enough for LYSS and netmiko (Cisco SB: "User Name:" prompt inside the shell; HPE: "Press
any key to continue"; legacy switches only offer SHA-1 key exchange and CBC ciphers). It is not
a full switch emulator.

MikroTik and SONiC switches are read-only in the simulator (LYSS never changes them): they serve
fixed outputs for the commands LYSS collects.

Labs live in `src/lyss/sim/labs/<name>/`: `lab.yaml` (switches, cables, external neighbours) and
one `<switch>.cfg` running configuration per switch (RouterOS export, SONiC config_db JSON), plus
a `<switch>.state` file with one `===== command =====` section per command for MikroTik and SONiC.
