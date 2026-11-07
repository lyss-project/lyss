# Audit a saved configuration (offline, no connection)

LYSS does not need to reach your devices. Give it a configuration you saved yourself, and it
assesses it on your PC: no SSH, no account on the device, nothing sent anywhere.

```sh
pip install lyss
lyss audit --level 2 router.rsc                  # one file
lyss audit --level 2 configs/                    # every configuration in a folder, any mix of platforms
lyss audit --level 2 --json router.rsc > router-lyss.json
```

LYSS recognises the platform from the configuration's own format (RouterOS export header,
Cisco Business `config-file-header`, HPE `Configuration Editor` line, SONiC config_db keys,
Cisco IOS `version`/`service`/`line vty` lines). When it cannot tell, it says so and skips the
file: give the platform with `--vendor cisco_ios|cisco_sb|hp_procurve|mikrotik|sonic`.
`--level 2` assesses Level 1 and Level 2 controls (the default is Level 1 only). In a folder,
LYSS reads `.cfg`, `.conf`, `.txt`, `.rsc` and `.json` files.

**Without installing anything:** paste the configuration into
[lyss.dev/audit.html](https://lyss.dev/audit.html). The same engine runs inside the page
(Pyodide, served from lyss.dev); the configuration is not uploaded, and the page's
Content-Security-Policy (`connect-src 'self'`) forbids it from contacting any other server.

## Saving the configuration

| Platform | Command on the device | Notes |
|---|---|---|
| MikroTik RouterOS 7 | `/export file=router` then download `router.rsc` (Winbox/WebFig: Files) | secrets are left out by default; plain or `terse` export both work |
| MikroTik RouterOS 6 | `/export hide-sensitive file=router` | without `hide-sensitive`, RouterOS 6 exports passwords and keys |
| Cisco IOS / IOS-XE | `show running-config` (terminal capture, or `copy running-config tftp:`) | |
| Cisco Small Business / Business | `show running-config` | |
| HPE Aruba AOS-S | `show running-config` | |
| SONiC | `show runningconfiguration all > switch.json` (or a copy of `/etc/sonic/config_db.json`) | |
| Arista EOS | `show running-config` (or `copy running-config flash:switch.cfg`) | |
| Zyxel GS1900 | `show version`, or copy the text of the web page System > System Information | firmware check only (CVE-2026-7273) |

A file copied from a terminal and saved with Notepad works (LYSS ignores the byte-order mark
Notepad adds). Evidence in the LYSS report never shows passwords, keys or SNMP community names,
but the file you saved may contain some (Cisco type 7, RouterOS 6 without `hide-sensitive`):
keep it as carefully as the device itself.

## What a configuration alone can and cannot tell

Most controls are settled by the configuration. For RouterOS this works especially well: an
export lists every setting that differs from the factory defaults, so a missing
`/ip service set telnet disabled=yes` means Telnet is still on. On a test router, 13 of the 20
Level 1 + 2 controls are decided from the export alone.

What only the running device knows stays **unknown**, never guessed: which ports are actually up
or unused, services really listening, the SSH algorithms offered, NTP synchronization, per-user
idle timeouts (RouterOS does not export users), the device model when the configuration does not
name it.

## Optional: add the device state by hand

To settle those controls too, still without any connection, paste the output of the "show" /
"print" commands into a file named like the configuration with `.state.txt`: `router.rsc` +
`router.state.txt`. Put each output under a line `===== <command> =====` with the command written
exactly as below, for example:

```
===== /system resource print =====
                   uptime: 12d4h31m10s
                  version: 7.24.1 (stable)
               board-name: CRS326-24G-2S+
===== /ip service print terse =====
 0     name=ftp port=21 proto=tcp available-from= vrf=main max-sessions=20
 ...
```

You can give only some of the commands; the others simply stay unknown.

| Platform | Commands LYSS reads |
|---|---|
| MikroTik RouterOS | `/system resource print` · `/ip service print terse` · `/ip ssh print` · `/snmp print` · `/snmp community print terse` · `/system ntp client print` · `/system logging action print terse` · `/system logging print terse` · `/user print terse` · `/user aaa print` · `/radius print terse` · `/system note print` · `/interface ethernet print terse` · `/interface bridge port print terse` · `/tool mac-server mac-winbox print` · `/ip neighbor print detail` |
| Cisco IOS / IOS-XE | `show version` · `show inventory` · `show ip ssh` · `show control-plane host open-ports` · `show interfaces status` · `show ntp status` · `show lldp neighbors` · `show cdp neighbors` · `show lldp neighbors detail` · `show cdp neighbors detail` |
| Cisco Small Business / Business | `show version` · `show inventory` · `show system` · `show ip ssh` · `show services tcp-udp` · `show interfaces status` · `show interfaces configuration` · `show sntp status` · `show lldp neighbors` · `show cdp neighbors` · `show cdp neighbors detail` |
| HPE Aruba AOS-S | `show version` · `show system` · `show modules` · `show ip ssh` · `show interfaces brief` · `show lldp info remote-device` · `show cdp neighbors` |
| SONiC | `show version` · `show interfaces status` · `show ntp` · `show ssh` · `show feature status` · `show lldp table` · `ss -tlnH` |
| Arista EOS | `show version` · `show management telnet` · `show management ssh` · `show interfaces status` · `show lldp neighbors detail` · `show ntp status` |

The authoritative list is `COMMANDS` in `src/lyss/collector.py` (it is what a LYSS scan runs).
The SSH banner and the negotiated SSH algorithms come from the connection itself, so they can only
be checked by a scan.

## Backups you already have

- **Oxidized:** `lyss oxidized --url http://oxidized:8888` assesses every backed-up node
  (Cisco, HPE, MikroTik), see [integrations/oxidized](../integrations/oxidized/README.md).
- **Scheduled LYSS scans** (SSH, read-only account, see [ACCOUNTS.md](ACCOUNTS.md)) when you want
  the full picture and history for many devices.
