# LYSS + Oxidized

[Oxidized](https://github.com/ytti/oxidized) backs up network device configurations. LYSS can assess
those backups directly: no SSH connection from LYSS, no extra account on the switches.

```sh
python -m lyss oxidized --url http://oxidized:8888                 # text report
python -m lyss oxidized --url http://oxidized:8888 --json > lyss.json
python -m lyss oxidized --url http://oxidized:8888 --events        # + SIEM events (Wazuh...)
python -m lyss oxidized --url https://host/oxidized --user lyss    # password in LYSS_OXIDIZED_PASSWORD
```

LYSS reads the Oxidized REST API (oxidized-web), read-only: `GET /nodes.json` and
`GET /node/fetch/<group>/<name>`.

| Oxidized model | LYSS adapter |
|---|---|
| `ios`, `iosxe` | Cisco IOS / IOS-XE |
| `ciscosmb` | Cisco Small Business / Business |
| `procurve` | HPE Aruba AOS-S (ProCurve) |
| `eos` | Arista EOS |
| `routeros` | MikroTik RouterOS |
| `aoscx` | HPE Aruba AOS-CX (preview) |
| `junos` | Juniper EX (Junos, preview) |
| `vrp` | Huawei S series (VRP, preview) |

Other models are listed as skipped.

**MikroTik.** The `routeros` model stores the hierarchical `/export` (LYSS rewrites it one command
per line) plus `/system resource print` as comments, which give LYSS the model and RouterOS
version for the firmware check. RouterOS exports every non-default setting, so a missing line means
the factory default: no `set telnet disabled=yes` = Telnet still on. On RouterOS 7, Oxidized runs
`/export show-sensitive` unless `remove_secret` is set: **your Oxidized backups then contain the
RADIUS secrets and SNMP passwords in cleartext**. LYSS redacts them from its reports, but consider
`remove_secret: true` (Oxidized then uses `/export hide-sensitive`) or protecting the backup store.

## What changes compared with a LYSS scan

- **Configuration only.** Controls that need the device state (services actually listening, SSH
  banner, firmware details not in the configuration) are `unknown` unless the configuration settles
  them. A full LYSS scan over SSH gives every verdict.
- **Backups (LYSS-BKP-001).** A successful Oxidized backup less than 7 days old is accepted as the
  automatic configuration backup the control requires; an older one fails it.
- **Hidden secrets.** With Oxidized's `remove_secret`, password and key lines read
  `<secret hidden>`: how they are stored cannot be checked, so those verdicts are `unknown` with a
  note, never a false pass or fail.

## Oxidized on Docker

The REST API listens on port 8888 inside the container (`rest: 0.0.0.0:8888` in the Oxidized
config). Publish it to the LYSS machine only, or put it behind your reverse proxy with
authentication. Oxidized starts its API only once `router.db` contains at least one usable node.
