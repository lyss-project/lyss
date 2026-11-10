# A dedicated account for LYSS

LYSS only reads: it logs in over SSH, runs the commands listed in `src/lyss/collector.py`
(`COMMANDS`) and logs out. Give it **its own account**, never a shared administrator login, so
that its sessions are easy to spot in the switch and SIEM logs and its rights stay minimal.

General rules, whatever the platform:

- one account per purpose: `lyss-audit` for scans; a separate administrator account only if you
  use LYSS remediation (it needs configuration rights);
- a long random password (LYSS stores it encrypted: DPAPI on Windows, AES-GCM elsewhere), and the
  strongest hash the platform offers;
- allow the account only from the LYSS host (management ACL, `available-from`, control-plane ACL);
- LYSS pins each switch's SSH host key at the first scan and refuses a changed key.

| Platform | Least rights that work | Verified |
|---|---|---|
| MikroTik RouterOS | group with `ssh,read` only (no `write`, no `sensitive`) | yes, CHR 7.25.1: same verdicts as `admin`, changes refused |
| SONiC | plain Linux user, not in `sudo` | yes, SONiC-VS 202505: same data as `admin`, changes refused |
| Arista EOS | privilege 15 with role `network-operator`, command authorization on | yes, cEOS-lab 4.37.0F: full collection, configuration mode refused |
| Cisco IOS / IOS-XE | privilege 15 (`show running-config`), restricted by TACACS+ command authorization | privilege 15 tested; restriction recommended, not lab-tested |
| Cisco Small Business / Business | privilege 15 | tested; lower levels not yet (reports welcome) |
| HPE Aruba AOS-S | manager | simulator only (reports from real switches welcome) |
| HPE Aruba AOS-CX | local user in a custom user group that permits `show` commands only (the built-in `operators` group cannot run `show running-config`) | yes, AOS-CX 10.17 simulator: same verdicts as `admin`, configuration commands refused |
| Huawei S series (VRP) | local user of level 3 with SSH only (`display current-configuration` needs level 3) | not yet (preview adapter, reports welcome) |
| Juniper EX (Junos) | login class with `view view-configuration` only | not yet (preview adapter, reports welcome) |

## MikroTik RouterOS

```
/user group add name=lyss-read comment="LYSS audit, read-only" policy=ssh,read,!local,!telnet,!ftp,!reboot,!write,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api
/user add name=lyss-audit group=lyss-read address=<lyss-host>/32 comment="LYSS audit"
/password    ! or set the password from Winbox; avoid typing it in a command line
```

- Do **not** use the built-in `read` group: it includes the `sensitive` policy, which lets an
  account read RADIUS secrets and other credentials back.
- Without `sensitive`, `/export` never contains secrets, and LYSS never asks for `show-sensitive`.
- Checked on CHR 7.25.1: the `lyss-read` account collects everything LYSS needs (identical
  verdicts to `admin`); `/ip service disable telnet` is refused with "not enough permissions".

## SONiC

```
sudo useradd -m -s /bin/bash -c "LYSS audit, read-only" lyss-audit
sudo passwd lyss-audit
```

- The account must not be in the `sudo` (or `docker`) group: LYSS runs `show` commands and
  `ss -tlnH`, none of which needs root.
- Checked on SONiC-VS 202505: a non-sudo account reads the complete configuration (identical to
  `admin`), and `config ...` commands are refused ("Root privileges are required").
- **Be aware:** this also means that **every local account on a SONiC switch can read the whole
  config_db**, including TACACS+/RADIUS keys stored in cleartext (LYSS-AUTH-004). Keep local
  accounts to a minimum and prefer TACACS+ for people.
- Restrict SSH to the administration network with a control-plane ACL (LYSS-MGMT-010).

## Arista EOS

```
username lyss-audit privilege 15 role network-operator secret <password>
aaa authorization exec default local
aaa authorization commands all default local
```

- `network-operator` is EOS's built-in read-only role. EOS **enforces roles only with command
  authorization** (`aaa authorization commands all default ...`): without it, a privilege 15
  account can configure the switch whatever its role.
- With TACACS+, give the LYSS account a read-only role on the server instead, and keep command
  authorization pointed at it.
- Checked on cEOS-lab 4.37.0F: the `lyss-audit` account collects everything LYSS needs, and it
  cannot even enter configuration mode.

## HPE Aruba AOS-CX

```
user-group lyss-ro
    10 permit cli command "show .*"
user lyss-audit group lyss-ro password
```

- A custom user group: every command its rules do not permit is refused. `show .*` lets LYSS run
  `show running-config` and the state commands; `configure terminal` and `copy` answer
  "Command not allowed".
- Do **not** use the built-in `operators` group: it cannot run `show running-config` (the switch
  answers `% Command incomplete.`). LYSS reports that as a collection error and assesses nothing.
- An account's group cannot be changed afterwards: delete the user and create it again.
- The configuration shows RADIUS, TACACS+ and SNMPv3 keys as `ciphertext`, encrypted with the export
  password (`!export-password: default` unless you set one): anyone who reads the configuration
  with that key can recover them. Set a custom export password.
- Checked on the AOS-CX 10.17 simulator: `lyss-audit` gets the same verdicts as `admin`;
  not yet on a physical switch.

## Huawei S series (VRP)

```
aaa
 local-user lyss-audit password irreversible-cipher <password>
 local-user lyss-audit privilege level 3
 local-user lyss-audit service-type ssh
```

- On VRP, level 3 is the lowest level allowed to run `display current-configuration`. Check on your
  release that this level cannot change the configuration (`system-view` refused); if it can, use
  command authorization through HWTACACS to limit the account to `display` commands.
- Not yet checked on a real switch (preview adapter).

## Juniper EX (Junos)

```
set system login class lyss-audit permissions [ view view-configuration ]
set system login class lyss-audit idle-timeout 10
set system login user lyss-audit class lyss-audit authentication plain-text-password
```

- `view` and `view-configuration` let the account run `show` commands and read the configuration,
  but not change it. Without the `secret` permission Junos hides password hashes and keys
  ("SECRET-DATA"): that is safer, but LYSS-AUTH-002 (hash strength) then stays unknown.
- LYSS reads `show configuration | display inheritance | display set`, so settings inherited from
  configuration groups are assessed too.
- Not yet checked on a real switch or vJunos-switch (preview adapter).

## Cisco IOS / IOS-XE (Catalyst)

LYSS collects `show running-config`, which IOS shows in full only at privilege 15.

```
username lyss-audit privilege 15 algorithm-type scrypt secret <long-random-password>
```

- Never reuse an existing account with a type 0 or type 7 password: LYSS-AUTH-003 fails on it,
  and LYSS itself would then log in with a weak credential.
- With TACACS+, authorize only what LYSS sends: `show *` and `terminal length 0` /
  `terminal width 511` (sent by netmiko at login), and deny everything else (command
  authorization for level 15). This is the closest IOS gets to a read-only privilege-15 account.
- Limit the `vty` lines to the LYSS host and the administration network (`access-class`).

## Cisco Small Business / Business (SG, CBS)

```
username lyss-audit privilege 15 password <long-random-password>
```

- The switch stores it as a hash; LYSS logs in through the "User Name:" prompt like a person.
- Tested with privilege 15. If a lower level shows the full `show running-config` on your
  model, please tell us in an issue.
- Restrict management access to the administration network (management ACL, LYSS-MGMT-010).

## HPE Aruba AOS-S (ProCurve)

- LYSS so far uses a manager account (`show running-config`, `show system`, LLDP tables).
- On AOS-S 16.x, local authorization groups can limit an account to `show` commands; reports from
  real switches are welcome.
- Use `encrypt-credentials` so that keys and passwords are stored encrypted (LYSS-AUTH-004).

## Remediation

The LYSS remediation page applies low-risk fixes on Cisco IOS, Cisco SB and HPE switches only
(never on MikroTik, SONiC, Arista, AOS-CX, Huawei or Junos). It needs configuration rights: configure a **separate** credential
profile for it, and keep the scan account read-only.
