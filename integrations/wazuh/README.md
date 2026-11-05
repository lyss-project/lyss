# LYSS → Wazuh

LYSS sends its scan results to Wazuh as JSON events: one per switch (level, pass / fail / unknown
counts), one per failed control, one per regression or fix, one per collection error, and the
number of unmanaged switches discovered. Wazuh turns them into alerts you can search, graph and
e-mail, next to your firewall and server logs.

| Rule | Level | When |
|---|---|---|
| 100801 | 3 | a switch was assessed: `LYSS: sw1 assessed, level 1, 4 failed control(s)` |
| 100802 | 5 | a control fails (Level 2) |
| 100803 | 7 | a **Baseline** (Level 1) control fails |
| 100804 | 10 | **regression**: a control that passed now fails (configuration changed) |
| 100805 | 3 | a control that failed now passes |
| 100806 | 6 | a switch could not be collected |
| 100807 | 6 | unmanaged switches discovered on the network |
| 100808 | 3 | test event from Settings |

Fields: `lyss.event`, `lyss.device`, `lyss.host`, `lyss.site`, `lyss.control`, `lyss.control_level`,
`lyss.title`, `lyss.evidence` (first evidence line, already redacted), `lyss.iso27001`, `lyss.nist`,
`lyss.level`, `lyss.pass`, `lyss.fail`, `lyss.unknown`, `lyss.model`, `lyss.firmware`, `lyss.version`.

## 1. Install the decoder and rules on the Wazuh manager

```sh
sudo sh install.sh            # copies lyss_decoders.xml + lyss_rules.xml, checks, restarts the manager
sudo sh install.sh --remove   # uninstall
```

The script refuses to install if one of the rule ids (100800-100809) is already used, and restores
the previous state if Wazuh's configuration check fails.

## 2. Choose how events reach Wazuh

**A. Syslog (simplest).** In LYSS: Settings → SIEM events → syslog server = your Wazuh manager,
port 514, UDP or TCP. Wazuh must accept syslog from the LYSS machine, in `/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.0.2.10</allowed-ips>   <!-- the machine running LYSS -->
</remote>
```

**B. Events file + Wazuh agent.** If a Wazuh agent runs on the LYSS machine, set an events file in
LYSS (e.g. `C:\LYSS\private\lyss-events.jsonl`) and add to the agent configuration:

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\LYSS\private\lyss-events.jsonl</location>
</localfile>
```

## 3. Test

LYSS: Settings → SIEM events → **Send test event**, then in Wazuh look for rule 100808. On the
manager, without sending anything:

```sh
echo 'Nov  5 12:00:00 host lyss: {"lyss":{"event":"regression","device":"sw1","control":"LYSS-MGMT-001","title":"Telnet management access is disabled"}}' \
  | sudo /var/ossec/bin/wazuh-logtest
```

Expected: decoder `lyss`, rule 100804, level 10.

## Oxidized

`python -m lyss oxidized --url http://oxidized:8888 --events` assesses the configurations Oxidized
already backs up and sends the same events, without any SSH connection from LYSS. See
[../oxidized/README.md](../oxidized/README.md).
