# Management reachability

A switch configuration can say "SSH only from the admin network", but an access list on the wrong
line, a firewall rule or a forgotten VLAN interface can still make management reachable from a user
PC. The reachability probe checks it from the network itself.

## 1. List the switch addresses

On the LYSS machine:

```sh
python -m lyss reachability targets --out switches.txt
```

This lists the switches' IP addresses only: no names and no credentials. Switches added by host
name are left out, because the probe takes addresses only. The Reachability page shows the same
steps.

## 2. Probe from the network to test

On a PC of that network (a user VLAN, the Wi-Fi, a branch office), with LYSS 0.15 or later
installed (`pip install --upgrade lyss`):

```sh
lyss probe --targets-file switches.txt
```

**What the probe does:**
- For every address, it opens and then closes a TCP connection to each management port: 22
  SSH, 23 Telnet, 80/8080 HTTP, 443/8443 HTTPS, 830 NETCONF, 8291 Winbox, 8728/8729 RouterOS API.
- It sends no data and no credentials, and runs no exploit. A switch logs at most a connection
  attempt.
- It refuses ranges, host names, the "any" address, broadcast and multicast addresses, and more
  than 32 ports: it is a management check, not a port scanner.
- It writes `lyss-reachability.json`. The file contains:
  - each address, port and state: open, closed, filtered or error;
  - the probe PC's own address for open ports;
  - the probe PC's host name;
  - the date and the LYSS version.

`--ports 22,23` limits the ports. `--workers` and `--timeout` set the pace.

**Only probe networks and switches you are responsible for.** A connection attempt to a management
port can look like a scan to a firewall or an intrusion detection system: warn the people who
watch them first.

## 3. Import the result

Use the **Reachability** page, or run:

```sh
python -m lyss reachability import lyss-reachability.json --label "User VLAN 20"
```

When importing, say whether that network **is allowed** to manage the switches. By default it is
not; tick "allowed" (or use `--authorized`) for an admin network.

## Effect on the assessment

Probes of the last 90 days are evidence in every assessment:

| Observation | Control |
|---|---|
| A management port answers from a network that is not allowed to manage | LYSS-MGMT-010 fails |
| Telnet (TCP 23) answers, from any network | LYSS-MGMT-001 fails |
| Plain HTTP (TCP 80 or 8080) answers, from any network | LYSS-MGMT-003 fails |

The evidence names the network, the port and the date. **A probe can only make a control fail,
never pass**: a port closed from one PC proves nothing about the others.

**What is kept from a file:**
- An import keeps only the open management ports of switches that are in the inventory, each
  matched by its inventory address. A switch's other addresses (VLAN interfaces) are not matched.
- The test date comes from the file, but a date in the future is replaced by the import date.
- At most the 30 most recent imports are kept; imports older than 90 days are removed first.
- Probe results are encrypted at rest like the other results.

**Re-assessment:**
- Importing or deleting from the web page re-assesses the switches right away, unless a scan, a
  fix or a firmware upgrade is running; then the next scan uses it.
- The command line (`lyss reachability import`, `lyss reachability delete <id>`) leaves it to the
  next scan.
