# Scale: how many switches one LYSS instance handles

LYSS collects switches in parallel over read-only SSH (8 at a time by default), then assesses each
configuration locally. Two sets of figures follow: a load test on simulated switches (repeatable
by anyone) and a real network.

## Load test on simulated switches

`python tools/load_test.py --switches N [--workers W] [--level 3]` builds N fictitious switches by
cloning the demo lab. The mix covers all six SSH platforms: Cisco IOS, Cisco Business, HPE Aruba,
MikroTik, SONiC and Arista. About a fifth of the switches are legacy and only speak SHA-1 SSH, so
they need the second, legacy connection. The tool then runs a complete scan: collection, audit and
history.

| Switches | Parallel collections | Collected | Collection time | Throughput | Audit time per switch |
|---|---|---|---|---|---|
| 27 | 8 | 27/27 | 4.8 s | 337 switches/min | 113 ms |
| 252 | 8 | 252/252 | 42 s | 358 switches/min | 110 ms |
| 252 | 16 (Level 3 on) | 252/252 | 29 s | 520 switches/min | 108 ms |
| 1,008 | 16 | 1,008/1,008 | 339 s | 179 switches/min | 112 ms |

These runs used LYSS 0.12, Python 3.11 and Windows 11 on a laptop (16 logical CPUs), in
November 2026. LYSS and the simulator run in the same Python process, so the simulator competes with
LYSS for the CPU. That is why throughput falls at 1,008 switches. The figures are a check of LYSS's
own overhead, not a promise for a real network.

**What they show:**
- LYSS's own cost is small: about 110 ms of audit per switch, whatever the fleet size.
- No collection failed, even at 1,008 switches.

## A real network

On 9 real switches (Cisco Catalyst 1000, SG300, SG350), reached through an SSH jump host, a full
scan takes about 26 seconds. Real switches are much slower than the simulator. An old SG300 needs
several seconds to answer a `show running-config`, and it refuses SSH sessions opened in quick
succession, so LYSS waits and retries.

**Rough estimate for a large real fleet:** about 15–20 seconds per legacy switch, divided by the
number of parallel collections.
- 1,000 such switches: roughly 30–40 minutes with 8 parallel collections, 15–20 minutes with 16.
- Modern switches are faster.

This is an estimate, not a measurement. Measure your own network with a scheduled night scan.

## Limits to know

- **One instance, one process.** There is no multi-instance mode or failover yet. For several sites,
  run one LYSS per site, or use the site filters of one instance.
- **Jump host.** Through an OpenSSH jump host, the server's `MaxSessions` (10 by default) limits
  the number of channels per connection. LYSS shares one connection and opens one channel per switch.
- **Old switches** slow down when they are scanned repeatedly within minutes. Scheduled scans,
  hours apart, avoid this.
- **Memory** was not measured reliably in these tests.
