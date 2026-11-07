# Security policy

LYSS handles network device credentials and security findings, so its own security matters.

## Reporting a vulnerability

Please report vulnerabilities privately, never in a public issue:

- on GitHub: **Security → Report a vulnerability** in this repository (private advisory), or
- by e-mail to **lyaazale@lyss.dev**.

Include the version, the steps to reproduce and the impact. You will receive an answer within
7 days. Please allow time for a fix before any public disclosure; reporters are credited in the
advisory unless they prefer otherwise.

## Security design

The full threat model (assets, trust boundaries, mitigations, what LYSS does not protect against)
is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

- Collection is read-only (`show` commands only) and runs over SSH.
- The web interface listens on 127.0.0.1 by default. Remote listening requires `LYSS_ALLOW_REMOTE=1`
  and should only be used behind an HTTPS reverse proxy: the interface itself speaks plain HTTP.
- Administrator password stored as a scrypt hash; 5 failed logins lock the login for 5 minutes;
  server-side sessions (HttpOnly, SameSite=Strict, 30-minute idle timeout); CSRF token and
  same-origin check on every state-changing request; strict Content-Security-Policy.
- Device, SMTP and API credentials are encrypted at rest: Windows DPAPI (current Windows user) or
  AES-256-GCM with a master key (`LYSS_MASTER_KEY` or `<data dir>/master.key`) on other systems.
  They are never sent back to the browser.
- Password hashes, keys and SNMP communities are redacted from all stored and reported evidence.
- Neighbour names received over LLDP/CDP are untrusted and are only rendered as text.

## Known limitations

- **Legacy SSH algorithms, per switch and only when needed.** LYSS uses a current paramiko (5.x),
  which no longer speaks the SHA-1 algorithms that many switches still in service require
  (Cisco SG300, older Catalyst images). `src/lyss/legacy_ssh.py` adds back exactly three of them:
  the `diffie-hellman-group14-sha1` and `diffie-hellman-group-exchange-sha1` key exchanges, and
  `ssh-rsa` (SHA-1) host-key signatures.
  - Every connection first runs with them **disabled**.
  - Only when a switch answers that it has no algorithm in common does LYSS reconnect to that
    switch with them allowed. The scan records it ("legacy: required"), and LYSS-MGMT-013 reports
    the weakness.
  - SHA-1 RSA signatures are accepted only when `ssh-rsa` itself was negotiated; paramiko's own
    RSA key class is not changed. LYSS never signs with SHA-1: it logs in with a password.
  - The jump host is always modern-only.

  This replaces the former pin of paramiko below 4.0. That pin offered SHA-1 on every connection
  and kept the low-severity advisory CVE-2026-44405 / GHSA-r374-rxx8-8654 open. Because the module
  hooks into paramiko internals, paramiko is limited to one major version (`>=5.1,<6`), and
  `tests/test_legacy_ssh.py` checks these properties against simulated legacy and modern switches.
- SSH host keys of switches are trusted on first use (TOFU), then pinned: a changed key stops the
  connection before any credential is sent. Verify the first key out of band when it matters.
- Single administrator account; no role separation yet.
- Single instance, no failover. Set a heartbeat URL (Settings → Health monitoring) or poll
  `/health` so that an external monitor warns you when scheduled scans stop.
