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

- `paramiko` is pinned below 4.0 because legacy switches only support SHA-1 key exchanges, which
  paramiko 4 removed. LYSS offers modern algorithms first; the legacy ones are only negotiated
  when the switch supports nothing better, and that weakness is reported (LYSS-MGMT-013).
  This is also why the low-severity advisory CVE-2026-44405 / GHSA-r374-rxx8-8654 ("paramiko
  allows SHA-1 in RSA signatures", CVSS 3.4) is accepted rather than fixed by paramiko 5: version 5
  removes `ssh-rsa` signatures with no opt-in, and legacy switches offer only `ssh-rsa` host keys,
  so LYSS could no longer audit them. Exploiting it would need a live SHA-1 signature forgery
  during the handshake from the local network; LYSS also pins host keys and reports `ssh-rsa` as a
  LYSS-MGMT-013 failure. Revisited when paramiko offers an explicit legacy opt-in.
- SSH host keys of switches are trusted on first use (TOFU), then pinned: a changed key stops the
  connection before any credential is sent. Verify the first key out of band when it matters.
- Single administrator account; no role separation yet.
