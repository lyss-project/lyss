# Threat model of the LYSS tool

LYSS holds read-only credentials for a whole switch fleet, and it stores the configurations of
those switches. This document lists what it protects, from whom, how, and what remains up to you.
To report a vulnerability, see [SECURITY.md](../SECURITY.md).

It describes the design as it is today. It is not a guarantee or a certification: LYSS is
provided without warranty (see [LICENSE](../LICENSE)), and you remain responsible for how you
deploy it.

## What LYSS holds (assets)

| Asset | Where | Why it matters |
|---|---|---|
| Switch credentials (read-only account) | data directory, `devices.json` / profiles | Read access to every switch |
| Configurations and device state | data directory, history | Network layout; may contain hashes or reversible type 7 keys |
| Assessment results and reports | data directory, exports | A list of the weaknesses of each switch |
| Jump host key | path in Settings | Access to the jump host |
| SMTP, CISO Assistant, SIEM credentials | settings (encrypted) | Access to those services |
| Administrator password | settings (scrypt hash) | Control of LYSS, including remediation if enabled |
| Pinned SSH host keys | `known_hosts` in the data directory | Protection against an impostor switch |

## Trust boundaries and threats

### 1. The network between LYSS and the switches
- **Threat:** someone impersonates a switch (man in the middle) to capture the credentials.
  **Mitigation:** SSH host keys are trusted on first use and then pinned. A changed key stops the
  connection before any credential is sent. Verify the first key out of band when it matters.
- **Threat:** a downgrade to weak SSH algorithms. **Mitigation:** modern algorithms only. SHA-1 is
  used only for a switch that offers nothing else, after a modern-only attempt fails; the scan
  records it, and LYSS-MGMT-013 reports it (see SECURITY.md).
- **Threat:** the switch account is abused. **Mitigation:** LYSS sends only the fixed `show` /
  `print` commands of `collector.COMMANDS`; users cannot add commands. Use a read-only account:
  [docs/ACCOUNTS.md](ACCOUNTS.md) shows the least-privilege account for each platform, verified in
  the lab.

### 2. Data coming from switches (untrusted input)
- **Threat:** a malicious device sends crafted text (an LLDP/CDP name, a banner, a configuration) to
  attack the web interface or the reports. **Mitigation:**
  - neighbour names and every switch output are rendered as text only (Jinja2 autoescaping,
    `textContent` in scripts);
  - the strict Content-Security-Policy forbids inline scripts.
- **Threat:** secrets end up in reports. **Mitigation:** passwords, keys, SNMP communities and hashes
  are redacted from all evidence before it is stored or shown; only well-known defaults (such as
  the community `public`) stay visible, so that they can be reported. Tests check every test case
  of every platform for this.

### 3. The web interface
- **Threat:** access from the network. **Mitigation:**
  - it listens on 127.0.0.1 only; listening elsewhere requires `LYSS_ALLOW_REMOTE=1`;
  - it speaks plain HTTP, so remote use belongs behind an HTTPS reverse proxy.
- **Threat:** password guessing, session theft, cross-site requests. **Mitigation:**
  - administrator password hashed with scrypt;
  - 5 failed logins lock the login for 5 minutes;
  - sessions are server-side, cookies HttpOnly and SameSite=Strict, with a 30-minute idle timeout;
  - every state-changing request needs a CSRF token and a same-origin check.
- **Threat:** secrets leak through the interface. **Mitigation:** stored secrets are never sent back
  to the browser. Settings show "configured"; the heartbeat URL is hidden too.
- `/health` needs no login, by design. It returns only LYSS's own state: times, counts and the
  version, with no switch name, address or result.

### 4. The machine running LYSS
- **Threat:** another user, or malware, reads the data directory. **Mitigation:**
  - secrets are encrypted at rest: Windows DPAPI, bound to the Windows user, or AES-256-GCM with a
    master key from `LYSS_MASTER_KEY` or a `master.key` file created with mode 0600;
  - **residual risk:** malware running as the same user can decrypt them. Run LYSS on an
    administration machine, not a shared desktop.
- **Threat:** configurations and results are read. They are **not** encrypted at rest. Protect
  the data directory like the switch configurations themselves (disk encryption, access rights).

### 5. Remediation (the only feature that writes to switches)
- It is **off by default**, and enabled only in Settings.
- It offers low-risk fixes only, previewed, applied one switch at a time, verified over a new
  connection, rolled back automatically on error, and logged.
- Its parameters (syslog and NTP addresses, banner) are validated.
- **It needs a write-capable account**, which LYSS otherwise never needs. In production, keep it
  off, or put it under your change management with a separate account.

### 6. Integrations
- **SMTP, CISO Assistant, SIEM:** off unless configured; their credentials are encrypted at rest.
- **The jump host connection** is always modern-only, and its host key is pinned too.

### 7. Supply chain
- **PyPI:** releases are published by GitHub Actions with PyPI Trusted Publishing. No token is
  stored, and every release needs the maintainer's approval.
- **Monitoring:** Dependabot watches the dependencies, and the export to the public repository runs
  gitleaks.
- **Browser audit:** the in-browser audit (lyss.dev/audit.html) serves Pyodide from lyss.dev
  itself, every file pinned by SHA-256. Its Content-Security-Policy (`connect-src 'self'`) stops
  the page from sending a configuration anywhere.

## What LYSS does not protect against
- A compromised administrator account, or a compromised machine running LYSS.
- A switch whose first SSH contact was already intercepted, before its key was pinned.
- The confidentiality of configurations exported by you (reports, JSON) after they leave LYSS.
- Availability: there is a single instance. Configure the heartbeat (Settings > Health monitoring)
  so an external monitor warns you when scheduled scans stop.
