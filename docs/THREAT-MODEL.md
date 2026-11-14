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
| Configurations and device state | data directory, history (encrypted by default) | Network layout; may contain hashes or reversible type 7 keys |
| Assessment results and reports | data directory (encrypted by default), exports | A list of the weaknesses of each switch |
| Jump host key | path in Settings | Access to the jump host |
| SMTP, CISO Assistant, SIEM credentials | settings (encrypted) | Access to those services |
| Administrator password | settings (scrypt hash) | Control of LYSS, including remediation if enabled |
| Pinned SSH host keys | `known_hosts` in the data directory | Protection against an impostor switch |

## Trust boundaries and threats

### 1. The network between LYSS and the switches
- **Threat:** someone impersonates a switch (man in the middle) to capture the credentials.
  **Mitigation:** SSH host keys are trusted on first use and then pinned. A changed key stops the
  connection before any credential is sent. Verify the first key out of band when it matters.
- **Threat:** a device announces itself as a switch (LLDP/CDP, SSH banner) to receive the shared
  credentials at its first scan. **Mitigation:** discovered devices are never added or scanned
  without the administrator's confirmation. "Scan right away" is off by default, and candidates
  outside the configured sites are flagged. **Residual risk:** first contact trusts the key; check
  the addresses before adding devices with a shared credential profile.
- **Threat:** a downgrade to weak SSH algorithms. **Mitigation:** modern algorithms only. SHA-1 is
  used only for a switch that offers nothing else, after a modern-only attempt fails; the scan
  records it, and LYSS-MGMT-013 reports it (see SECURITY.md).
- **Threat:** the switch account is abused. **Mitigation:** LYSS sends only the fixed read-only
  commands (`show`, `display`, `print`) of `collector.COMMANDS`; users cannot add commands. Use a read-only account:
  [docs/ACCOUNTS.md](ACCOUNTS.md) shows the least-privilege account for each platform and says
  where it was verified (not yet for Juniper EX and Huawei).

### 2. Data coming from switches (untrusted input)
- **Threat:** a malicious device sends crafted text (an LLDP/CDP name, a banner, a configuration) to
  attack the web interface or the reports. **Mitigation:**
  - neighbour names and every switch output are rendered as text only (Jinja2 autoescaping,
    `textContent` in scripts);
  - the strict Content-Security-Policy forbids inline scripts.
- **Threat:** crafted text makes a failing switch look compliant. **Mitigation:**
  - text a neighbour sends (CDP/LLDP fields) cannot imitate a device-state section: collected
    section headers carry a random value per collection;
  - a configuration matching two platforms is not guessed;
  - banner text is never read as configuration;
  - a failed state command never counts as evidence of absence;
  - long lines are capped and the patterns are written to run in linear time, so a crafted line
    cannot stall an assessment (tests time the redaction, platform detection, neighbour parsers and
    device-state rules on worst-case lines);
  - output read from a switch is capped at 20 MB per command, on every platform;
  - control characters (terminal escape sequences) are removed from evidence and from error
    messages before they are stored, printed or logged.
- **Residual risk:** a neighbour that announces text imitating the switch's own prompt can cut one
  command's output short (neighbours missing from the topology; on Cisco Small Business the
  following state command can be misread). The prompt check is not yet anchored on every platform.
- **Threat:** secrets end up in reports. **Mitigation:** passwords, keys, SNMP communities and hashes
  are redacted from all evidence before it is stored or shown; only well-known defaults (such as
  the community `public`) stay visible, so that they can be reported. Tests check every test case
  of every platform for this. **Residual risk:** redaction works by known keywords and formats; a
  secret format LYSS does not know could stay visible. Review a report before sharing it outside
  the team, and report any miss (SECURITY.md).

### 3. The web interface
- **Threat:** access from the network. **Mitigation:**
  - it listens on 127.0.0.1 only; listening elsewhere requires `LYSS_ALLOW_REMOTE=1`;
  - in that remote mode, creating the administrator needs a one-time token printed on the
    console, so whoever reaches the port first cannot claim the instance;
  - it speaks plain HTTP, so remote use belongs behind an HTTPS reverse proxy.
- **Threat:** a web page visited by the administrator reaches LYSS through DNS rebinding (its own
  name resolving to 127.0.0.1). **Mitigation:** requests for any host name other than 127.0.0.1,
  localhost, [::1] and the names in `LYSS_ALLOWED_HOSTS` are refused.
- **Threat:** password guessing, session theft, cross-site requests. **Mitigation:**
  - administrator password hashed with scrypt;
  - 5 failed logins lock the login for 5 minutes, attempts in progress included. **Residual
    risk:** the lock is global, so a local process (in remote mode: any host that reaches the
    port) can keep the administrator locked out;
  - sessions are server-side, cookies HttpOnly and SameSite=Strict, with a 30-minute idle timeout;
  - every state-changing request needs a CSRF token and a same-origin check.
- **Threat:** secrets leak through the interface. **Mitigation:** stored secrets are never sent back
  to the browser. Settings show "configured"; the heartbeat URL is hidden too. A stored password
  or token is only used for the destination it was saved for: changing the server, URL, account
  or a switch's address removes it, and it must be entered again.
- **Residual risk:** browsers share cookies between all ports of one host name. Another web
  service on 127.0.0.1 opened in the same browser receives the LYSS session cookie; do not run
  untrusted local web services on the machine that runs LYSS.
- `/health` needs no login, by design. It returns only LYSS's own state: times, counts and the
  version, with no switch name, address or result.

### 4. The machine running LYSS
- **Threat:** another user, or malware, reads the data directory. **Mitigation:**
  - secrets are encrypted at rest: Windows DPAPI, bound to the Windows user, or AES-256-GCM with a
    master key from `LYSS_MASTER_KEY` or a `master.key` file created with mode 0600;
  - **residual risk:** malware running as the same user can decrypt them. Run LYSS on an
    administration machine, not a shared desktop.
- **Threat:** configurations and results are read from the disk or from a copy of the data
  directory. **Mitigation:**
  - collected configurations, device state, archived configuration versions and results are
    encrypted at rest by default, with the same key as the credentials (Settings > Data
    protection). Files are written with owner-only permissions where the system supports it;
  - an optional retention period removes old configuration versions and scan history; the current
    configuration is always kept.
  - **Residual risk:** the same as for credentials. With AES-GCM, keep the master key outside the
    data directory (`LYSS_MASTER_KEY`), or a copy of the directory includes its own key. The
    inventory, settings, topology data and scan history (verdicts only) stay in plain JSON. Disk
    encryption is still recommended.

### 5. Remediation and firmware upgrades (the only features that write to switches)
- Both are **off by default**, each with its own setting.
- Remediation offers low-risk fixes only, previewed, applied one switch at a time, verified over a
  new connection, rolled back automatically on error (a failed save included), and logged. A rejected rollback is reported
  as such and nothing is saved; the switch is then refused for further changes until a new scan.
- Its parameters (syslog and NTP addresses, banner) are validated when saved and again when fixes
  are built, and the collector refuses any command containing control characters (no line can
  be injected).
- **Saving saves everything:** "write memory" also makes permanent any unsaved change another
  administrator left in the running configuration. Check that running and saved configurations
  agree before using remediation or a firmware upgrade.
- **It needs a write-capable account**, which LYSS otherwise never needs. In production, keep it
  off, or put it under your change management with a separate account.

### 6. Integrations
- **SMTP, CISO Assistant, SIEM:** off unless configured; their credentials are encrypted at rest.
- **Rescan on change** trusts the SIEM's alerts: whoever can send forged syslog to the SIEM in a
  switch's name can trigger rescans of that switch (read-only logins) and delay scheduled scans.
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
