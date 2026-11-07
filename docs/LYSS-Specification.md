<!-- Generated from spec/lyss-spec.yaml by tools/build_spec.py. Do not edit by hand. -->

# LYSS Specification: security controls for network switches

**Version 0.6.0-draft** · Status: draft · Licence: [CC BY 4.0](../LICENSE-SPEC) · Author: Mouad Lyaazale

## 1. Scope

LYSS (Lyaazale Switch Security) defines, once and independently of any vendor, what a securely
managed network switch looks like, and how conformance is assessed and claimed. It applies to
managed Ethernet switches of any vendor, whatever their age. How each control is verified on a
given platform is defined by *adapters*, maintained separately from this document.

This document is generated from `spec/lyss-spec.yaml`, which is the normative source.

## 2. Conventions and terms

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in
RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

- **Control**: a security requirement with a stable identifier (`LYSS-<DOMAIN>-<NNN>`), a level,
  a statement, a rationale and a vendor-neutral test procedure.
- **Adapter**: the interpretation of the controls for one platform family (how to check, how to fix).
- **Evidence**: the data a verdict is based on: `config` (running configuration), `state` (read-only
  device state such as listening ports, SSH banner, port status), `external_data` (vendor advisories,
  end-of-life bulletins), `backup_system` (configuration archive or attested backup system).
- **Verdict**: the result of one control on one device: `pass`, `fail`, `unknown` or `not_applicable`.

## 3. Verdicts

- `pass`: the evidence shows that the control is met.
- `fail`: the evidence shows that the control is not met.
- `unknown`: the available evidence cannot decide. An assessment MUST report `unknown` rather than
  guess, and MUST NOT turn a missing evidence into a pass.
- `not_applicable`: the control does not apply to the platform (e.g. the feature does not exist).

## 4. Conformance levels

| Level | Name | Intent |
|---|---|---|
| 1 | Baseline | the minimum every managed switch must meet: no cleartext management, no default or recoverable credentials, supported firmware, automatic backups. |
| 2 | Hardened | a hardened management plane: central authentication, restricted and modern management access, remote logging and time, basic access-port hygiene. |
| 3 | Advanced | access-layer protections against attacks from user ports: DHCP snooping, ARP inspection, port authentication, storm control, no neighbor discovery towards users. |

A device is **LYSS Level N conformant** when every control of levels 1 to N is `pass` or
`not_applicable`. An `unknown` verdict is not a pass. A conformance claim MUST state the device,
the specification version, the assessment date and the tool and version used, for example:

> core-sw-01 is LYSS Level 1 conformant (specification 0.6.0-draft), assessed 2026-11-03 with LYSS 0.3.0.

A claim is valid for the configuration and firmware assessed; any change requires a new assessment.

## 5. Control catalogue

| ID | Level | Title |
|---|---|---|
| [LYSS-MGMT-001](#lyss-mgmt-001) | 1 | Telnet management access is disabled |
| [LYSS-MGMT-002](#lyss-mgmt-002) | 1 | SSH management uses protocol version 2 only |
| [LYSS-MGMT-003](#lyss-mgmt-003) | 1 | Cleartext HTTP management is disabled |
| [LYSS-MGMT-004](#lyss-mgmt-004) | 1 | Idle management sessions time out within 10 minutes |
| [LYSS-AUTH-001](#lyss-auth-001) | 1 | No default or well-known SNMP community strings |
| [LYSS-AUTH-002](#lyss-auth-002) | 1 | Privileged-mode password is stored as a strong hash |
| [LYSS-AUTH-003](#lyss-auth-003) | 1 | Local account passwords are not stored in cleartext or reversible form |
| [LYSS-AUTH-004](#lyss-auth-004) | 1 | AAA shared secrets (RADIUS/TACACS+) are not stored in cleartext |
| [LYSS-VULN-001](#lyss-vuln-001) | 1 | Firmware is vendor-supported and free of known critical vulnerabilities |
| [LYSS-BKP-001](#lyss-bkp-001) | 1 | Configuration is backed up automatically |
| [LYSS-AUTH-010](#lyss-auth-010) | 2 | Administrative logins use central AAA (RADIUS/TACACS+) with local fallback only |
| [LYSS-AUTH-011](#lyss-auth-011) | 2 | SNMP uses v3 with authentication and privacy or is disabled |
| [LYSS-MGMT-010](#lyss-mgmt-010) | 2 | Management access is restricted to authorized source networks |
| [LYSS-MGMT-011](#lyss-mgmt-011) | 2 | Management interface is on a dedicated management VLAN |
| [LYSS-MGMT-012](#lyss-mgmt-012) | 2 | A legal warning banner is shown before login |
| [LYSS-MGMT-013](#lyss-mgmt-013) | 2 | SSH uses modern key exchange, ciphers and host keys |
| [LYSS-LOG-010](#lyss-log-010) | 2 | Events are sent to a remote syslog/SIEM server |
| [LYSS-LOG-011](#lyss-log-011) | 2 | Clock is synchronized with NTP/SNTP |
| [LYSS-ACC-010](#lyss-acc-010) | 2 | Unused ports are administratively disabled |
| [LYSS-ACC-011](#lyss-acc-011) | 2 | Edge ports are protected against rogue spanning-tree participants (BPDU guard) |
| [LYSS-ACC-020](#lyss-acc-020) | 3 | DHCP snooping is enabled on user VLANs |
| [LYSS-ACC-021](#lyss-acc-021) | 3 | Dynamic ARP inspection is enabled on user VLANs |
| [LYSS-ACC-022](#lyss-acc-022) | 3 | Access ports require 802.1X or MAC authentication |
| [LYSS-ACC-023](#lyss-acc-023) | 3 | Storm control limits broadcast traffic on access ports |
| [LYSS-ACC-024](#lyss-acc-024) | 3 | Neighbor discovery (CDP/LLDP) is not sent on untrusted access ports |

### Level 1: Baseline

#### LYSS-MGMT-001

**Telnet management access is disabled**

- **Requirement.** The switch does not accept management sessions over Telnet.
- **Rationale.** Telnet sends credentials and session data in cleartext; anyone on the path can capture administrator passwords.
- **Test procedure.** Check that no management service listens on TCP 23 (device state) and that no remote CLI line or service is configured to accept Telnet (configuration). Fail if either shows Telnet accepted. Unknown if the platform hides the Telnet default and no device state is available.
- **Evidence.** config, state
- **References (informative).** ISO/IEC 27001:2022 A.8.20, A.8.21, A.8.24 · NIST SP 800-53 r5 CM-7, SC-8, AC-17(2) · CIS Controls v8 4.8, 12.6

#### LYSS-MGMT-002

**SSH management uses protocol version 2 only**

- **Requirement.** SSH is the remote CLI protocol and SSH protocol version 1 is not accepted.
- **Rationale.** SSHv1 has known cryptographic weaknesses and must not be negotiable.
- **Test procedure.** Read the SSH identification string of the switch: "SSH-2.0-" passes, "SSH-1.99-" or "SSH-1.5-" fails. Without device state, an explicit "version 2 only" setting passes.
- **Evidence.** config, state
- **References (informative).** ISO/IEC 27001:2022 A.8.21, A.8.24 · NIST SP 800-53 r5 SC-8, SC-13, AC-17(2) · CIS Controls v8 12.6

#### LYSS-MGMT-003

**Cleartext HTTP management is disabled**

- **Requirement.** The web management interface, if enabled, is only reachable over HTTPS.
- **Rationale.** Plain HTTP exposes administrator credentials and session cookies.
- **Test procedure.** Fail if a management web service listens on TCP 80 (device state) or the plain HTTP server is enabled in the configuration, including when it is enabled by default and not disabled.
- **Evidence.** config, state
- **References (informative).** ISO/IEC 27001:2022 A.8.21, A.8.24 · NIST SP 800-53 r5 CM-7, SC-8, AC-17(2) · CIS Controls v8 4.8, 12.6

#### LYSS-MGMT-004

**Idle management sessions time out within 10 minutes**

- **Requirement.** Interactive CLI sessions (console and remote) are closed after at most 10 minutes of inactivity.
- **Rationale.** Abandoned privileged sessions can be reused by anyone with access to the terminal or session.
- **Test procedure.** Determine the effective idle timeout of every console and remote CLI line: the configured value, or the platform's documented default when none is configured. Fail if any effective timeout is disabled (0, never) or above the parameter. For example, Cisco IOS and Cisco Business default to 10 minutes (pass when unset); HPE AOS-S defaults to no timeout (fail when unset).
- **Parameters.** `max_idle_minutes` = 10
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.5 · NIST SP 800-53 r5 AC-12, SC-10 · CIS Controls v8 4.3

#### LYSS-AUTH-001

**No default or well-known SNMP community strings**

- **Requirement.** SNMP communities "public", "private" and vendor defaults are not configured.
- **Rationale.** Default communities give anyone on the network read (or write) access to the device.
- **Test procedure.** Fail if an SNMP community named "public", "private" or a documented vendor default is configured.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.5.17, A.8.21 · NIST SP 800-53 r5 IA-5, CM-6 · CIS Controls v8 4.7

#### LYSS-AUTH-002

**Privileged-mode password is stored as a strong hash**

- **Requirement.** The privileged (enable) credential is stored with a one-way hash based on SHA-256 or a stronger algorithm (e.g. scrypt, PBKDF2-SHA-256, SHA-256/SHA-512 crypt). Cleartext, reversible encodings, MD5- and SHA-1-based hashes and Cisco type 4 are not accepted.
- **Rationale.** Reversible encodings (e.g. Cisco type 7) are decoded instantly by public tools from any configuration backup, and MD5- or SHA-1-based hashes (e.g. Cisco type 5) are cracked quickly on commodity hardware.
- **Test procedure.** Fail if the privileged credential, or a local account with full privileges, is stored in cleartext, a reversible form, or with MD5, SHA-1 or Cisco type 4 (e.g. Cisco "enable password", type 4 or 5, a 40-hex-digit SHA-1 value, HPE "sha1"). Pass if it uses an accepted algorithm, or if there is no privileged credential and privileged access is only granted through central AAA. Unknown if the algorithm cannot be identified.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.5.17, A.8.5 · NIST SP 800-53 r5 IA-5(1) · CIS Controls v8 3.11

#### LYSS-AUTH-003

**Local account passwords are not stored in cleartext or reversible form**

- **Requirement.** Every local user account credential is stored as a one-way hash.
- **Rationale.** Configuration backups circulate (backup servers, tickets, e-mail); stored passwords must not be recoverable.
- **Test procedure.** Fail if any local account credential is stored in cleartext or a reversible encoding.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.5.17 · NIST SP 800-53 r5 IA-5(1) · CIS Controls v8 3.11

#### LYSS-AUTH-004

**AAA shared secrets (RADIUS/TACACS+) are not stored in cleartext**

- **Requirement.** Keys shared with RADIUS or TACACS+ servers are never stored in cleartext in the configuration.
- **Rationale.** A cleartext RADIUS key in a backup lets an attacker impersonate the AAA server or decrypt authentication traffic.
- **Test procedure.** Fail if a RADIUS or TACACS+ shared key appears in cleartext. A reversible encoding is not cleartext and passes this control; storing keys irreversibly or with a device-specific encryption key is planned as a separate Level 2 control.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.5.17, A.8.24 · NIST SP 800-53 r5 IA-5, SC-28 · CIS Controls v8 3.11

#### LYSS-VULN-001

**Firmware is vendor-supported and free of known critical vulnerabilities**

- **Requirement.** The vendor still publishes security fixes for the device, and the running firmware has no known critical (CVSS >= 9.0) or known-exploited (CISA KEV) vulnerability whose fix is not installed.
- **Rationale.** Unsupported or vulnerable firmware is the most common path to switch compromise.
- **Test procedure.** Identify the model and firmware version from device state and compare them with a sourced knowledge base (vendor advisories, end-of-life bulletins, CISA KEV). Fail if security support has ended, or if an applicable critical (CVSS >= 9.0) or known-exploited (CISA KEV) advisory is unfixed in the running version; other advisories do not affect this control. Unknown if the platform is not in the knowledge base: a pass is never assumed.
- **Evidence.** state, external_data
- **References (informative).** ISO/IEC 27001:2022 A.8.8 · NIST SP 800-53 r5 SI-2, SA-22, RA-5 · CIS Controls v8 2.2, 12.1

#### LYSS-BKP-001

**Configuration is backed up automatically**

- **Requirement.** The running configuration is collected automatically, so that a copy at most 7 days old exists at any time.
- **Rationale.** Without a recent backup, recovery after failure or compromise is slow and error-prone.
- **Test procedure.** Pass if the most recent automatic (scheduled) collection of the running configuration is at most the parameter old at the time of assessment; a schedule less frequent than the parameter therefore fails between runs. Otherwise pass on an external backup system only with evidence of its last successful backup for this device, at most the parameter old (for example from the backup system's records), or with an administrator attestation, renewed at least every 90 days, that the external system backs the device up at least as often as the parameter and alerts on failure. Fail if the last automatic backup is older, or only manual collections exist.
- **Parameters.** `max_age_days` = 7
- **Evidence.** backup_system
- **References (informative).** ISO/IEC 27001:2022 A.8.9, A.8.13 · NIST SP 800-53 r5 CP-9, CM-2(3) · CIS Controls v8 11.2

### Level 2: Hardened

#### LYSS-AUTH-010

**Administrative logins use central AAA (RADIUS/TACACS+) with local fallback only**

- **Requirement.** Administrator logins are authenticated by a RADIUS or TACACS+ server first; local accounts are only a fallback.
- **Rationale.** Central AAA gives individual accounts, immediate revocation and an audit trail; shared local passwords do not.
- **Test procedure.** Pass if an AAA server is defined and every login method list used for remote administrative access starts with the AAA server, local accounts coming only after it. Fail if any such list starts with a local account, a line password or no authentication.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.5.16, A.8.5 · NIST SP 800-53 r5 IA-2, AC-2 · CIS Controls v8 12.5

#### LYSS-AUTH-011

**SNMP uses v3 with authentication and privacy or is disabled**

- **Requirement.** No SNMPv1/v2c community is configured; SNMP, if used, is SNMPv3 with authentication and encryption.
- **Rationale.** SNMPv1/v2c communities travel in cleartext and are equivalent to shared passwords.
- **Test procedure.** Fail if any SNMPv1/v2c community or v1/v2 group is configured, or if any SNMPv3 group or user has a security level below authentication with privacy (noAuthNoPriv or authNoPriv).
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.21, A.8.24 · NIST SP 800-53 r5 SC-8, SC-13, IA-5 · CIS Controls v8 12.6

#### LYSS-MGMT-010

**Management access is restricted to authorized source networks**

- **Requirement.** Management protocols only accept connections from authorized administration networks.
- **Rationale.** Limiting who can even reach the login prompt removes most password-guessing and exploit attempts.
- **Test procedure.** Pass if every remote management access path is bound to an access list of authorized sources.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.20, A.8.22 · NIST SP 800-53 r5 AC-17, SC-7 · CIS Controls v8 12.3

#### LYSS-MGMT-011

**Management interface is on a dedicated management VLAN**

- **Requirement.** The switch management address is on a VLAN reserved for management: not the default VLAN (1), and no user access port is a member of it.
- **Rationale.** Separating management from user networks prevents users from reaching the management plane.
- **Test procedure.** Fail if VLAN 1 carries a management address, or if an access (untagged, non-uplink) port is a member of the management VLAN. Pass if the management address is on another VLAN with no access port.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.22 · NIST SP 800-53 r5 SC-7, AC-4 · CIS Controls v8 12.2

#### LYSS-MGMT-012

**A legal warning banner is shown before login**

- **Requirement.** A banner stating authorized use only is displayed before authentication.
- **Rationale.** The warning supports legal action against intruders and informs users that activity is monitored.
- **Test procedure.** Pass if a banner displayed before authentication (login or message-of-the-day, not a post-login exec banner) is configured and its text states the authorized-use restriction ("authorized", "authorised", "unauthorized" or "unauthorised"). Fail otherwise.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.5.10 · NIST SP 800-53 r5 AC-8 · CIS Controls v8 —

#### LYSS-MGMT-013

**SSH uses modern key exchange, ciphers and host keys**

- **Requirement.** The SSH server supports a SHA-2 (or better) key exchange, a CTR/GCM/ChaCha20 cipher and a SHA-2 host key signature.
- **Rationale.** SHA-1 key exchange, CBC ciphers and ssh-rsa (SHA-1) signatures are deprecated; modern clients refuse them and they weaken the management channel.
- **Test procedure.** Connect offering the strongest algorithms first and record the negotiated ones (the best the switch supports). Fail on a SHA-1 or group1 key exchange, a CBC/3DES/RC4 cipher, or an ssh-rsa/ssh-dss host key signature.
- **Evidence.** state
- **References (informative).** ISO/IEC 27001:2022 A.8.24, A.8.21 · NIST SP 800-53 r5 SC-8, SC-13 · CIS Controls v8 3.10, 12.6

#### LYSS-LOG-010

**Events are sent to a remote syslog/SIEM server**

- **Requirement.** The switch forwards its logs to at least one remote syslog or SIEM collector.
- **Rationale.** Local logs are lost on reboot and can be erased by an intruder; remote logs support detection and investigation.
- **Test procedure.** Fail if logging is disabled globally (e.g. "no logging on"). Pass if at least one remote syslog destination is configured and logging is enabled.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.15, A.8.16 · NIST SP 800-53 r5 AU-4(1), AU-6 · CIS Controls v8 8.2, 8.9

#### LYSS-LOG-011

**Clock is synchronized with NTP/SNTP**

- **Requirement.** The switch clock is synchronized with at least one configured time server.
- **Rationale.** Without a reliable clock, logs cannot be correlated and certificates and schedules misbehave.
- **Test procedure.** Fail if no NTP or SNTP server is configured, or if the device state reports the clock as not synchronized. Pass if a time server is configured and the clock is reported synchronized; without device state, a configured time server passes and the report says that synchronization was not verified.
- **Evidence.** config, state
- **References (informative).** ISO/IEC 27001:2022 A.8.17 · NIST SP 800-53 r5 AU-8, SC-45 · CIS Controls v8 8.4

#### LYSS-ACC-010

**Unused ports are administratively disabled**

- **Requirement.** Ports with no link are administratively shut down.
- **Rationale.** An enabled, unused port lets anyone plug in an unauthorized device.
- **Test procedure.** Fail if any port is operationally down while administratively enabled (device state).
- **Evidence.** config, state
- **References (informative).** ISO/IEC 27001:2022 A.8.20 · NIST SP 800-53 r5 CM-7 · CIS Controls v8 12.3

#### LYSS-ACC-011

**Edge ports are protected against rogue spanning-tree participants (BPDU guard)**

- **Requirement.** Every edge port disables itself when it receives a spanning-tree BPDU. Links to other switches are configured as such (trunks or link aggregations); every other port is an edge port.
- **Rationale.** A rogue or misconnected switch on an access port can take over the spanning tree or create a loop.
- **Test procedure.** Edge ports are all ports minus uplinks, and uplinks are only the ports configured as trunks or link-aggregation members (tagged on HPE AOS-S). Neighbour discovery never exempts a port: a rogue device can advertise bridge capability. Fail if an edge port lacks BPDU protection, unless a global default protects all edge ports.
- **Evidence.** config, state
- **References (informative).** ISO/IEC 27001:2022 A.8.20 · NIST SP 800-53 r5 SC-5, CM-6 · CIS Controls v8 12.2

### Level 3: Advanced

#### LYSS-ACC-020

**DHCP snooping is enabled on user VLANs**

- **Requirement.** DHCP snooping is enabled globally and on every VLAN used by an access port, so that DHCP server messages are only accepted from trusted (uplink) ports.
- **Rationale.** A rogue DHCP server on a user port can hand out its own gateway and DNS server and intercept traffic; DHCP snooping drops server messages from untrusted ports and builds the binding table that ARP inspection and IP source guard rely on.
- **Test procedure.** Fail if DHCP snooping is not enabled globally, or if a VLAN used by an access port is not in the snooping VLAN list. Pass if it is enabled and every such VLAN is covered (on platforms where snooping applies to the whole bridge, the bridge setting covers every access port). Not applicable without access ports.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.20, A.8.22 · NIST SP 800-53 r5 SC-7, SI-4 · CIS Controls v8 —

*Draft: requirement text and checks to be written.*

#### LYSS-ACC-021

**Dynamic ARP inspection is enabled on user VLANs**

- **Requirement.** ARP packets received on access ports are checked against the DHCP snooping bindings (or static ARP access lists) on every VLAN used by an access port.
- **Rationale.** Without ARP inspection, any user device can claim the gateway's IP address (ARP spoofing) and read or alter the traffic of every host in the VLAN.
- **Test procedure.** Fail if a VLAN used by an access port is not covered by dynamic ARP inspection, or if the platform offers no ARP inspection (the report names the platform limit). Pass if every such VLAN is covered. Not applicable without access ports.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.20, A.8.22 · NIST SP 800-53 r5 SC-7, SI-4 · CIS Controls v8 —

*Draft: requirement text and checks to be written.*

#### LYSS-ACC-022

**Access ports require 802.1X or MAC authentication**

- **Requirement.** Every access port authenticates the connected device (IEEE 802.1X, or MAC authentication bypass for devices without a supplicant) before granting network access.
- **Rationale.** Without port authentication, anyone who can plug a cable into a wall socket is on the internal network.
- **Test procedure.** Fail if port authentication is not enabled globally where the platform requires it, or if an access port has no 802.1X / MAC authentication setting. Pass if every access port has one. Not applicable without access ports.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.20, A.5.15 · NIST SP 800-53 r5 IA-3, AC-3 · CIS Controls v8 13.9

*Draft: requirement text and checks to be written.*

#### LYSS-ACC-023

**Storm control limits broadcast traffic on access ports**

- **Requirement.** Every access port limits the rate of broadcast traffic it accepts (storm control).
- **Rationale.** A loop or a misbehaving device on one user port can flood broadcast traffic to every port of the VLAN and take the network down; a rate limit contains it on the offending port.
- **Test procedure.** Fail if an access port has no broadcast rate limit. Pass if every access port has one. Unknown when the platform sets it on the switch chip and the setting cannot be read. Not applicable without access ports.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.20, A.8.6 · NIST SP 800-53 r5 SC-5 · CIS Controls v8 —

*Draft: requirement text and checks to be written.*

#### LYSS-ACC-024

**Neighbor discovery (CDP/LLDP) is not sent on untrusted access ports**

- **Requirement.** Access ports do not transmit CDP or LLDP advertisements, except ports that serve IP phones (a voice VLAN), which need LLDP-MED or CDP.
- **Rationale.** CDP and LLDP advertisements tell anyone on a user port the switch name, model, software version, management address and VLANs, which helps an attacker choose an exploit.
- **Test procedure.** Pass if neighbor discovery transmission is disabled globally, or on every access port without a voice VLAN, for each protocol the platform sends by default or that is enabled. Fail otherwise. Not applicable without access ports.
- **Evidence.** config
- **References (informative).** ISO/IEC 27001:2022 A.8.20, A.8.9 · NIST SP 800-53 r5 CM-7 · CIS Controls v8 4.8

*Draft: requirement text and checks to be written.*

## 6. Requirements for adapters

An adapter for a platform family:

1. MUST identify the platform it covers and the specification version it implements.
2. MUST map each check to an existing control identifier and MUST NOT change a control's meaning.
3. MUST yield `unknown` when the platform hides a default or the evidence is missing.
4. SHOULD provide, for each failing control, a remediation that an administrator can review.
5. MUST be accompanied by test cases in which each implemented control passes and fails.

## 7. Requirements for assessment tools

1. Collection MUST be read-only: no command that changes the device configuration or state.
2. Secrets (password hashes, keys, SNMP communities) MUST be redacted from stored and reported evidence;
   well-known default values MAY remain visible because they are the finding.
3. Credentials used for collection MUST be stored encrypted.
4. Reports MUST state the specification version, the evidence of each verdict and the assessment date.

### 7.1 Optional remediation

A tool MAY offer to apply fixes. If it does, remediation:

1. MUST be disabled by default and MUST never run without an explicit action of an administrator.
2. MUST show the exact commands and their rollback before they are applied.
3. MUST be limited to changes that cannot cut management or user access; credentials, access
   lists, VLANs, authentication, spanning tree and port shutdowns remain manual changes.
4. MUST back up the configuration first, apply one device at a time, and roll back on the first
   rejected command.
5. MUST verify the result over a new management connection and roll back fixes whose control
   does not pass, and MUST only save the configuration after verification.
6. MUST record every change (date, device, commands, outcome) in a change log.

## 8. Versioning

The specification follows semantic versioning:

- **MAJOR**: a control is removed, or its requirement becomes stricter or changes meaning.
- **MINOR**: controls are added, or a level gains controls.
- **PATCH**: editorial changes, references, test procedure clarifications.

Control identifiers are never reused. A withdrawn control keeps its identifier, marked withdrawn.
While the version is below 1.0.0 the specification is a draft and MAY change without a MAJOR increment.

## 9. References (informative)

Mappings to ISO/IEC 27001:2022 Annex A, NIST SP 800-53 revision 5 and CIS Controls v8 are
informative: they help reuse LYSS results as audit evidence and do not change the requirements.
