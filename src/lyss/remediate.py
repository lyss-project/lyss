# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Optional remediation: apply LOW-RISK fixes to failing controls, safely.

Disabled by default (Settings > Remediation). For each switch, one at a time:
  1. fresh collection + audit, the configuration is archived (trigger "pre-change");
  2. the selected fixes that still apply are sent; on the first rejected command, everything
     already sent is rolled back;
  3. verification: a NEW SSH connection (management access still works), collection + audit;
     a fix whose control does not pass afterwards is rolled back;
  4. only then the running configuration is saved (until then a reboot restores the old one);
  5. every action is written to the change log (private/changes.jsonl).
Only fixes that cannot cut management or user access are in the catalogue. Credentials, ACLs,
VLANs, AAA, spanning tree and port shutdowns stay manual.
"""

import ipaddress
import json
import re
import threading
import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime

from . import collector, inventory, sealed
from .config import Config, parse
from .engine import redact

BANNER_TEXT = re.compile(r"^[A-Za-z0-9 .,;:!?()'/\-éèêàçùâôîÉÈ]{3,200}$")
_lock = threading.Lock()
_job: dict | None = None


@dataclass
class Fix:
    control_id: str
    label: str
    commands: list[str]
    rollback: list[str]
    kind: str = "fix"          # "fix" makes the control pass; "mitigation" reduces the risk only
    note: str = ""
    blocked: str = ""          # reason why it cannot be applied automatically
    verify_state: str = ""     # mitigation: regex that must NOT match the new device state
    verify_section: str = ""
    verify_config: list = field(default_factory=list)   # regexes the new configuration must contain
                                                        # (instead of the control passing: e.g. NTP needs minutes to sync)


# ---------------- settings ----------------

def settings() -> dict:
    return {"enabled": False, "firmware": False, "syslog": "", "ntp": [],
            "banner": "Authorized access only. Activity is logged.",
            **inventory.load_settings().get("remediation", {})}


def validate_params(syslog: str, ntp: list[str], banner: str) -> list[str]:
    """The values that end up in commands sent to switches: IPv4 addresses written exactly
    (the commands use IPv4 syntax; IPv6 scope ids could carry anything, even new lines), and a
    banner of plain characters."""
    errors = []
    for value, name in [(syslog, "Syslog server")] + [(n, "NTP server") for n in ntp]:
        if value and inventory.strict_ip(value, version=4) is None:
            errors.append(f"{name}: {value!r} is not an IPv4 address.")
    if banner and (not BANNER_TEXT.fullmatch(banner) or "#" in banner):
        errors.append("Banner: 3-200 characters, letters, digits and basic punctuation only (no #).")
    return errors


def suggest_defaults() -> dict:
    """Syslog / NTP servers already configured on most of the fleet. Each switch counts once per
    address, and only an address found on more than half of the switches that have one is
    suggested: a single rogue switch cannot choose the servers for the whole fleet."""
    syslog, ntp, with_syslog, with_ntp = Counter(), Counter(), 0, 0
    for device in inventory.load_devices():
        cfg_path, _ = collector.config_paths(device)
        if not cfg_path.exists():
            continue
        text = sealed.read_text(cfg_path, errors="replace")
        s = set(re.findall(r"(?m)^logging (?:host )?(\d+\.\d+\.\d+\.\d+)", text))
        n = set(re.findall(r"(?m)^s?ntp server (\d+\.\d+\.\d+\.\d+)", text))
        syslog.update(s)
        ntp.update(n)
        with_syslog += bool(s)
        with_ntp += bool(n)
    best_syslog = [ip for ip, c in syslog.most_common(1) if c * 2 > with_syslog]
    return {"syslog": best_syslog[0] if best_syslog else "",
            "ntp": [ip for ip, c in ntp.most_common(2) if c * 2 > with_ntp]}


# ---------------- fix catalogue ----------------

def _blocks(cfg: Config, header: str):
    pattern = re.compile(header)
    return [b for b in cfg.blocks if pattern.search(b.header)]


def _child(block, pattern: str) -> str | None:
    p = re.compile(pattern)
    return next((c for c in block.children if p.search(c)), None)


def _community_fix(cfg: Config, vendor: str) -> Fix:
    # HP quotes the name: snmp-server community "public" unrestricted
    lines = [l for l in cfg.lines if re.match(r'(?i)^snmp-server community "?(public|private)"?(\s|$)', l)]
    commands = [f"no snmp-server community {l.split()[2]}" for l in lines]
    fix = Fix("LYSS-AUTH-001", "Remove the default SNMP communities", commands, list(lines),
              note="Check first that no monitoring tool still polls the switch with these communities.")
    if any("<" in l for l in lines):  # masked in the collected config: the rollback could not restore it
        fix.blocked = "the configuration shows these lines masked; remove them manually"
    return fix


def _needs(params: dict, *keys: str) -> str:
    missing = [k for k in keys if not params.get(k)]
    return f"set the {', '.join(missing)} value in Settings > Remediation" if missing else ""


def _present(cfg: Config, pattern: str) -> bool:
    p = re.compile(pattern)
    return any(p.search(l.strip()) for l in cfg.lines)


def _syslog_fix(cfg: Config, syslog: str, command: str, params: dict) -> Fix:
    """Send logs to the syslog server. A server that is already configured is never re-sent (the
    control then fails for another reason) and so never removed by a rollback."""
    if syslog and _present(cfg, rf"^{re.escape(command)}$"):
        return Fix("LYSS-LOG-010", f"Send logs to {syslog}", [], [],
                   blocked=f"{syslog} is already configured: LYSS-LOG-010 fails for another reason (see its evidence)")
    return Fix("LYSS-LOG-010", f"Send logs to {syslog or 'the syslog server'}", [command], [f"no {command}"],
               blocked=_needs(params, "syslog"))


def _ntp_fix(cfg: Config, ntp: list[str], keyword: str, extra: list[str], params: dict, poll: str = "") -> Fix:
    """Add only the NTP servers that are not configured yet; the rollback removes only those. The
    clock needs minutes to synchronise: the fix is verified on the configuration, and the next
    scan shows the control passing."""
    new = [n for n in ntp if not _present(cfg, rf"^{keyword} server {re.escape(n)}\b")]
    label = f"Synchronise the clock with {', '.join(ntp) or 'NTP'}"
    if ntp and not new:
        return Fix("LYSS-LOG-011", label, [], [],
                   blocked="these NTP servers are already configured: the clock is not synchronised; "
                           "check that the switch can reach them")
    extra = [c for c in extra if not _present(cfg, rf"^{re.escape(c)}$")]
    return Fix("LYSS-LOG-011", label, extra + [f"{keyword} server {n}{poll}" for n in new],
               [f"no {keyword} server {n}" for n in new], blocked=_needs(params, "ntp"),
               verify_config=[rf"^{keyword} server {re.escape(n)}\b" for n in new],
               note="The clock synchronises within a few minutes: the next scan shows LYSS-LOG-011 passing.")


def fixes_for(vendor: str, cfg: Config, failing: dict, params: dict) -> list[Fix]:
    """Fixes for the failing controls of one device (failing: control_id -> finding)."""
    out = []
    banner = params.get("banner", "")
    syslog, ntp = params.get("syslog", ""), params.get("ntp", [])
    if validate_params(syslog, ntp, banner):
        # settings changed outside the form (settings.json): never build commands from them
        invalid = "the Remediation settings are invalid: save them again in Settings > Remediation"
        params = {**params, "syslog": "", "ntp": [], "banner": ""}
        syslog, ntp, banner = "", [], ""
    else:
        invalid = ""

    if vendor == "cisco_sb":
        if "LYSS-MGMT-001" in failing:
            out.append(Fix("LYSS-MGMT-001", "Turn off the Telnet server", ["no ip telnet server"], ["ip telnet server"],
                           note="SSH stays available (LYSS itself uses SSH)."))
        if "LYSS-MGMT-003" in failing:
            out.append(Fix("LYSS-MGMT-003", "Turn off plain HTTP (HTTPS unchanged)", ["no ip http server"], ["ip http server"],
                           note="Use https:// for the web interface."))
        if "LYSS-AUTH-001" in failing:
            out.append(_community_fix(cfg, vendor))
        vuln = failing.get("LYSS-VULN-001")
        if vuln and any("no fix" in e or "support ended" in e for e in vuln["evidence"]):
            # Cisco SB syntax (checked with the CLI help on SG300 1.4 and SG350 2.5): HTTPS is
            # "ip http secure-server"; the rollback only restarts what was listening before
            ports = cfg.state.get("show services tcp-udp", [])
            if not ports:
                # without the list of listening services the rollback could not know what to
                # restart (it would turn on HTTPS even if it was off): no automatic fix
                out.append(Fix("LYSS-VULN-001", "Mitigation: turn off the whole web interface (HTTP and HTTPS)",
                               [], [], kind="mitigation", blocked="the listening services were not collected: run a scan first"))
            http_on = any(re.search(r"^TCP6?\s+All[:-]80\s.*listen", l) for l in ports)
            https_on = any(re.search(r"^TCP6?\s+All[:-]443\s.*listen", l) for l in ports)
            cmds = (["no ip http server"] if http_on else []) + (["no ip http secure-server"] if https_on else [])
            back = (["ip http server"] if http_on else []) + (["ip http secure-server"] if https_on else [])
            # no web service listening any more: the mitigation is already in place, nothing to offer
            if cmds:
                out.append(Fix("LYSS-VULN-001", "Mitigation: turn off the whole web interface (HTTP and HTTPS)",
                           cmds, back, kind="mitigation", verify_section="show services tcp-udp",
                           verify_state=r"^TCP6?\s+All[:-](80|443)\s.*listen",
                           note="The critical web-interface vulnerability can never be patched on this model: "
                                "removing the web interface removes the attack path. Manage it over SSH. "
                                "The control stays failed until the switch is replaced."))
        if "LYSS-MGMT-012" in failing:
            # Cisco SB: the text goes on its own line between the delimiters (CLI help, SG300/SG350)
            out.append(Fix("LYSS-MGMT-012", "Add the login banner", [f"banner login #\n{banner}\n#"], ["no banner login"],
                           blocked=_needs(params, "banner")))
        if "LYSS-LOG-010" in failing:
            out.append(_syslog_fix(cfg, syslog, f"logging host {syslog}", params))
        if "LYSS-LOG-011" in failing:
            out.append(_ntp_fix(cfg, ntp, "sntp", ["clock source sntp", "sntp unicast client enable"], params,
                                poll=" poll"))

    elif vendor == "cisco_ios":
        if "LYSS-MGMT-001" in failing:
            cmds, back = [], []
            for b in _blocks(cfg, r"^line vty"):
                old = _child(b, r"^transport input")
                cmds += [b.header, "transport input ssh"]
                back += [b.header, old or "default transport input"]
            out.append(Fix("LYSS-MGMT-001", "Remote CLI over SSH only (no Telnet)", cmds, back,
                           note="SSH stays available (LYSS itself uses SSH)."))
        if "LYSS-MGMT-002" in failing:
            out.append(Fix("LYSS-MGMT-002", "Accept SSH version 2 only", ["ip ssh version 2"], ["no ip ssh version"]))
        if "LYSS-MGMT-003" in failing:
            out.append(Fix("LYSS-MGMT-003", "Turn off plain HTTP (HTTPS unchanged)", ["no ip http server"], ["ip http server"]))
        if "LYSS-MGMT-004" in failing:
            cmds, back = [], []
            for b in _blocks(cfg, r"^line (con|vty)"):
                old = _child(b, r"^exec-timeout")
                cmds += [b.header, "exec-timeout 10 0"]
                back += [b.header, old or "no exec-timeout"]
            out.append(Fix("LYSS-MGMT-004", "Idle session timeout 10 minutes", cmds, back))
        if "LYSS-AUTH-001" in failing:
            out.append(_community_fix(cfg, vendor))
        if "LYSS-MGMT-012" in failing:
            out.append(Fix("LYSS-MGMT-012", "Add the login banner", [f"banner login #{banner}#"], ["no banner login"],
                           blocked=_needs(params, "banner")))
        if "LYSS-LOG-010" in failing:
            out.append(_syslog_fix(cfg, syslog, f"logging host {syslog}", params))
        if "LYSS-LOG-011" in failing:
            out.append(_ntp_fix(cfg, ntp, "ntp", [], params))
    elif vendor == "hp_procurve":
        # AOS-S: only well-documented global commands; SNTP, SSH crypto and AAA stay manual until
        # validated on a real switch
        if "LYSS-MGMT-001" in failing:
            out.append(Fix("LYSS-MGMT-001", "Turn off the Telnet server", ["no telnet-server"], ["telnet-server"],
                           note="SSH stays available (LYSS itself uses SSH)."))
        if "LYSS-MGMT-003" in failing:
            ssl = any(re.match(r"^web-management ssl\b", l) for l in cfg.lines)
            out.append(Fix("LYSS-MGMT-003", "Turn off plain HTTP web management", ["no web-management plaintext"],
                           ["web-management plaintext"],
                           note="HTTPS stays available." if ssl else
                                "HTTPS is not configured: the web interface becomes unavailable (manage over SSH)."))
        if "LYSS-MGMT-004" in failing:
            old = next((l for l in cfg.lines if re.match(r"^console idle-timeout \d+\s*$", l)), None)
            out.append(Fix("LYSS-MGMT-004", "Idle session timeout 10 minutes", ["console idle-timeout 600"],
                           [old or "console idle-timeout 0"]))
        if "LYSS-AUTH-001" in failing:
            out.append(_community_fix(cfg, vendor))
        if "LYSS-MGMT-012" in failing:
            out.append(Fix("LYSS-MGMT-012", "Add the login banner", [f'banner motd "{banner}"'], ["no banner motd"],
                           blocked=_needs(params, "banner")))
        if "LYSS-LOG-010" in failing:
            out.append(_syslog_fix(cfg, syslog, f"logging {syslog}", params))
    if invalid:
        for f in out:
            if f.control_id in ("LYSS-LOG-010", "LYSS-LOG-011", "LYSS-MGMT-012"):
                f.blocked = invalid
    if _present(cfg, r"^banner (login|motd)\b"):
        # a banner exists but does not state the authorized-use restriction: its rollback
        # ("no banner ...") would delete the original text, which LYSS cannot type back faithfully
        for f in out:
            if f.control_id == "LYSS-MGMT-012" and not f.blocked:
                f.blocked = "a banner is already configured: change its text manually (LYSS could not restore it)"
    # a fix with nothing to send is never offered, unless it waits for a missing setting
    return [f for f in out if f.commands or f.blocked]


def plan(device: dict) -> list[Fix]:
    """Fixes available for a device from its last collection and result (no connection)."""
    result = inventory.load_result(device["id"])
    cfg_path, state_path = collector.config_paths(device)
    if not result or not cfg_path.exists():
        return []
    cfg = parse(sealed.read_text(cfg_path, errors="replace"),
                sealed.read_text(state_path, errors="replace") if state_path.exists() else "", device["vendor"])
    failing = {f["control_id"]: f for f in result["findings"] if f["verdict"] == "fail"}
    fixes = fixes_for(device["vendor"], cfg, failing, settings())
    if not settings()["enabled"]:
        for f in fixes:
            f.blocked = f.blocked or "remediation is disabled (Settings > Remediation)"
    return fixes


# ---------------- change log ----------------

def _log_file():
    return inventory.PRIVATE / "changes.jsonl"


def log_change(entry: dict) -> None:
    entry.setdefault("ended", datetime.now().isoformat(timespec="seconds"))
    path = _log_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_changes(limit: int = 100) -> list[dict]:
    path = _log_file()
    if not path.exists():
        return []
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return list(reversed(rows))[:limit]


# ---------------- apply ----------------

def _verified(fix: Fix, result: dict, state_text: str, config_text: str = "") -> bool:
    if fix.kind == "mitigation":
        from .config import parse_state
        lines = parse_state(state_text).get(fix.verify_section)
        return lines is not None and not any(re.search(fix.verify_state, l) for l in lines)
    if fix.verify_config:
        lines = [l.strip() for l in config_text.splitlines()]
        return all(any(re.search(p, l) for l in lines) for p in fix.verify_config)
    return any(f["control_id"] == fix.control_id and f["verdict"] == "pass" for f in result["findings"])


UNCLEAN = ("ROLLBACK FAILED", "connection lost", "verification failed", "error:")


def unclean_change(device_id: str) -> str:
    """The outcome of the last change on this device if it may have left the running
    configuration half-changed and no scan has looked at the switch since; "" otherwise. Firmware
    staging/activation and new fixes are refused meanwhile: they save the running configuration,
    which would make the leftovers permanent."""
    last = next((c for c in load_changes(500) if c.get("device") == device_id), None)
    if not last or not any(u in last.get("outcome", "") for u in UNCLEAN):
        return ""
    result = inventory.load_result(device_id) or {}
    scanned = result.get("scanned_at", "")
    if scanned > last.get("ended", last.get("ts", "")) and result.get("trigger") not in ("change", "pre-change"):
        return ""
    return last["outcome"]


CONNECTION_ERRORS = (EOFError, ConnectionError, TimeoutError, OSError)


def _retry(action, attempts: int = 3):
    """Retry when the switch drops the connection (old Cisco SB switches refuse SSH sessions
    opened in quick succession). Authentication errors are never retried."""
    import paramiko
    for attempt in range(1, attempts + 1):
        try:
            return action()
        except paramiko.AuthenticationException:
            raise
        except (*CONNECTION_ERRORS, paramiko.SSHException):
            if attempt == attempts:
                raise
            time.sleep(5 * attempt)


def _open(device: dict, jump):
    return _retry(lambda: collector.open_session(device, jump))


def _collect(device: dict, jump):
    return _retry(lambda: collector.collect_device(device, jump))


def _send_rollback(session, fixes: list, entry: dict) -> bool:
    """Send the rollback of fixes (newest first) on an open session. True only if the switch
    accepted every rollback command: a rejected one is never reported as rolled back."""
    ok = True
    for fix in reversed(fixes):
        if not fix.rollback:
            entry["rolled_back"].append(fix.control_id)
            continue
        done = session.configure(fix.rollback)
        bad = [c for c, o in done if collector.CLI_ERROR.search(o)]
        if bad or len(done) < len(fix.rollback):
            ok = False
            entry.setdefault("rollback_rejected", []).append(f"{fix.control_id}: {bad[0] if bad else '?'}")
        else:
            entry["rolled_back"].append(fix.control_id)
    return ok


def _rollback(device: dict, jump, fixes: list, entry: dict, step) -> bool:
    """Send the rollback of fixes over a NEW session (the previous one may be dead)."""
    step("rolling back over a new connection", 90)
    try:
        session = _open(device, jump)
        try:
            return _send_rollback(session, fixes, entry)
        finally:
            session.close()
    except Exception as exc:
        entry["rollback_error"] = redact(f"{type(exc).__name__}: {exc}")[:200]
        return False


def _rolled_back(ok: bool) -> str:
    return "rolled back, not saved" if ok else "ROLLBACK FAILED, not saved: a reboot restores the saved configuration"


def apply_device(device: dict, control_ids: list[str], jump, step) -> dict:
    """Apply the selected fixes to one device. step(message, percent) reports progress:
    collection 0-20 %, commands 25-55 %, verification 60-80 %, save 85-100 %."""
    from . import scan  # late import: scan imports the collector too

    entry = {"ts": datetime.now().isoformat(timespec="seconds"), "device": device["id"], "host": device["host"],
             "controls": control_ids, "applied": [], "rolled_back": [], "commands": [], "outcome": "", "saved": False}
    previous = unclean_change(device["id"])
    if previous:
        entry["outcome"] = ("refused: the last change on this switch may be incomplete (" + previous[:120]
                            + "). Check the switch, run a scan, then try again.")
        log_change(entry)
        return entry
    step("fresh collection and backup before the change", 5)
    entry["stage"] = "pre-change collection"
    _collect(device, jump)
    scan.audit_device(device, "pre-change")
    fixes = [f for f in plan(device) if f.control_id in control_ids and not f.blocked]
    if not fixes:
        entry["outcome"] = "nothing to apply (already compliant or blocked)"
        log_change(entry)
        return entry

    step("connecting to apply the fixes", 20)
    entry["stage"] = "opening the configuration session"
    session = _open(device, jump)
    touched, error = [], ""
    try:
        entry["stage"] = "sending commands"
        for i, fix in enumerate(fixes):
            step(f"applying {fix.control_id} ({i + 1}/{len(fixes)})", 25 + 30 * i // len(fixes))
            touched.append(fix)
            done = session.configure(fix.commands)
            entry["commands"] += [c for c, _ in done]
            bad = [(c, o) for c, o in done if collector.CLI_ERROR.search(o)]
            if bad or len(done) < len(fix.commands):
                error = f"{fix.control_id}: command rejected: {bad[0][0] if bad else '?'} -> {(bad[0][1] if bad else '').strip()[:160]}"
                break
        if error:
            step("error: rolling back everything sent", 90)
            ok = _send_rollback(session, touched, entry)
            entry["outcome"] = (f"failed, rolled back, not saved: {error}" if ok
                                else f"failed ({error}); " + _rolled_back(ok))
            log_change(entry)
            return entry
    except Exception as exc:
        # the session died (or netmiko failed) while commands were being sent: undo what may
        # have been applied, over a new connection. Any exception counts, not only socket errors.
        session_error = redact(f"{type(exc).__name__}: {exc}")[:400]
        entry["failed_command"] = getattr(session, "current", "")
        session_error += f" on command {entry['failed_command']!r}" if entry["failed_command"] else ""
        ok = _rollback(device, jump, touched, entry, step)
        entry["outcome"] = f"connection lost while sending commands ({session_error}); " + _rolled_back(ok)
        log_change(entry)
        return entry
    finally:
        try:
            session.close()
        except Exception:
            pass

    step("verification over a new SSH connection", 60)
    entry["stage"] = "verification"
    try:
        _collect(device, jump)  # proves management access still works
        step("checking the controls after the change", 80)
        result = scan.audit_device(device, "change")
        cfg_path, state_path = collector.config_paths(device)
        state_text = sealed.read_text(state_path, errors="replace")
        config_text = sealed.read_text(cfg_path, errors="replace")
        failed = [f for f in fixes if not _verified(f, result, state_text, config_text)]
    except Exception as exc:
        # nothing can be verified: undo everything, never save
        ok = _rollback(device, jump, fixes, entry, step)
        entry["outcome"] = (f"verification failed ({redact(f'{type(exc).__name__}: {exc}')[:200]}); "
                            + _rolled_back(ok))
        log_change(entry)
        return entry
    entry["stage"] = "saving"
    session = _open(device, jump)
    try:
        if failed:
            step("rolling back the fixes that did not verify: " + ", ".join(f.control_id for f in failed), 85)
            if not _send_rollback(session, failed, entry):
                # a rejected rollback leaves an unverified change in the running configuration:
                # saving now would make it permanent
                entry["outcome"] = ("ROLLBACK FAILED for " + ", ".join(entry.get("rollback_rejected", []))
                                    + ", not saved: a reboot restores the saved configuration")
                log_change(entry)
                return entry
        entry["applied"] = [f.control_id for f in fixes if f not in failed]
        if entry["applied"]:
            step("saving the configuration", 90)
            session.save()
            entry["saved"] = True
    finally:
        session.close()
    if failed:
        _collect(device, jump)
        scan.audit_device(device, "change", archive=False)
    step("done", 100)
    entry["outcome"] = "applied and saved" if not failed else "partially applied (some fixes rolled back)"
    log_change(entry)
    return entry


def current_job() -> dict | None:
    with _lock:
        return None if _job is None else json.loads(json.dumps(_job))


def running() -> bool:
    with _lock:
        return bool(_job and not _job["finished"])


def start(selection: dict[str, list[str]]) -> str | None:
    """Apply fixes to several devices, strictly one device after the other."""
    global _job
    from . import firmware, scan
    if not settings()["enabled"]:
        raise PermissionError("remediation is disabled")
    sj = scan.current_job()
    devices = [d for d in inventory.load_devices() if d["id"] in selection and selection[d["id"]]]
    firmware_busy = firmware.running()   # before taking our lock: firmware.start does the reverse
    with _lock:
        if (_job and not _job["finished"]) or (sj and not sj["finished"]) or firmware_busy:
            return None
        _job = {"id": uuid.uuid4().hex[:8], "started": time.time(), "finished": None, "percent": 0,
                "items": {d["id"]: {"status": "queued", "message": "", "outcome": "", "percent": 0} for d in devices}}
        job_id = _job["id"]

    def update(device_id, **kw):
        with _lock:
            _job["items"][device_id].update(kw)
            items = _job["items"].values()
            _job["percent"] = round(sum(i["percent"] for i in items) / max(len(items), 1))

    def run():
        settings_jump = inventory.load_settings().get("jump", {})
        jump = collector.JumpHost(settings_jump) if settings_jump.get("host") else None
        try:
            for device in devices:
                update(device["id"], status="running")
                try:
                    entry = apply_device(device, selection[device["id"]], jump,
                                         lambda m, p=None, d=device["id"]: update(d, message=m, **({"percent": p} if p is not None else {})))
                    update(device["id"], status="done", outcome=entry["outcome"], message="", percent=100)
                except Exception as exc:
                    log_change({"ts": datetime.now().isoformat(timespec="seconds"), "device": device["id"],
                                "controls": selection[device["id"]],
                                "outcome": f"error: {type(exc).__name__}: {exc} (nothing saved)"[:300]})
                    update(device["id"], status="error", outcome=f"{type(exc).__name__}: {exc}"[:300], percent=100)
        finally:
            if jump:
                jump.close()
            with _lock:
                _job["finished"] = time.time()

    threading.Thread(target=run, daemon=True).start()
    return job_id


def fix_dict(fix: Fix) -> dict:
    return asdict(fix)
