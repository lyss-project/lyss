# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Regression tests for the security review of LYSS 0.14 (November 2026): each test reproduces
a reported attack or failure and checks that it is now refused. Synthetic data only."""

import json
import re

import pytest
from fastapi.testclient import TestClient

from lyss import ci, collector, firmware, inventory, remediate, scan
from lyss.config import parse
from lyss.web import app as webapp

from test_remediate import PARAMS, FakeSession, failing, lab, passing_after  # noqa: F401  (fixture)

EVIL_SCOPE = "fe80::1%x;id>pwned;#"


# ---------------- addresses that reach a command line ----------------

def test_strict_ip_refuses_ipv6_scope_ids_and_control_characters():
    assert inventory.strict_ip("192.0.2.1") == "192.0.2.1"
    assert inventory.strict_ip("2001:db8::1") == "2001:db8::1"
    for bad in (EVIL_SCOPE, "fe80::2%a$(reboot)", "fe80::1%eth0", "192.0.2.1 ", "192.0.2.1\n", "", None):
        assert inventory.strict_ip(bad) is None, bad
    assert inventory.strict_ip("2001:db8::1", version=4) is None


def test_device_address_with_shell_characters_is_refused():
    errors = inventory.validate_device({"id": "x", "host": EVIL_SCOPE, "vendor": "cisco_ios", "port": 22,
                                        "username": "ro"}, ["cisco_ios"])
    assert errors and "Address" in errors[0]


def test_jump_nc_command_never_gets_a_scope_id():
    jump = collector.JumpHost({"host": "192.0.2.254", "source": "192.0.2.1"})
    with pytest.raises(ValueError):
        jump._nc_channel(None, EVIL_SCOPE, 22, 5)
    jump = collector.JumpHost({"host": "192.0.2.254", "source": "fe80::2%a$(reboot)"})
    with pytest.raises(ValueError):
        jump._nc_channel(None, "192.0.2.10", 22, 5)


def test_remediation_parameters_cannot_inject_commands():
    payload = "fe80::1%x\nusername evil privilege 15 secret 0 Evil-Pass1\ndo write memory"
    assert remediate.validate_params(payload, [], "")
    assert remediate.validate_params("2001:db8::1", [], "")            # IPv4 syntax only
    assert remediate.validate_params("", ["192.0.2.1\x1a"], "")
    # values written to settings.json directly are re-validated when fixes are built
    case, fail = failing("ios-weak")
    fixes = remediate.fixes_for("cisco_ios", parse(case["config"]), fail, {**PARAMS, "syslog": payload})
    log010 = next(f for f in fixes if f.control_id == "LYSS-LOG-010")
    assert log010.blocked and "invalid" in log010.blocked
    assert not any("\n" in c for f in fixes if not f.blocked for c in f.commands)


def test_configure_refuses_control_characters_before_sending_anything():
    with pytest.raises(ValueError):
        collector.check_commands(["logging host 192.0.2.1\nusername evil"])
    with pytest.raises(ValueError):
        collector.check_commands(["end\x1a"])
    collector.check_commands(["banner login #\nAuthorized access only.\n#"], banner_block=True)
    with pytest.raises(ValueError):          # only the SB banner block, and only on the SB shell
        collector.check_commands(["banner login #\nAuthorized access only.\n#"])

    class Conn:
        sent = []

        def config_mode(self):
            self.sent.append("config_mode")
    s = collector.NetmikoSession.__new__(collector.NetmikoSession)
    s.conn = Conn()
    with pytest.raises(ValueError):
        s.configure(["logging host 192.0.2.1\nusername evil"])
    assert Conn.sent == []                   # not even configuration mode


# ---------------- remediation behaviour ----------------

def test_one_rogue_switch_cannot_choose_the_suggested_servers(data_dir):
    honest = "hostname h{n}\nlogging host 192.0.2.10\nntp server 192.0.2.123\n"
    rogue = "hostname r\n" + "logging host 203.0.113.66\n" * 50 + "ntp server 203.0.113.66\n" * 50
    for i, text in enumerate([honest.format(n=1), honest.format(n=2), rogue]):
        inventory.save_device({"id": f"sw{i}", "host": f"192.0.2.{i + 20}", "port": "22", "vendor": "cisco_ios",
                               "username": "ro", "via_jump": False}, "x")
        cfg, _ = collector.config_paths(inventory.get_device(f"sw{i}"))
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(text, encoding="utf-8")
    assert remediate.suggest_defaults() == {"syslog": "192.0.2.10", "ntp": ["192.0.2.123"]}


def test_existing_servers_are_never_resent_nor_removed_by_a_rollback():
    case, fail = failing("ios-weak")
    config = case["config"] + "\nlogging host 192.0.2.60\nntp server 192.0.2.123\n"
    fail = {**fail, "LYSS-LOG-010": {"evidence": []}, "LYSS-LOG-011": {"evidence": []}}
    params = {**PARAMS, "ntp": ["192.0.2.123", "192.0.2.124"]}
    fixes = {f.control_id: f for f in remediate.fixes_for("cisco_ios", parse(config), fail, params)}
    assert fixes["LYSS-LOG-010"].blocked and not fixes["LYSS-LOG-010"].rollback
    ntp = fixes["LYSS-LOG-011"]
    assert ntp.commands == ["ntp server 192.0.2.124"] and ntp.rollback == ["no ntp server 192.0.2.124"]
    assert ntp.verify_config      # verified on the configuration: synchronisation takes minutes


def test_rejected_rollback_is_never_reported_as_done_and_nothing_is_saved(lab, monkeypatch):
    device, log = lab
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeSession(log, reject="no logging host 192.0.2.60"))
    passing_after(monkeypatch, {"LYSS-MGMT-001"})                     # LOG-010 does not verify
    entry = remediate.apply_device(device, ["LYSS-MGMT-001", "LYSS-LOG-010"], None, lambda *a: None)
    assert entry["outcome"].startswith("ROLLBACK FAILED") and not entry["saved"]
    assert ("save", "") not in log and "LYSS-LOG-010" not in entry["rolled_back"]


def test_any_error_while_sending_triggers_the_rollback(lab, monkeypatch):
    device, log = lab

    class NetmikoDies(FakeSession):
        def configure(self, commands):
            if commands == ["logging host 192.0.2.60"]:
                raise ValueError("Failed to exit configuration mode")      # not a socket error
            return super().configure(commands)
    sessions = []
    monkeypatch.setattr(collector, "open_session",
                        lambda d, j: sessions.append(1) or (NetmikoDies(log) if len(sessions) == 1 else FakeSession(log)))
    entry = remediate.apply_device(device, ["LYSS-MGMT-001", "LYSS-LOG-010"], None, lambda *a: None)
    assert "rolled back, not saved" in entry["outcome"] and len(sessions) == 2
    assert ("configure", "ip telnet server") in log and ("save", "") not in log


def test_an_incomplete_change_blocks_the_next_one_until_a_scan(lab, monkeypatch):
    device, log = lab
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeSession(log, reject="no logging host 192.0.2.60"))
    passing_after(monkeypatch, {"LYSS-MGMT-001"})
    remediate.apply_device(device, ["LYSS-MGMT-001", "LYSS-LOG-010"], None, lambda *a: None)
    assert remediate.unclean_change("lab")
    again = remediate.apply_device(device, ["LYSS-MGMT-001"], None, lambda *a: None)
    assert again["outcome"].startswith("refused")
    s = inventory.load_settings()
    s["remediation"]["firmware"] = True
    inventory.save_settings(s)
    monkeypatch.setattr(firmware, "eligible", lambda d: True)
    with pytest.raises(ValueError, match="incomplete"):
        firmware.start("activate", "lab")
    import time
    time.sleep(1.1)                                                   # timestamps have 1 s resolution
    monkeypatch.undo()
    scan.audit_device(inventory.get_device("lab"), "manual")
    assert remediate.unclean_change("lab") == ""


def test_firmware_upgrades_are_off_by_default(lab):
    with pytest.raises(ValueError, match="not allowed"):
        firmware.start("activate", "lab")


# ---------------- web interface ----------------

@pytest.fixture
def client(data_dir):
    webapp._sessions.clear()
    webapp._failures.update(count=0, locked_until=0, inflight=0)
    return TestClient(webapp.app, base_url="http://127.0.0.1:8765")


def login(c):
    r = c.post("/setup", data={"password": "correct horse battery", "confirm": "correct horse battery"},
               follow_redirects=False)
    assert r.status_code == 303
    return re.search(r'name="csrf" value="([^"]+)"', c.get("/settings").text).group(1)


def test_dns_rebinding_host_names_are_refused(client, monkeypatch):
    assert client.get("/health", headers={"host": "attacker.example:8765"}).status_code == 421
    r = client.post("/setup", headers={"host": "attacker.example:8765", "origin": "http://attacker.example:8765",
                                       "sec-fetch-site": "same-origin"},
                    data={"password": "x" * 12, "confirm": "x" * 12}, follow_redirects=False)
    assert r.status_code == 421 and inventory.load_settings().get("admin") is None
    monkeypatch.setenv("LYSS_ALLOWED_HOSTS", "lyss.example.org")
    assert client.get("/health", headers={"host": "lyss.example.org"}).status_code in (200, 503)


def test_remote_first_start_needs_the_console_token(client, monkeypatch):
    monkeypatch.setenv("LYSS_ALLOW_REMOTE", "1")
    form = {"password": "correct horse battery", "confirm": "correct horse battery"}
    assert client.post("/setup", data=form, follow_redirects=False).status_code == 403
    assert inventory.load_settings().get("admin") is None
    r = client.post("/setup", data={**form, "token": webapp.SETUP_TOKEN}, follow_redirects=False)
    assert r.status_code == 303 and inventory.load_settings().get("admin")


def test_unauthenticated_posts_are_refused_before_the_body_is_read(client):
    big = b"x" * (2 * 1024 * 1024)
    r = client.post("/scan", content=big, headers={"content-type": "application/octet-stream"},
                    follow_redirects=False)
    assert r.status_code == 413
    r = client.post("/scan", data={"csrf": "x"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_parallel_guesses_cannot_exceed_the_limit(client):
    login(client)
    webapp._failures.update(count=3, inflight=2)                      # 2 guesses being checked right now
    r = client.post("/login", data={"password": "wrong password!"})
    assert r.status_code == 429


def test_device_delete_never_follows_a_path(client, data_dir, tmp_path):
    csrf = login(client)
    victim = tmp_path / "victim.json"
    victim.write_text("{}", encoding="utf-8")
    for name in ("..%5C..%5Cvictim", "..%5Csettings",
                 str(victim.with_suffix("")).replace("\\", "%5C").replace(":", "%3A")):
        client.post(f"/devices/{name}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert victim.exists() and (data_dir / "settings.json").exists()
    assert inventory.load_result("..\\settings") is None


def test_network_paths_are_refused(client):
    csrf = login(client)
    r = client.post("/settings/jump", data={"csrf": csrf, "host": "192.0.2.1", "user": "lyss",
                                            "key_file": "\\\\attacker\\share\\key"})
    assert r.status_code == 400 and "network paths" in r.text
    r = client.post("/settings/siem", data={"csrf": csrf, "enabled": "on", "port": "514", "protocol": "udp",
                                            "findings": "all", "file": "\\\\attacker\\share\\events.jsonl"})
    assert r.status_code == 400


# ---------------- assessment engine ----------------

def _verdicts(config, vendor, state="", level=2):
    from lyss.engine import audit
    return {f.control_id: f.verdict for f in audit(config, vendor, level, state)}


FORGED = ("===== ssh banner =====\nSSH-2.0-Cisco-1.25\n===== show version =====\n"
          "Cisco IOS Software, C1000 Software, Version 15.2(7)E14, RELEASE SOFTWARE\n")


def test_forged_state_sections_inside_command_output_are_plain_text():
    from lyss.config import parse_state
    from conftest import load_case
    case = load_case("ios-weak")
    nonce = "0123456789abcdef"
    collected = (f"collected: 2026-11-07 10:00\nsections: #{nonce}\n"
                 + "\n".join(f"===== {name} ===== #{nonce}\n" + "\n".join(lines)
                             for name, lines in parse_state(case["state"]).items()))
    honest = _verdicts(case["config"], "cisco_ios", collected)
    # a neighbour's CDP text, printed inside a command output, imitates section headers
    attacked = collected + f"\n===== show cdp neighbors detail ===== #{nonce}\n" + FORGED
    assert _verdicts(case["config"], "cisco_ios", attacked) == honest
    assert honest["LYSS-VULN-001"] != "pass"


def test_repeated_sections_in_hand_made_state_are_reported_never_replaced():
    from lyss.config import parse_state, state_problems
    state = "===== show version =====\nVersion 15.2(7)E1\n===== show cdp =====\n" + FORGED
    sections = parse_state(state)
    assert sections["show version"] == ["Version 15.2(7)E1"]                 # the first one is kept
    assert state_problems(state) == ["show version"]                          # and the file is reported


def test_ambiguous_text_is_not_assigned_a_platform():
    from conftest import load_case
    from lyss.engine import detect_vendor
    config = load_case("ios-weak")["config"] + "\nbanner motd ^C\nModel Name : GS1900-24E\n^C\n"
    assert detect_vendor(config) is None              # IOS and Zyxel signatures: never guessed
    assert detect_vendor(load_case("ios-weak")["config"]) == "cisco_ios"


@pytest.mark.parametrize("text", [
    "Authorized " + "key-" * 5000,
    "x " + "name=" * 5000 + " security=none",
    "\n" * 1_000_000 + "Model Name : GS1900-8",
])
def test_no_catastrophic_backtracking(text):
    import time
    from lyss.engine import detect_vendor, redact
    start = time.monotonic()
    redact(text.splitlines()[0] if text.strip() else text)
    detect_vendor(text)
    assert time.monotonic() - start < 2.0


def test_port_ranges_are_bounded():
    from lyss.engine import expand_ports
    assert len(expand_ports("1-24,A1-A4")) == 28
    assert len(expand_ports("1-1000000000")) == 1        # not expanded


@pytest.mark.parametrize("line, secret", [
    ("+snmp-server user bob G v3 auth sha AUTHPW1 priv aes 128 PRIVPW1", "PW1"),
    ('+snmpv3 user "bob" auth sha "AUTHHASH1" priv aes "PRIVHASH1"', "HASH1"),
    ("encrypted snmp-server user bob G v3 auth sha AUTHHEX1 priv PRIVHEX1", "HEX1"),
    ("snmp-server host 192.0.2.1 version 2c MYCOMM1", "MYCOMM1"),
    ("snmp-server host 192.0.2.1 traps MYCOMM2", "MYCOMM2"),
    ("/snmp community add name=MYCOMM3 addresses=192.0.2.0/24", "MYCOMM3"),
    ('/snmp community set [ find default=yes ] name="MYCOMM4"', "MYCOMM4"),
    ("ntp authentication-key 1 md5 CLEARNTP1 7", "CLEARNTP1"),
    (" ip ospf message-digest-key 1 md5 CLEAROSPF1", "CLEAROSPF1"),
    ('key "CLEAR KEY WITH SPACE"', "WITH SPACE"),
    ('password "CLEAR PW WITH SPACE"', "WITH SPACE"),
    ('/radius add address=192.0.2.9 secret="CLEAR KEY2"', "KEY2"),
    ("/interface wireless security-profiles set default wpa2-pre-shared-key=CLEARPSK1", "CLEARPSK1"),
    ("/interface wifi security add passphrase=CLEARPASS1", "CLEARPASS1"),
    (" wpa-psk ascii 0 CLEARWPA1", "CLEARWPA1"),
    ("Password: CLEARSTATE1", "CLEARSTATE1"),
])
def test_secrets_that_used_to_escape_redaction(line, secret):
    from lyss.engine import redact
    assert secret not in redact(line), redact(line)


def test_private_key_blocks_are_hidden_in_differences():
    from lyss.engine import redact_lines
    # markers assembled at run time: no key-shaped block in the source (secret scanners)
    kind = "RSA " + "PRIVATE" + " KEY"
    body = "FICTITIOUS" + "-BODY-" + "LINE"
    diff = ["+crypto key import", f"+-----BEGIN {kind}-----", f"+{body}", f"+-----END {kind}-----", "+hostname x"]
    out = redact_lines(diff)
    assert body not in "\n".join(out) and out[-1] == "+hostname x"


def _ios_hardened(replace=(), extra=""):
    from conftest import load_case
    text = load_case("ios-hardened")["config"]
    for old, new in replace:
        assert old in text, old
        text = text.replace(old, new, 1)
    return text.replace("\nend\n", f"\n{extra}\nend\n") if extra else text


def test_ios_hardened_baseline_passes_what_the_variants_break():
    v = _verdicts(_ios_hardened(), "cisco_ios")
    for control in ("LYSS-AUTH-002", "LYSS-AUTH-003", "LYSS-AUTH-004", "LYSS-MGMT-004", "LYSS-AUTH-010",
                    "LYSS-LOG-010", "LYSS-MGMT-002"):
        assert v[control] == "pass", control


@pytest.mark.parametrize("variant, control", [
    ({"extra": "username backdoor privilege 15 nopassword"}, "LYSS-AUTH-002"),
    ({"extra": "username backdoor privilege 15 nopassword"}, "LYSS-AUTH-003"),
    ({"replace": [(" server name NPS", " server-private 192.0.2.51 key CLEARTEXTKEY")]}, "LYSS-AUTH-004"),
    ({"replace": [("line vty 0 4\n access-class MGMT in\n exec-timeout 10 0",
                   "line vty 0 4\n access-class MGMT in\n exec-timeout 0 86400")]}, "LYSS-MGMT-004"),
    ({"replace": [("aaa authentication login default group NPS-GRP local",
                   "aaa authentication login WEBUI group NPS-GRP local")]}, "LYSS-AUTH-010"),
    # configuration words inside a multi-line banner never count as configuration
    ({"replace": [("logging host 192.0.2.60\n", ""), ("ip ssh version 2\n", ""),
                  ("banner login ^CAuthorized access only. Activity is logged.^C",
                   "banner login ^C\nAuthorized access only.\nlogging host 192.0.2.60\nip ssh version 2\n^C")]},
     "LYSS-LOG-010"),
])
def test_configurations_that_used_to_pass_now_fail(variant, control):
    config = _ios_hardened(variant.get("replace", ()), variant.get("extra", ""))
    assert _verdicts(config, "cisco_ios")[control] != "pass"


def test_a_routeros_like_line_never_rewrites_another_platform():
    config = _ios_hardened([("enable algorithm-type scrypt secret 9", "enable secret 5 $1$fake$fakefakefake\n"
                             "enable algorithm-type scrypt secret 9")],
                           extra="banner motd ^C\n/x\n^C")
    assert _verdicts(config, "cisco_ios")["LYSS-AUTH-002"] == "fail"


def test_absent_state_rule_does_not_pass_on_a_cli_error():
    from conftest import load_case
    case = load_case("sb-weak")
    config = "\n".join(l for l in case["config"].splitlines() if "telnet" not in l)
    state = "===== show services tcp-udp =====\n% Unrecognized command\n"
    assert _verdicts(config, "cisco_sb", state)["LYSS-MGMT-001"] != "pass"


def test_sonic_json_names_cannot_inject_configuration_lines():
    from conftest import load_case
    case = load_case("sonic-weak")
    data = json.loads(case["config"])
    honest = _verdicts(case["config"], "sonic", case["state"])
    data.setdefault("DEVICE_METADATA", {})["x\nAAA|authentication\n  login=tacacs+,local\nTACPLUS_SERVER|192.0.2.9"] = {}
    attacked = _verdicts(json.dumps(data), "sonic", case["state"])
    assert attacked["LYSS-AUTH-010"] == honest["LYSS-AUTH-010"] != "pass"


@pytest.mark.parametrize("extra, control", [
    ("/ip service set telnet disabled=yes\n/ip service enable telnet", "LYSS-MGMT-001"),
    ('/ip service set telnet comment="disabled=yes"', "LYSS-MGMT-001"),
    ('/snmp set enabled=yes\n/snmp community set [ find default=yes ] name="public"', "LYSS-AUTH-001"),
])
def test_routeros_overrides_and_quotes(extra, control):
    from conftest import load_case
    case = load_case("mikrotik-hardened")
    # without the hardened case's own telnet / snmp lines: only the lines under test decide
    keep = [l for l in case["config"].splitlines() if not re.search(r"telnet|^/snmp", l)]
    assert _verdicts("\n".join(keep) + "\n/ip service set telnet disabled=yes\n", "mikrotik")["LYSS-MGMT-001"] == "pass"
    config = "\n".join(keep) + "\n" + extra + "\n"
    assert _verdicts(config, "mikrotik")[control] != "pass"   # configuration only (Oxidized backup)


def test_ci_gate_does_not_vouch_for_a_file_it_could_not_assess(tmp_path):
    from lyss.__main__ import main
    (tmp_path / "version.txt").write_text("Model Name : GS1900-24E\nFirmware Version : V2.90(AAHK.2) | 10/01/2026\n",
                                          encoding="utf-8")
    assert main(["audit", "--require-level", "1", str(tmp_path)]) in (1, 2)   # firmware only: never vouched for
    assert main(["audit", str(tmp_path)]) == 0                              # report-only still works


def test_wrong_switch_password_is_tried_once_only(data_dir):
    """Cisco SB asks "User Name:" again after a wrong password: an authentication error, never
    retried (two failed logins per scan could lock the account)."""
    import time
    import paramiko
    from lyss.sim import Simulator, load_lab
    sim = Simulator(load_lab("demo"), base_port=0).start()
    try:
        sim.pin_host_keys()
        sw = next(s for s in sim.lab.switches.values() if s.platform == "cisco_sb")
        inventory.save_device({"id": sw.id, "host": "127.0.0.1", "port": sw.port, "vendor": "cisco_sb",
                               "username": sim.lab.credentials["username"], "via_jump": False}, "Wrong-Pass-123")
        start = time.monotonic()
        with pytest.raises(paramiko.AuthenticationException):
            collector.collect_device(inventory.get_device(sw.id), None)
        assert time.monotonic() - start < 20
        updates = []
        collector.collect_many([inventory.get_device(sw.id)], {}, lambda d, s, m: updates.append(s))
        assert updates.count("retrying") == 0 and updates[-1] == "error"
    finally:
        sim.stop()


def test_hand_made_file_with_unindented_block_commands_is_refused(tmp_path, capsys):
    from lyss.__main__ import main
    config = _ios_hardened([("line vty 0 4\n access-class MGMT in\n exec-timeout 10 0",
                             "line vty 0 4\n access-class MGMT in\nexec-timeout 0 0")])
    (tmp_path / "crafted.cfg").write_text(config, encoding="utf-8")
    assert main(["audit", "--vendor", "cisco_ios", str(tmp_path)]) == 2
    assert "not indented" in capsys.readouterr().err
    (tmp_path / "crafted.cfg").write_text(_ios_hardened(), encoding="utf-8")   # device output: accepted
    assert main(["audit", "--vendor", "cisco_ios", str(tmp_path)]) == 0


def test_hp_serial_console_timeout():
    from conftest import load_case
    config = load_case("hp-hardened")["config"] + "\nconsole idle-timeout serial-usb 0\n"
    assert _verdicts(config, "hp_procurve")["LYSS-MGMT-004"] == "fail"


def test_sb_remediation_never_guesses_the_previous_state():
    case, fail = failing("sb-weak")
    no_ports = parse(case["config"], "")                                    # services not collected
    fixes = {f.control_id: f for f in remediate.fixes_for("cisco_sb", no_ports, fail, PARAMS)}
    assert fixes["LYSS-VULN-001"].blocked and not fixes["LYSS-VULN-001"].commands
    with_banner = parse(case["config"] + "\nbanner login ^\nWelcome\n^\n", case["state"])
    fixes = {f.control_id: f for f in remediate.fixes_for("cisco_sb", with_banner, {**fail, "LYSS-MGMT-012": {}}, PARAMS)}
    assert "already configured" in fixes["LYSS-MGMT-012"].blocked


def test_firmware_activation_keeps_a_fallback_and_never_leaves_a_boot_change_armed(data_dir, monkeypatch):
    from test_firmware import DATA, NAME, FakeC1000
    import hashlib
    firmware.save_image(NAME, DATA, hashlib.md5(DATA).hexdigest())
    device = {"id": "c1000-lab", "host": "192.0.2.17", "port": 22, "vendor": "cisco_ios", "via_jump": False}
    old = "flash:/c1000-universalk9-mz.152-7.E8/c1000-universalk9-mz.152-7.E8.bin"
    firmware._set_state("c1000-lab", status="staged", image=NAME, version="15.2(7)E14", boot_before=old)
    target = firmware.bin_path(NAME)

    class Switch(FakeC1000):
        boot = old

        def configure(self, commands):
            for c in commands:
                if c.startswith("boot system "):
                    Switch.boot = c[len("boot system "):]
                elif c == "no boot system":
                    Switch.boot = ""
            return super().configure(commands)

        def run(self, command, timeout):
            return f"BOOT path-list      : {Switch.boot}" if command == "show boot" else super().run(command, timeout)
    log = []
    switch = Switch(log)
    switch.conn = type("C", (), {"send_command_timing": lambda s, c, **k: log.append(("timing", c)) or ""})()
    monkeypatch.setattr(collector, "open_session", lambda d, j: switch)
    with pytest.raises(RuntimeError, match="boot variable restored"):        # no "[confirm]" prompt
        firmware.activate(device, None, lambda m: None)
    assert ("configure", f"boot system {target};{old}") in log              # previous image as fallback
    assert Switch.boot == old                                                 # restored, nothing armed


def test_two_settings_writers_keep_both_changes(data_dir):
    first, second = inventory.load_settings(), inventory.load_settings()   # e.g. two browser tabs
    first["level3"] = True
    second["retention_days"] = 30
    inventory.save_settings(first)
    inventory.save_settings(second)
    saved = inventory.load_settings()
    assert saved["level3"] is True and saved["retention_days"] == 30
    second.pop("retention_days")                                              # deletions are kept too
    inventory.save_settings(second)
    assert "retention_days" not in inventory.load_settings() and inventory.load_settings()["level3"] is True


def test_discovered_switches_are_not_scanned_by_default():
    from pathlib import Path
    template = (Path(webapp.__file__).parent / "templates" / "discovery.html").read_text(encoding="utf-8")
    box = re.search(r'<input type="checkbox" name="scan_now"[^>]*>', template).group(0)
    assert "checked" not in box and "not verified" in template and "outside your sites" in template


# ---------------- second review (bypasses of the first fixes) ----------------

def test_reaudit_never_clears_an_incomplete_change(lab, monkeypatch):
    from lyss.web import app as web
    device, log = lab
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeSession(log, reject="no logging host 192.0.2.60"))
    passing_after(monkeypatch, {"LYSS-MGMT-001"})
    remediate.apply_device(device, ["LYSS-MGMT-001", "LYSS-LOG-010"], None, lambda *a: None)
    monkeypatch.undo()
    import time
    time.sleep(1.1)
    web._reaudit("lab")                                                    # no connection to the switch
    assert remediate.unclean_change("lab")
    for _ in range(3):                                                     # refused attempts keep the state
        assert remediate.apply_device(device, ["LYSS-MGMT-001"], None, lambda *a: None)["outcome"].startswith("refused")
    for i in range(600):                                                   # many other changes in the log
        remediate.log_change({"device": f"other-{i}", "outcome": "applied and saved"})
    assert remediate.unclean_change("lab")


@pytest.mark.parametrize("banner", [
    "banner login ^C\nAuthorized only. Press ^C to disconnect.\nlogging host 192.0.2.60\nip ssh version 2\n^C",
    "banner motd ^CPress ^C to quit\nlogging host 192.0.2.60\nip ssh version 2\n^C",
])
def test_a_delimiter_inside_the_banner_text_does_not_end_it(banner):
    config = _ios_hardened([("logging host 192.0.2.60\n", ""), ("ip ssh version 2\n", ""),
                            ("banner login ^CAuthorized access only. Activity is logged.^C", banner)])
    v = _verdicts(config, "cisco_ios")
    assert v["LYSS-LOG-010"] != "pass" and v["LYSS-MGMT-002"] != "pass"


def test_unclosed_banner_and_indented_headers_are_refused_in_ci():
    from conftest import load_case
    from lyss.config import structure_problems
    weak = load_case("ios-weak")["config"]
    assert "a banner or macro that never ends" in structure_problems("banner motd ^C\n" + weak, "cisco_ios")
    indented = weak.replace("\nline vty 0 4", "\n line vty 0 4")
    assert any("line vty" in p for p in structure_problems(indented, "cisco_ios"))


def test_macro_bodies_are_not_configuration():
    from lyss.config import structure_problems
    config = _ios_hardened([("logging host 192.0.2.60\n", "")],
                           extra="macro name EDGE\nlogging host 192.0.2.60\nswitchport mode access\n@")
    assert _verdicts(config, "cisco_ios")["LYSS-LOG-010"] != "pass"
    assert structure_problems(config, "cisco_ios") == []                   # device output stays accepted


def test_section_header_parsing_is_linear():
    import time
    from lyss.config import parse_state
    start = time.monotonic()
    parse_state(("=====" + " " * 4090 + "x\n") * 200)
    assert time.monotonic() - start < 1.0


@pytest.mark.parametrize("line, secret", [
    ("username bob privilege 15 password 0 correct horse battery", "horse battery"),
    ("radius-server key my shared radius key", "shared radius key"),
    ("snmp-server user u G v3 auth sha AUTHX priv aes256 PRIVZ", "PRIVZ"),
    ("snmp-server user u G v3 auth md5 AUTHX priv des56 PRIVY", "PRIVY"),
    ("snmp-server host 192.0.2.1 vrf MGMT REALCOMM4", "REALCOMM4"),
    ('/user add name=u password="x\\" LEAKME"', "LEAKME"),
    ("standby 1 authentication HSRPTXT1", "HSRPTXT1"),
    ("vrrp 1 authentication text VRRPTXT1", "VRRPTXT1"),
    ("pre-shared-key local IKEPSK1", "IKEPSK1"),
    ("Password : STATEPW1", "STATEPW1"),
    ("password:STATEPW2", "STATEPW2"),
    ("community: STATECOMM1", "STATECOMM1"),
    ("Community name: STATECOMM2", "STATECOMM2"),
])
def test_more_secret_formats(line, secret):
    from lyss.engine import redact
    assert secret not in redact(line), redact(line)


def test_ci_refuses_repeated_state_sections_and_empty_files(tmp_path, capsys):
    from conftest import load_case
    from lyss.__main__ import main
    case = load_case("ios-weak")
    (tmp_path / "sw.cfg").write_text(case["config"], encoding="utf-8")
    (tmp_path / "sw.state.txt").write_text("===== show version =====\nx\n===== show version =====\ny\n", encoding="utf-8")
    assert main(["audit", "--vendor", "cisco_ios", str(tmp_path)]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "s.json").write_text('{"PORT": {}}', encoding="utf-8")
    assert main(["audit", "--require-level", "1", str(empty)]) != 0


def test_retention_without_limit_keeps_every_version(data_dir, monkeypatch):
    from datetime import datetime, timedelta
    from lyss import history
    device, _, _ = add_switch_plain()
    clock = {"now": datetime(2026, 1, 1, 0, 0, 0)}
    monkeypatch.setattr(history, "_now", lambda: clock["now"])
    for i, text in enumerate(("hostname v1\n", "hostname v2\n", "hostname v3\n")):
        clock["now"] += timedelta(minutes=1)
        history.archive_config(device["id"], text, "schedule")
    for _ in range(history.KEEP_INDEX + 5):
        clock["now"] += timedelta(minutes=1)
        history.archive_config(device["id"], "hostname v3\n", "schedule")
    assert len(history.versions(device["id"])) == 3
    clock["now"] += timedelta(minutes=1)
    history.archive_config(device["id"], "hostname v4\n", "schedule")
    history.archive_config(device["id"], "hostname v5\n", "schedule")          # same second
    assert {history.read_version(device["id"], v["file"]) for v in history.versions(device["id"])} >= {"hostname v4\n", "hostname v5\n"}


def test_nested_settings_changes_are_both_kept(data_dir):
    inventory.save_settings({**inventory.load_settings(), "remediation": {"enabled": True, "firmware": True, "syslog": ""}})
    a, b = inventory.load_settings(), inventory.load_settings()
    a["remediation"]["firmware"] = False
    inventory.save_settings(a)
    b["remediation"]["syslog"] = "192.0.2.60"
    inventory.save_settings(b)
    assert inventory.load_settings()["remediation"] == {"enabled": True, "firmware": False, "syslog": "192.0.2.60"}


def test_host_header_needs_a_numeric_port(client):
    assert client.get("/health", headers={"host": "localhost:8765@evil.example"}).status_code == 421
    assert client.get("/health", headers={"host": "[::1]evil.example"}).status_code == 421
    assert client.get("/health", headers={"host": "127.0.0.1:8765"}).status_code in (200, 503)


def test_remediation_servers_must_be_real_servers():
    for bad in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "224.0.0.1"):
        assert remediate.validate_params(bad, [], "")


def add_switch_plain():
    inventory.save_device({"id": "lab-sw", "host": "192.0.2.10", "port": "22", "vendor": "cisco_ios",
                           "username": "ro", "via_jump": False}, "x")
    d = inventory.get_device("lab-sw")
    return d, None, None


# ---------------- offline audit / CI ----------------

def test_links_are_not_followed(tmp_path):
    from lyss.__main__ import config_files, main
    outside = tmp_path / "outside.cfg"
    outside.write_text("hostname secret-other-switch\n", encoding="utf-8")
    folder = tmp_path / "configs"
    folder.mkdir()
    try:
        (folder / "link.cfg").symlink_to(outside)
    except OSError:
        pytest.skip("this system does not allow creating symbolic links")
    assert config_files(folder, recursive=True) == []
    link_dir = tmp_path / "linked"
    link_dir.symlink_to(folder, target_is_directory=True)
    assert main(["audit", str(link_dir)]) == 2


def test_huge_files_are_not_read(tmp_path, monkeypatch, capsys):
    from lyss import __main__ as cli
    monkeypatch.setattr(cli, "MAX_CONFIG_BYTES", 100)
    (tmp_path / "big.cfg").write_text("hostname x\n" * 50, encoding="utf-8")
    assert cli.main(["audit", str(tmp_path)]) == 2
    assert "larger than" in capsys.readouterr().err


def test_summary_stays_below_the_github_limit():
    results = [{"device": "x" * 5000 + str(i), "vendor": "cisco_ios",
                "summary": {"achieved_level": 0, "pass": 0, "fail": 1, "unknown": 0},
                "findings": [{"control_id": "LYSS-MGMT-001", "title": "t", "level": 1, "verdict": "fail",
                              "evidence": ["e" * 500]}]} for i in range(3000)]
    text = ci.summary_markdown(results, "0.6.0-draft", 2, 1, problems=["p" * 5000] * 500)
    assert len(text.encode()) < 1024 * 1024 and "see the JSON results" in text


def test_kev_feed_text_cannot_start_a_workflow_command(tmp_path, capsys):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import kev_watch
    feed = {"catalogVersion": "1", "vulnerabilities": [
        {"cveID": "CVE-2099-0001", "vendorProject": "MikroTik", "product": "RouterOS\n::error title=x::injected",
         "dateAdded": "2099-01-01", "vulnerabilityName": "x"}]}
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(feed), encoding="utf-8")
    kev_watch.main(["--kev", str(path)])
    assert not any(l.startswith("::") for l in capsys.readouterr().out.splitlines())
