# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Security review of 0.20.0 (14/11/2026): each case reproduces a weakness found in the review.
All addresses are documentation ranges (RFC 5737) and all names are fictitious."""

import re

import pytest

from lyss import discovery, inventory, sites, vault
from lyss.web import app as webapp

from test_remediate import FakeSession, lab, passing_after  # noqa: F401  (fixture)
from test_security_review import client, login  # noqa: F401  (fixture)


# ---------------- request bodies ----------------

def test_a_post_without_a_declared_length_is_refused_before_it_is_read(client):
    """A chunked body has no Content-Length: the size limit was skipped, and the public /login
    parsed (and spooled to disk) whatever was sent, without a session."""
    def endless():
        for _ in range(64):
            yield b"x" * 65536

    r = client.post("/login", content=endless(), headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 411
    r = client.post("/login", content=b"password=x", headers={"content-type": "application/x-www-form-urlencoded",
                                                             "transfer-encoding": "chunked"})
    assert r.status_code == 411
    # a normal form post still works
    assert client.post("/login", data={"password": "wrong password!"}).status_code in (401, 200)


# ---------------- network paths ----------------

@pytest.mark.parametrize("path", ["\\/attacker/share/key", "/\\attacker\\share\\key", "//attacker/share/key",
                                  "\\\\attacker\\share\\key"])
def test_network_paths_with_mixed_slashes_are_refused(client, path):
    """Windows reads "\\/server/share" and "/\\server\\share" as network paths too: checking the file
    would open an SMB connection and send the NTLM authentication of the account running LYSS."""
    assert webapp._unc(path)
    csrf = login(client)
    r = client.post("/settings/jump", data={"csrf": csrf, "host": "192.0.2.1", "user": "lyss", "key_file": path})
    assert r.status_code == 400 and "network paths" in r.text
    r = client.post("/settings/siem", data={"csrf": csrf, "enabled": "on", "port": "514", "protocol": "udp",
                                            "findings": "all", "file": path + ".jsonl"})
    assert r.status_code == 400


# ---------------- site and discovery ranges ----------------

@pytest.mark.parametrize("bad", ["192.0.2.01-05", "192.0.2.300-301", "192.0.2.20-10", "192.0.2.1-999",
                                 "192.0.2.١-٥", "999.0.2.1-5"])
def test_a_range_that_cannot_be_loaded_is_refused_when_saved(bad):
    """"192.0.2.01-05" passed the check (only "prefix + 0" was validated) and then raised on every
    page that lists the sites: the dashboard and Settings returned 500 until settings.json was edited."""
    assert sites.parse(bad) == ([], [f"{bad}: not an IPv4 address, CIDR (/8 or smaller) or a-b range"])
    nets, errors = discovery.parse_ranges(bad)
    assert nets == [] and len(errors) == 1


def test_valid_ranges_are_kept_and_an_old_bad_one_is_ignored():
    assert sites.parse("192.0.2.10-20 198.51.100.0/24")[0] == ["192.0.2.10-20", "198.51.100.0/24"]
    assert discovery.expand(discovery.parse_ranges("192.0.2.10-12")[0]) == ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
    # saved by an older version: skipped, the page still loads
    assert len(sites._networks({"ranges": ["192.0.2.01-05", "192.0.2.10-20"]})) == 1


# ---------------- stored secrets stay with their destination ----------------

SMTP = {"enabled": "on", "host": "mail.example.net", "port": "587", "security": "starttls", "username": "lyss",
        "sender": "lyss@example.net", "recipients": "admin@example.net", "mode": "regressions"}


def test_a_stored_smtp_password_is_dropped_when_the_server_changes(client):
    """With a stolen session, saving another SMTP server with an empty password kept the stored one,
    and "Send test e-mail" then sent it to that server."""
    csrf = login(client)
    assert client.post("/settings/smtp", data={**SMTP, "csrf": csrf, "password": "fictitious-smtp-pw"}).status_code == 200
    stored = inventory.load_settings()["smtp"]["secret"]
    assert stored
    # same destination, empty password: kept (the normal way to edit recipients)
    client.post("/settings/smtp", data={**SMTP, "csrf": csrf, "password": "", "recipients": "soc@example.net"})
    assert inventory.load_settings()["smtp"]["secret"] == stored
    # another server, or no encryption any more: dropped
    for change in ({"host": "attacker.example.org"}, {"security": "none"}, {"port": "2525"}, {"username": "other"}):
        client.post("/settings/smtp", data={**SMTP, "csrf": csrf, "password": "fictitious-smtp-pw"})
        r = client.post("/settings/smtp", data={**SMTP, **change, "csrf": csrf, "password": ""})
        assert inventory.load_settings()["smtp"]["secret"] == "", change
        assert "enter it again" in r.text


def test_a_stored_ciso_token_and_wazuh_password_are_dropped_when_the_url_changes(client):
    csrf = login(client)
    ciso = {"csrf": csrf, "enabled": "on", "url": "https://ciso.example.net", "evidence_id": "abc-123", "verify_tls": "on"}
    client.post("/settings/ciso", data={**ciso, "token": "fictitious-token"})
    assert inventory.load_settings()["ciso"]["secret"]
    client.post("/settings/ciso", data={**ciso, "token": "", "auto_push": "on"})
    assert inventory.load_settings()["ciso"]["secret"]                       # same URL: kept
    client.post("/settings/ciso", data={**ciso, "token": "", "url": "http://attacker.example.org"})
    assert inventory.load_settings()["ciso"]["secret"] == ""
    client.post("/settings/ciso", data={**ciso, "token": "fictitious-token"})
    client.post("/settings/ciso", data={**{k: v for k, v in ciso.items() if k != "verify_tls"}, "token": ""})
    assert inventory.load_settings()["ciso"]["secret"] == ""                 # certificate check turned off

    watch = {"csrf": csrf, "enabled": "on", "url": "https://wazuh.example.net", "username": "lyss-ro",
             "interval": "5", "verify_tls": "on"}
    client.post("/settings/changes", data={**watch, "password": "fictitious-pw"})
    assert inventory.load_settings()["change_watch"]["secret"]
    client.post("/settings/changes", data={**watch, "password": "", "interval": "10"})
    assert inventory.load_settings()["change_watch"]["secret"]
    client.post("/settings/changes", data={**watch, "password": "", "url": "https://attacker.example.org"})
    assert inventory.load_settings()["change_watch"]["secret"] == ""


def test_a_switch_password_is_never_reused_for_another_address(client):
    """Editing a device's address with an empty password kept the stored one: the next scan sent it
    to the new address, whose SSH host key is not pinned yet."""
    csrf = login(client)
    vendor = sorted(webapp._vendors())[0]
    inventory.save_device({"id": "demo-sw-01", "host": "192.0.2.10", "port": "22", "vendor": vendor,
                           "username": "lyss", "via_jump": False}, "fictitious-switch-pw")
    stored = inventory.get_device("demo-sw-01")["secret"]
    form = {"csrf": csrf, "host": "192.0.2.10", "port": "22", "vendor": vendor, "username": "lyss", "password": ""}
    for change in ({"host": "198.51.100.66"}, {"port": "2222"}, {"username": "other"}):
        r = client.post("/devices/demo-sw-01/edit", data={**form, **change}, follow_redirects=False)
        assert r.status_code == 400 and "enter it again" in r.text, change
        assert inventory.get_device("demo-sw-01")["host"] == "192.0.2.10"
    # nothing about the destination changes: the stored password is kept
    r = client.post("/devices/demo-sw-01/edit", data=form, follow_redirects=False)
    assert r.status_code == 303 and inventory.get_device("demo-sw-01")["secret"] == stored
    # a new address with the password typed again: accepted
    r = client.post("/devices/demo-sw-01/edit", data={**form, "host": "198.51.100.66", "password": "fictitious-switch-pw"},
                    follow_redirects=False)
    assert r.status_code == 303 and inventory.get_device("demo-sw-01")["host"] == "198.51.100.66"
    assert vault.unprotect(inventory.get_device("demo-sw-01")["secret"]) == "fictitious-switch-pw"


# ---------------- SIEM events file ----------------

def test_the_events_file_cannot_be_one_of_the_data_files(client, data_dir):
    """Appending events to settings.json or devices.json broke every page (500)."""
    csrf = login(client)
    siem = {"csrf": csrf, "enabled": "on", "host": "", "port": "514", "protocol": "udp", "findings": "all"}
    for name in ("settings.json", "devices.json", "reachability.json", "results\\x.json", "sub\\lyss-events.jsonl"):
        r = client.post("/settings/siem", data={**siem, "file": str(data_dir / name)})
        assert r.status_code == 400, name
    assert client.post("/settings/siem", data={**siem, "file": str(data_dir / "lyss-events.jsonl")}).status_code == 200
    assert client.post("/settings/siem", data={**siem, "file": str(data_dir.parent / "elsewhere" / "events.jsonl")}).status_code == 200


# ---------------- hostile switch output ----------------

def test_neighbour_parsers_stay_linear_on_long_lines():
    """A lazy group followed by "\\s*$" took quadratic time: 200 lines of 4000 spaces from a switch
    cost 20 to 50 seconds of CPU and stalled the web interface (measured before the fix)."""
    import time
    from lyss import topology
    pad = " " * 4000
    eos = ["Interface Ethernet1 detected 1 LLDP neighbors:", '  Neighbor 0011.2233.4455/"Ethernet1", age 5 seconds']
    for field in ("  Port ID     : a", "  - System Name: a", "  - System Description: a", "  Enabled Capabilities: a"):
        eos += [f"{field}{pad}x\"y"] * 50
    detail = []
    for _ in range(200):
        detail += ["-" * 20, "Local Intf: Gi1/0/1", f"Platform: a{pad}x"]
    started = time.perf_counter()
    topology.parse_eos_lldp(eos)
    rows = topology.parse_neighbor_details(detail)
    assert time.perf_counter() - started < 2.0
    assert len(rows) == 200


def test_neighbour_parsers_read_the_same_values_as_before():
    from lyss import topology
    rows = topology.parse_eos_lldp([
        "Interface Ethernet1 detected 1 LLDP neighbors:",
        '  Neighbor 0011.2233.4455/"Ethernet2", age 5 seconds',
        "    Chassis ID     : 0011.2233.4455",
        '    Port ID     : "Ethernet2"  ',
        '    - System Name: "demo-leaf-02"',
        '    - System Description: "Arista Networks EOS version 4.37.0F"   ',
        "    Enabled Capabilities: Bridge, Router  ",
        "    Port ID     : 0",
    ])
    assert rows[0]["name"] == "demo-leaf-02" and rows[0]["platform"] == "Arista Networks EOS version 4.37.0F"
    assert rows[0]["caps"] == "B, R" and rows[0]["remote_port"] == topology.normalize_port("Ethernet2")
    detail = topology.parse_neighbor_details(["-" * 20, "Device ID: demo-sw-02", "Interface: Gi1/0/1,  Port ID (outgoing port): Gi1/0/2",
                                              "Platform: cisco C1000-24T-4G-L ,  Capabilities: Switch IGMP"])
    assert detail[0]["platform"] == "cisco C1000-24T-4G-L" and detail[0]["caps"] == "Switch IGMP"


def test_no_escape_sequence_reaches_a_terminal():
    """A switch (or a configuration file) can carry terminal escape sequences: OSC 52 writes the
    clipboard, others clear the screen or forge status lines in a log."""
    from lyss import collector
    from lyss.config import printable
    from lyss.engine import redact
    hostile = "\x1b]52;c;ZmFrZQ==\x07% Invalid input \x1bc\x9b2J"
    for text in (printable(hostile), redact("snmp-server location " + hostile), collector.config_refusal(hostile)):
        assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", text), repr(text)
    assert printable("tab\tkept, accents kept: é ع") == "tab\tkept, accents kept: é ع"


def test_a_switch_behind_the_jump_host_is_never_contacted_directly():
    """Without a configured jump host, the address was contacted from the LYSS machine itself:
    another machine with the same private address would have received the credentials."""
    from lyss import collector
    device = {"id": "demo-sw-09", "host": "192.0.2.9", "port": 22, "vendor": "cisco_ios", "via_jump": True}
    with pytest.raises(ValueError, match="jump host"):
        collector.open_session(device, None)


def test_netmiko_output_is_bounded():
    """netmiko keeps everything it reads until the prompt: a switch that never prints it could fill
    the memory. The session counts what is read and stops at the same limit as the shell path."""
    from lyss import collector

    class Conn:
        def read_channel(self):
            return "x" * (1024 * 1024)

    session = object.__new__(collector.NetmikoSession)
    session.conn = Conn()
    session._bound_output()
    with pytest.raises(RuntimeError, match="20 MB"):
        for _ in range(30):
            session.conn.read_channel()


# ---------------- remediation ----------------

def test_a_failed_save_rolls_the_fixes_back(lab, monkeypatch):
    """After a good verification, an error while saving left the fixes live and unsaved, with the
    entry logged as "nothing saved" and no rollback."""
    from lyss import collector, remediate
    device, log = lab

    class NoSave(FakeSession):
        def save(self):
            raise RuntimeError("saving the configuration failed: % Error")
    monkeypatch.setattr(collector, "open_session", lambda d, j: NoSave(log))
    passing_after(monkeypatch, {"LYSS-MGMT-001"})
    entry = remediate.apply_device(device, ["LYSS-MGMT-001"], None, lambda *a: None)
    assert entry["outcome"].startswith("could not save") and "rolled back, not saved" in entry["outcome"]
    assert not entry["saved"] and entry["applied"] == [] and entry["rolled_back"] == ["LYSS-MGMT-001"]
    assert ("configure", "ip telnet server") in log


def test_the_save_connection_failing_rolls_the_fixes_back(lab, monkeypatch):
    from lyss import collector, remediate
    device, log = lab
    opened = []

    def opener(d, j):
        opened.append(1)
        if len(opened) == 2:            # 1 = apply, 2 = save, 3 = rollback
            raise ConnectionError("refused")
        return FakeSession(log)
    monkeypatch.setattr(collector, "open_session", opener)
    monkeypatch.setattr(remediate.time, "sleep", lambda s: None)
    monkeypatch.setattr(remediate, "_open", lambda d, j: collector.open_session(d, j))
    passing_after(monkeypatch, {"LYSS-MGMT-001"})
    entry = remediate.apply_device(device, ["LYSS-MGMT-001"], None, lambda *a: None)
    assert entry["outcome"].startswith("could not save") and not entry["saved"]
    assert entry["rolled_back"] == ["LYSS-MGMT-001"] and ("save", "") not in log

# ---------------- secrets in evidence ----------------

FICTITIOUS = "Zq9FICTIONx7"


@pytest.mark.parametrize("line", [
    "snmp-agent community read cipher {s}", "snmp-agent community read {s}", "snmp-agent community read simple {s}",
    "snmp-agent community write {s} acl 2001", "snmp-agent community write cipher {s} mib-view v acl 2000",
    "snmp-agent community read cipher %^%#{s}%^%#",
    "snmp-agent usm-user v3 demo authentication-mode sha cipher {s}", "snmp-agent usm-user v3 demo privacy-mode aes128 cipher {s}",
    " ospf authentication-mode md5 1 cipher {s}", "ntp-service authentication-keyid 1 authentication-mode md5 cipher {s}",
    'set system root-authentication plain-text-password-value "{s}"', 'set security ike policy p pre-shared-key ascii-text "{s}"',
    "archive-sites ftp://backup:{s}@192.0.2.9/cfg", "/snmp set trap-community={s}",
    "SNMP|x / snmp_rocommunity={s}", "MACSEC|p / primary_cak={s}", "USER|admin / pw_hash={s}",
    "snmp-server host 192.0.2.1 community public community {s}",
])
def test_more_secret_formats_are_redacted(line):
    """On Huawei, the word after "community" is the access right: "read" was redacted and the
    community itself stayed in every report."""
    from lyss.engine import redact
    assert FICTITIOUS not in redact(line.format(s=FICTITIOUS))


def test_a_huawei_community_never_reaches_the_findings():
    from conftest import load_case
    from lyss.engine import audit
    case = load_case("vrp-weak")
    config = case["config"] + f"\nsnmp-agent community read cipher {FICTITIOUS}\nsnmp-agent community write {FICTITIOUS} acl 2001\n"
    findings = audit(config, "huawei_vrp", 3, case.get("state", ""))
    assert FICTITIOUS not in " ".join(e for f in findings for e in f.evidence)
    assert any("snmp-agent community read cipher <redacted>" in e for f in findings for e in f.evidence)


def test_well_known_communities_stay_visible_and_readable_text_is_kept():
    from lyss.engine import redact
    assert redact("snmp-server community public RO") == "snmp-server community public RO"
    assert redact("snmp-agent community read public") == "snmp-agent community read public"
    assert redact(" authentication-mode aaa") == " authentication-mode aaa"
    assert redact(" authentication-mode local radius") == " authentication-mode local radius"


# ---------------- the CI gate ----------------

HIDDEN = ["ip http server", "snmp-server community public RW", "line vty 5 15", " transport input telnet", " no exec-timeout"]


def _audit(tmp_path, text, *extra, name="sw1.cfg"):
    import subprocess
    import sys
    (tmp_path / name).write_text(text, encoding="utf-8")
    return subprocess.run([sys.executable, "-m", "lyss", "audit", "--vendor", "cisco_ios", "--level", "2",
                           "--require-level", "2", *extra, str(tmp_path / name)], capture_output=True, text=True)


@pytest.mark.parametrize("opening, closing", [("banner exec #x#y", "!#"), ("banner exec #", "hello # world\n!#"),
                                               ("banner exec ^C", "press ^ here\n^C"), ("banner exec ^Cx^Cy", "^C")])
def test_configuration_hidden_after_an_early_banner_delimiter_is_refused(tmp_path, opening, closing):
    """IOS ends a typed or loaded banner at the FIRST delimiter character; LYSS only ended it on a
    line ending with the delimiter. Lines in between were configuration for the switch and banner
    text for LYSS: a weak configuration passed the gate."""
    from conftest import load_case
    from lyss.config import structure_problems
    hardened = load_case("ios-hardened")["config"]
    assert _audit(tmp_path, hardened).returncode == 0
    text = hardened + "\n" + opening + "\n" + "\n".join(HIDDEN) + "\n" + closing + "\n"
    assert any("delimiter" in p for p in structure_problems(text, "cisco_ios"))
    r = _audit(tmp_path, text)
    assert r.returncode == 2 and "not as the switch prints it" in r.stderr


def test_ordinary_banners_are_still_accepted():
    from lyss.config import structure_problems
    for banner in ("banner login ^C\nAuthorized access only.\nDisconnect now.\n^C", "banner motd ^CAuthorized access only^C",
                   "banner login #\nAuthorized access only\n#", 'banner motd "Authorized access only"'):
        assert structure_problems("hostname demo-sw\n" + banner + "\nend\n", "cisco_ios") == [], banner


@pytest.mark.parametrize("vendor", ["hp_procurve", "aruba_aoscx", "huawei_vrp", "juniper_junos"])
def test_a_banner_that_never_ends_is_refused_on_every_platform(vendor):
    """Only three platforms were checked: elsewhere "banner motd X" hid the rest of the file."""
    from lyss.config import structure_problems
    assert structure_problems("banner motd X\n" + "\n".join(HIDDEN) + "\n", vendor) == ["a banner or macro that never ends"]


def test_a_gate_on_level_3_assesses_level_3(tmp_path):
    """--level 2 --require-level 3 passed: Level 3 was required but never assessed."""
    from conftest import load_case
    r = _audit(tmp_path, load_case("ios-hardened")["config"])
    assert r.returncode == 0
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-m", "lyss", "audit", "--vendor", "cisco_ios", "--level", "2", "--require-level", "3",
                        str(tmp_path / "sw1.cfg")], capture_output=True, text=True)
    assert r.returncode == 1 and "LYSS-ACC-02" in r.stdout


def test_an_ambiguous_file_is_not_skipped(tmp_path):
    """--skip-unrecognised also skipped a file matching TWO platforms: a weak configuration with a
    banner quoting another vendor's "Model Name" line left the gate without a word."""
    import subprocess
    import sys
    from conftest import load_case
    (tmp_path / "ok.cfg").write_text(load_case("ios-hardened")["config"], encoding="utf-8")
    (tmp_path / "README.txt").write_text("Configurations of the demo lab.\n", encoding="utf-8")
    (tmp_path / "weak.cfg").write_text(load_case("ios-weak")["config"] + "\nbanner exec ^C\nModel Name : GS1900-24E\n^C\n",
                                       encoding="utf-8")
    summary = tmp_path / "summary.md"
    r = subprocess.run([sys.executable, "-m", "lyss", "audit", "--level", "2", "--require-level", "2", "--skip-unrecognised",
                        "--summary", str(summary), str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 2 and "weak.cfg: platform not recognised" in r.stderr
    text = summary.read_text(encoding="utf-8")
    assert "skipped" in text and "README" in text                      # a skipped file is listed


# ---------------- hostile files ----------------

def test_locating_evidence_is_linear():
    """One ".*" per redacted value: a line with many "key=" fields made the regular expression
    backtrack for minutes, and the CI job never wrote its report."""
    import time
    from lyss import ci
    evidence = "/ip service set telnet disabled=no" + " key=<redacted>" * 12 + " comment=END"
    trap = "/ip service set telnet disabled=no" + " key=" * 300 + " x"
    started = time.perf_counter()
    assert ci.locate(trap + "\n" + evidence.replace("<redacted>", "1") + "\n", [evidence]) == 2
    assert time.perf_counter() - started < 1.0
    assert ci.locate("a\nsnmp-server community S3 RO\n", ["snmp-server community <redacted> RO"]) == 2
    assert ci.locate("snmp-server community S3 RW\n", ["snmp-server community <redacted> RO"]) is None
    assert ci.locate("ab\n", ["a<redacted>ab"]) is None


def test_state_rules_stay_linear_on_long_lines():
    import time
    from conftest import load_case
    from lyss.engine import audit
    case = load_case("mikrotik-weak")
    lines = "\n".join(" 1" + " " * 4000 + "a" for _ in range(40))
    state = f"===== /ip service print terse =====\n{lines}\n===== /interface ethernet print terse =====\n{lines}\n"
    started = time.perf_counter()
    audit(case["config"], "mikrotik", 3, state)
    assert time.perf_counter() - started < 5.0


def test_deeply_nested_json_and_odd_accepted_risks_do_not_crash(tmp_path):
    from lyss import accepted
    from lyss.config import parse
    parse('{"DEVICE_METADATA":' + "[" * 200000)                       # RecursionError was not caught
    base = ("accepted_risks:\n  - control: {control}\n    switches: [sw-old-*]\n    reason: End of life, replacement ordered\n"
            "    approved_by: Security officer\n    expires: {expires}\n")
    for control, expires in (("[LYSS-MGMT-001]", "2027-01-01"), ("LYSS-MGMT-001", "2027-01-01 10:00:00")):
        path = tmp_path / "risks.yaml"
        path.write_text(base.format(control=control, expires=expires), encoding="utf-8")
        with pytest.raises(ValueError):
            accepted.load(path)