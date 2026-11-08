# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Management reachability: the probe (TCP connect only, on 127.0.0.1), the import of an untrusted
result file, and its effect on LYSS-MGMT-010 / MGMT-001 / MGMT-003. Synthetic data."""

import json
import re
import socket
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from lyss import collector, inventory, reachability, scan
from lyss.__main__ import main
from lyss.engine import observed_failures
from lyss.web import app as webapp

from conftest import load_case


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    yield s.getsockname()[1]
    s.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_probe_sees_open_and_closed_ports_and_sends_nothing(listener):
    closed = free_port()
    report = reachability.probe(["127.0.0.1"], [listener, closed], timeout=1)
    states = {r["port"]: r["state"] for r in report["results"]}
    # Windows retries a refused loopback connection for about 2 s: "filtered" with a 1 s timeout
    assert states[listener] == "open" and states[closed] in ("closed", "filtered")
    assert report["kind"] == "reachability" and report["results"][0]["source_ip"] in ("127.0.0.1", "")


def test_probe_accepts_ip_addresses_only():
    for bad in ("switch.example", "192.0.2.1; rm -rf /", "fe80::1%eth0"):
        with pytest.raises(ValueError):
            reachability.probe([bad], [22])


def test_cli_probe_writes_a_file(tmp_path, listener, capsys):
    out = tmp_path / "probe.json"
    assert main(["probe", "127.0.0.1", "--ports", str(listener), "--out", str(out), "--timeout", "1"]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["results"][0]["state"] == "open"
    assert "OPEN" in capsys.readouterr().out


def report(results, started=None):
    return {"kind": "reachability", "started": started or datetime.now().isoformat(timespec="seconds"),
            "source": {"hostname": "pc-test"}, "results": results}


def test_import_refuses_untrusted_content(data_dir):
    for bad in ({"kind": "other", "results": []},
                report([{"target": "not-an-ip", "port": 22, "state": "open"}]),
                report([{"target": "192.0.2.10", "port": 70000, "state": "open"}]),
                report([{"target": "192.0.2.10", "port": True, "state": "open"}]),
                report([{"target": "192.0.2.10", "port": 22, "state": "<script>"}])):
        with pytest.raises(ValueError):
            reachability.import_report(bad, "x", False)


def test_import_keeps_only_open_management_ports_of_known_switches(data_dir):
    device()
    entry = reachability.import_report({**report([
        {"target": "192.0.2.10", "port": 22, "state": "open"},
        {"target": "192.0.2.10", "port": 22, "state": "open"},          # duplicate
        {"target": "192.0.2.10", "port": 9100, "state": "open"},        # not a management port
        {"target": "192.0.2.10", "port": 23, "state": "closed"},
        {"target": "203.0.113.5", "port": 22, "state": "open"}],         # not in the inventory
        started="2099-12-31T00:00:00"), "source": "not a dict"}, "x", False)
    assert entry["results"] == [{"target": "192.0.2.10", "port": 22, "service": "ssh", "state": "open", "source_ip": ""}]
    assert entry["date"] <= datetime.now().isoformat() and entry["targets"] == 1   # future date capped


def test_ipv4_mapped_addresses_match_the_switch(data_dir):
    d = device()
    reachability.import_report(report([{"target": "::ffff:192.0.2.10", "port": 22, "state": "open"}]), "x", False)
    assert [o["port"] for o in reachability.for_device(d)] == [22]


def test_probe_refuses_non_switch_addresses_and_port_scans():
    for bad in (["0.0.0.0"], ["224.0.0.1"], ["255.255.255.255"]):
        with pytest.raises(ValueError):
            reachability.probe(bad, [22])
    with pytest.raises(ValueError):
        reachability.probe(["192.0.2.1"], list(range(1, 100)))


def test_targets_file_written_by_powershell_is_read(tmp_path, listener):
    for encoding in ("utf-8-sig", "utf-16"):
        f = tmp_path / "switches.txt"
        f.write_text("127.0.0.1\n", encoding=encoding)
        out = tmp_path / "p.json"
        assert main(["probe", "--targets-file", str(f), "--ports", str(listener), "--out", str(out), "--timeout", "1"]) == 0


def device(host="192.0.2.10"):
    inventory.save_device({"id": "sw-a", "host": host, "port": "22", "vendor": "cisco_ios", "username": "ro",
                           "via_jump": False}, "x")
    return inventory.get_device("sw-a")


def test_observations_make_controls_fail_never_pass(data_dir):
    d = device()
    reachability.import_report(report([
        {"target": "192.0.2.10", "port": 22, "state": "open", "source_ip": "192.0.2.77"},
        {"target": "192.0.2.10", "port": 23, "state": "open", "source_ip": "192.0.2.77"},
        {"target": "192.0.2.10", "port": 80, "state": "closed"},
        {"target": "192.0.2.99", "port": 22, "state": "open"}]), "User VLAN 20", authorized=False)
    seen = reachability.for_device(d)
    assert {o["port"] for o in seen} == {22, 23}            # this switch's address, open ports only
    assert observed_failures("LYSS-MGMT-010", {"reachability": seen})       # SSH from a user VLAN
    assert observed_failures("LYSS-MGMT-001", {"reachability": seen})       # Telnet answers
    assert not observed_failures("LYSS-MGMT-003", {"reachability": seen})   # HTTP closed: no evidence either way
    assert not observed_failures("LYSS-AUTH-001", {"reachability": seen})


def test_authorised_networks_and_old_probes_do_not_count(data_dir):
    d = device()
    reachability.import_report(report([{"target": "192.0.2.10", "port": 22, "state": "open"}]), "Admin LAN", True)
    old = (datetime.now() - timedelta(days=reachability.MAX_AGE_DAYS + 5)).isoformat(timespec="seconds")
    reachability.import_report(report([{"target": "192.0.2.10", "port": 22, "state": "open"}], old), "Old", False)
    assert not observed_failures("LYSS-MGMT-010", {"reachability": reachability.for_device(d)})


def test_a_scan_uses_the_probe_and_hardened_config_still_fails(data_dir):
    d = device()
    case = load_case("ios-hardened")
    cfg, state = collector.config_paths(d)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(case["config"], encoding="utf-8")
    assert {f["control_id"]: f["verdict"] for f in scan.audit_device(d)["findings"]}["LYSS-MGMT-010"] == "pass"
    reachability.import_report(report([{"target": "192.0.2.10", "port": 22, "state": "open",
                                        "source_ip": "198.51.100.7"}]), "Guest Wi-Fi", False)
    finding = next(f for f in scan.audit_device(d)["findings"] if f["control_id"] == "LYSS-MGMT-010")
    assert finding["verdict"] == "fail" and "Guest Wi-Fi" in finding["evidence"][0]


def test_web_import_and_delete(data_dir, tmp_path):
    device()
    webapp._sessions.clear()
    webapp._failures.update(count=0, locked_until=0, inflight=0)
    c = TestClient(webapp.app, base_url="http://127.0.0.1:8765")
    c.post("/setup", data={"password": "correct horse battery", "confirm": "correct horse battery"})
    page = c.get("/reachability").text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    data = json.dumps(report([{"target": "192.0.2.10", "port": 22, "state": "open"}])).encode()
    r = c.post("/reachability/import", data={"csrf": csrf, "label": "<b>User</b> VLAN"},
               files={"file": ("probe.json", data, "application/json")})
    assert r.status_code == 200 and "Imported: 1 open management port" in r.text
    assert "<b>User</b>" not in r.text and "&lt;b&gt;User&lt;/b&gt; VLAN" in r.text     # label shown as text
    import_id = reachability.load()[0]["id"]
    c.post(f"/reachability/{import_id}/delete", data={"csrf": csrf})
    assert reachability.load() == []
    r = c.post("/reachability/import", data={"csrf": csrf, "label": "x"},
               files={"file": ("probe.json", b"{not json", "application/json")})
    assert r.status_code == 400
