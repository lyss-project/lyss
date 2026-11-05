# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""SIEM events (syslog / JSON lines, Wazuh rules) and the Oxidized integration, on synthetic data."""
import json
import re
import socket
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree

import httpx
import pytest
from fastapi.testclient import TestClient

from lyss import events, inventory, oxidized
from lyss.engine import audit, conformance
from lyss.web import app as webapp
from test_web import PASSWORD, csrf_of

CASES = Path(__file__).parent / "cases"
WAZUH = Path(__file__).parent.parent / "integrations" / "wazuh"


def case_config(name: str) -> str:
    return (CASES / name / "config.cfg").read_text(encoding="utf-8")


def stored_result(device_id: str, case: str, vendor: str) -> dict:
    findings = audit(case_config(case), vendor, 2, "")
    result = {"device": device_id, "vendor": vendor, "model": "", "firmware": "", "spec_version": "x",
              "summary": conformance(findings), "findings": [asdict(f) for f in findings]}
    inventory.save_result(device_id, result)
    return result


# ---------------- SIEM events ----------------

def test_events_of_a_scan(data_dir):
    inventory.save_device({"id": "sw-weak", "host": "192.0.2.21", "port": "22", "vendor": "cisco_ios",
                           "username": "ro", "via_jump": False}, "Sw1tch-Pass!")
    result = stored_result("sw-weak", "ios-weak", "cisco_ios")
    failed = [f["control_id"] for f in result["findings"] if f["verdict"] == "fail"]
    job = {"trigger": "schedule", "items": {"sw-weak": {"status": "done", "message": ""},
                                            "sw-down": {"status": "error", "message": "SSH timeout"}}}
    changes = {"sw-weak": {"new_fail": [failed[0]], "fixed": []}}
    evs = [e["lyss"] for e in events.build(job, changes, 2, {"findings": "all"})]
    kinds = [e["event"] for e in evs]
    assert kinds.count("scan") == 1 and kinds.count("finding") == len(failed) and failed
    assert kinds.count("regression") == 1 and "collection_error" in kinds and "discovered" in kinds
    scan = next(e for e in evs if e["event"] == "scan")
    assert scan["device"] == "sw-weak" and scan["host"] == "192.0.2.21" and scan["fail"] == len(failed)
    finding = next(e for e in evs if e["event"] == "finding")
    assert re.match(r"^LYSS-[A-Z]+-\d{3}$", finding["control"]) and finding["title"] and "version" in finding
    assert all(e["time"] for e in evs)
    # "changes" mode: no per-control findings, regressions still sent
    kinds = [e["lyss"]["event"] for e in events.build(job, changes, 0, {"findings": "changes"})]
    assert "finding" not in kinds and "regression" in kinds


def test_syslog_line_is_rfc3164_with_json_message():
    line = events.syslog_line({"lyss": {"event": "finding", "device": "sw1"}}, hostname="lyss-host.example")
    m = re.match(r"^<(\d+)>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d lyss-host lyss: (\{.*\})$", line)
    assert m and int(m.group(1)) == 16 * 8 + 4
    assert json.loads(m.group(2)) == {"lyss": {"event": "finding", "device": "sw1"}}


def test_send_over_udp_and_to_a_file(tmp_path):
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(5)
    port = receiver.getsockname()[1]
    out = tmp_path / "siem" / "lyss-events.jsonl"
    try:
        sent = events.send([events.test_event(), events.test_event()],
                           {"host": "127.0.0.1", "port": port, "protocol": "udp", "file": str(out)})
        datagrams = [receiver.recv(9000).decode("utf-8") for _ in range(2)]
    finally:
        receiver.close()
    assert sent == 2 and all(" lyss: {" in d for d in datagrams)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["lyss"]["event"] == "test"


def test_send_over_tcp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    port = server.getsockname()[1]
    try:
        events.send([events.test_event()], {"host": "127.0.0.1", "port": port, "protocol": "tcp"})
        conn, _ = server.accept()
        with conn:
            data = conn.recv(9000).decode("utf-8")
    finally:
        server.close()
    assert data.endswith("\n") and " lyss: {" in data


def test_wazuh_rules_and_decoder_are_valid_and_cover_every_event():
    rules = ElementTree.fromstring((WAZUH / "lyss_rules.xml").read_text(encoding="utf-8"))
    ids = [r.get("id") for r in rules.iter("rule")]
    assert len(ids) == len(set(ids)) and all(100000 <= int(i) <= 120000 for i in ids)
    matched = {f.text.strip("^$") for f in rules.iter("field") if f.get("name") == "lyss.event"}
    assert {"scan", "finding", "regression", "fixed", "collection_error", "discovered", "test"} <= matched
    decoder = ElementTree.fromstring((WAZUH / "lyss_decoders.xml").read_text(encoding="utf-8"))
    assert decoder.findtext("program_name") == "^lyss$" and decoder.findtext("plugin_decoder") == "JSON_Decoder"


def test_settings_siem_form(data_dir):
    webapp._sessions.clear()
    webapp._failures.update(count=0, locked_until=0)
    client = TestClient(webapp.app, base_url="http://127.0.0.1:8765")
    client.post("/setup", data={"password": PASSWORD, "confirm": PASSWORD})
    csrf = csrf_of(client.get("/settings").text)
    out = data_dir / "lyss-events.jsonl"
    r = client.post("/settings/siem", data={"csrf": csrf, "enabled": "on", "host": "", "port": "514",
                                            "protocol": "udp", "file": str(out), "findings": "all"})
    assert r.status_code == 200 and "SIEM events saved." in r.text
    assert inventory.load_settings()["siem"]["file"] == str(out)
    r = client.post("/settings/siem/test", data={"csrf": csrf})
    assert r.status_code == 200 and json.loads(out.read_text(encoding="utf-8"))["lyss"]["event"] == "test"
    for bad in ({"host": "bad host!"}, {"port": "70000"}, {"protocol": "icmp"}, {"file": "relative.jsonl"},
                {"file": str(data_dir / "x.exe")}, {"host": "", "file": ""}):
        data = {"csrf": csrf, "enabled": "on", "host": "siem.example", "port": "514", "protocol": "udp",
                "file": "", "findings": "all", **bad}
        assert client.post("/settings/siem", data=data).status_code == 400, bad


# ---------------- Oxidized ----------------

def oxidized_api(nodes: list[dict], configs: dict[str, str]):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/nodes.json":
            return httpx.Response(200, json=nodes)
        key = request.url.path.removeprefix("/node/fetch/")
        if key in configs:
            return httpx.Response(200, text=configs[key])
        return httpx.Response(404, text="node not found")
    return httpx.MockTransport(handler)


def node(name, model, group="", status="success", age_days=0):
    end = datetime.now(timezone.utc) - timedelta(days=age_days)
    return {"name": name, "ip": "192.0.2.30", "model": model, "group": group,
            "last": {"status": status, "end": end.strftime("%Y-%m-%d %H:%M:%S UTC")}}


def verdict(result, control):
    return next(f for f in result["findings"] if f["control_id"] == control)


def test_oxidized_assesses_backed_up_configurations(monkeypatch):
    hidden = re.sub(r"secret 9 \S+", "secret <secret hidden>", case_config("ios-hardened"))
    nodes = [node("core-1", "ios", group="hq"), node("acc-old", "ios", age_days=30),
             node("acc-hidden", "ios"), node("sb-1", "ciscosmb"), node("fw-1", "junos"),
             node("lost", "ios")]
    configs = {"hq/core-1": case_config("ios-weak"), "acc-old": case_config("ios-hardened"),
               "acc-hidden": hidden, "sb-1": case_config("sb-weak")}
    monkeypatch.setattr(oxidized, "_transport", oxidized_api(nodes, configs))
    with oxidized.client("http://oxidized.example:8888") as http:
        results, skipped = oxidized.assess_all(http, level=2)
    by_name = {r["device"]: r for r in results}
    assert set(by_name) == {"core-1", "acc-old", "acc-hidden", "sb-1"}
    assert {s["device"] for s in skipped} == {"fw-1", "lost"}
    core = by_name["core-1"]
    assert core["source"] == "oxidized" and core["group"] == "hq" and core["vendor"] == "cisco_ios"
    assert core["summary"]["fail"] > 0
    # a recent successful Oxidized backup is evidence for LYSS-BKP-001, an old one is not
    assert verdict(core, "LYSS-BKP-001")["verdict"] == "pass"
    assert "Oxidized" in verdict(core, "LYSS-BKP-001")["evidence"][0]
    assert verdict(by_name["acc-old"], "LYSS-BKP-001")["verdict"] == "fail"
    # secrets hidden by Oxidized never produce a verdict on how they are stored
    for f in by_name["acc-hidden"]["findings"]:
        assert not (f["verdict"] in ("pass", "fail") and any("hidden>" in e for e in f["evidence"])), f["control_id"]
    assert verdict(by_name["acc-hidden"], "LYSS-AUTH-002")["verdict"] == "unknown"
    assert verdict(by_name["acc-old"], "LYSS-AUTH-002")["verdict"] == "pass"  # same config, secrets visible
    assert by_name["sb-1"]["vendor"] == "cisco_sb"


def test_oxidized_turns_verdicts_based_on_hidden_secrets_into_unknown():
    config = re.sub(r'(password manager user-name "\S+" sha256) \S+', r"\1 <secret hidden>",
                    case_config("hp-hardened"))
    assert "<secret hidden>" in config
    result = oxidized.assess(node("hp-1", "procurve"), config)
    f = verdict(result, "LYSS-AUTH-002")
    assert f["verdict"] == "unknown" and "Oxidized hides" in f["note"]
    plain = oxidized.assess(node("hp-1", "procurve"), case_config("hp-hardened"))
    assert verdict(plain, "LYSS-AUTH-002")["verdict"] == "pass"


def test_oxidized_results_become_siem_events(monkeypatch):
    nodes = [node("core-1", "ios", group="hq")]
    monkeypatch.setattr(oxidized, "_transport", oxidized_api(nodes, {"hq/core-1": case_config("ios-weak")}))
    with oxidized.client("http://oxidized.example:8888") as http:
        results, _ = oxidized.assess_all(http)
    r = results[0]
    evs = events.wrap(events.result_events({"device": r["device"], "host": r["host"], "site": r["group"]},
                                           r, {}, "all", "oxidized"))
    scan = evs[0]["lyss"]
    assert scan["event"] == "scan" and scan["source"] == "oxidized" and scan["site"] == "hq"
    assert sum(1 for e in evs if e["lyss"]["event"] == "finding") == r["summary"]["fail"]


def test_oxidized_command_line(monkeypatch, capsys):
    from lyss.__main__ import main
    nodes = [node("core-1", "ios", group="hq"), node("fw-1", "junos")]
    monkeypatch.setattr(oxidized, "_transport", oxidized_api(nodes, {"hq/core-1": case_config("ios-weak")}))
    assert main(["oxidized", "--url", "http://oxidized.example:8888", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["source"] == "oxidized" and [r["device"] for r in out["results"]] == ["core-1"]
    assert out["skipped"][0]["device"] == "fw-1"
    assert main(["oxidized", "--url", "http://oxidized.example:8888"]) == 0
    assert "1 switch(es) assessed from Oxidized, 1 skipped." in capsys.readouterr().out


@pytest.mark.parametrize("value", ["2026-11-05 10:00:00 UTC", "2026-11-05T10:00:00+00:00", "2026-11-05 10:00:00"])
def test_oxidized_time_formats(value):
    assert oxidized._parse_time(value) == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
