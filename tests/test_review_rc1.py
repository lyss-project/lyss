# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Public review of specification 1.0.0-rc.1: adapter and tool fixes that follow the comments of
@jaba0x (SwitchDesk discussion #29, 21/11/2026). Fictitious data only."""

import re
import socket
import threading

import pytest

from conftest import load_case
from lyss import reachability
from lyss.engine import audit, expand_ports, observed_failures


def _verdicts(config, state="", level=3):
    return {f.control_id: f.verdict for f in audit(config, "hp_procurve", level, state)}


# ---------------- AOS-S stacks and VSF: ports are named member/port ----------------

def _as_stack(case):
    """The hardened standalone case with its ports renamed as on stack member 1: 5 -> 1/5."""
    config = (case["config"].replace("trunk 27-28 ", "trunk 1/27-1/28 ").replace("1-28,Trk1", "1/1-1/28,Trk1")
              .replace(" 1-26", " 1/1-1/26"))
    state = re.sub(r"(?m)^(  )(\d+)(-Trk\d+)?( [^|\n]*\| )", r"\g<1>1/\2\3\4", case["state"])
    return config, state


def test_stack_port_lists_are_expanded():
    assert expand_ports("1/1-1/3,2/A1-2/A2,Trk1,5-6,A1") == {"1/1", "1/2", "1/3", "2/a1", "2/a2", "trk1", "5", "6", "a1"}
    assert expand_ports("1/1-2/3") == {"1/1-2/3"}            # never a range across two members


def test_a_stack_gets_the_same_access_layer_verdicts_as_a_standalone_switch():
    """"show interfaces brief" names the ports of a stack 1/1, 1/16-Trk1, 2/A1: the port pattern did
    not match them, so every access-layer control was unknown ("Needs show interfaces brief")."""
    case = load_case("hp-hardened")
    alone = _verdicts(case["config"], case["state"])
    config, state = _as_stack(case)
    assert "  1/5 " in state and "1/1-1/26" in config
    stack = _verdicts(config, state)
    assert stack == alone
    assert stack["LYSS-ACC-010"] != "unknown" and stack["LYSS-ACC-011"] == "pass"
    # and a real difference is still seen: BPDU protection missing on one member port
    worse = _verdicts(config.replace("spanning-tree 1/1-1/26 bpdu-protection", "spanning-tree 1/1-1/25 bpdu-protection"), state)
    assert worse["LYSS-ACC-011"] == "fail"


# ---------------- LYSS-MGMT-011 with "management-vlan" ----------------

BASE = "hostname \"demo-hp-09\"\nvlan 1\n   untagged 1-24\n   {v1}\nvlan 10\n   tagged 24\n   ip address 192.0.2.9 255.255.255.0\n{mgmt}"


@pytest.mark.parametrize("v1, mgmt, expected", [
    ("ip address dhcp-bootp", "management-vlan 10\n", "pass"),      # VLAN 1 address is not a management address
    ("ip address 198.51.100.1 255.255.255.0", "management-vlan 10\n", "pass"),
    ("ip address dhcp-bootp", "", "fail"),                           # no management VLAN: VLAN 1 is managed
    ("ip address dhcp-bootp", "management-vlan 1\n", "fail"),
    ("no ip address", "", "pass"),
])
def test_an_address_on_vlan_1_is_not_a_management_address_when_management_is_bound_elsewhere(v1, mgmt, expected):
    assert _verdicts(BASE.format(v1=v1, mgmt=mgmt), level=2)["LYSS-MGMT-011"] == expected


def test_access_ports_in_the_management_vlan_still_fail():
    config = BASE.format(v1="no ip address", mgmt="management-vlan 10\n").replace("tagged 24", "untagged 20-23\n   tagged 24")
    assert _verdicts(config, level=2)["LYSS-MGMT-011"] == "fail"


# ---------------- LYSS-MGMT-003: a port 80 that only redirects to HTTPS ----------------

@pytest.mark.parametrize("answer, kind", [
    ("HTTP/1.1 302 Found\r\nLocation: https://192.0.2.5/\r\n\r\n", "redirect-https"),
    ("HTTP/1.0 301 Moved\nlocation:https://192.0.2.5/\n\n", "redirect-https"),               # not to the letter
    ("HTTP/1.1 307 Temporary Redirect\r\nServer: eHTTP v2.0\r\nLOCATION:  https://192.0.2.5/index.html\r\n\r\n", "redirect-https"),
    ('HTTP/1.1 200 OK\r\n\r\n<html><meta http-equiv="refresh" content="0; url=https://192.0.2.5/"></html>', "redirect-https"),
    ("HTTP/1.1 200 OK\r\n\r\n<script>window.location.href = 'https://192.0.2.5/';</script>", "redirect-https"),
    ("HTTP/1.1 302 Found\r\nLocation: http://192.0.2.5/login\r\n\r\n", "page"),               # stays on plain HTTP
    ("HTTP/1.1 302 Found\r\nLocation: /login.html\r\n\r\n", "page"),
    ("HTTP/1.1 200 OK\r\n\r\n<html><form><input type=password></form></html>", "page"),
    ('HTTP/1.1 200 OK\r\n\r\n<meta http-equiv="refresh" content="0; url=https://x/"><form><input name=u></form>', "page"),
    ("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n", "page"),
    ("garbage", "page"), ("", ""),
])
def test_what_an_http_port_answers(answer, kind):
    assert reachability.http_kind(answer) == kind


def test_the_probe_sends_one_anonymous_get_and_reads_a_bounded_answer():
    ours, theirs = socket.socketpair()
    seen = []

    def server():
        seen.append(theirs.recv(4096))
        theirs.sendall(b"HTTP/1.1 302 Found\r\nLocation: https://192.0.2.5/\r\n\r\n" + b"x" * 100000)
        theirs.close()
    t = threading.Thread(target=server)
    t.start()
    ours.settimeout(5)
    assert reachability._ask_http(ours, "192.0.2.5") == "redirect-https"
    ours.close()
    t.join()
    request = seen[0].decode("ascii")
    assert request.startswith("GET / HTTP/1.0\r\nHost: 192.0.2.5\r\n") and "Authorization" not in request and "Cookie" not in request


def test_a_redirect_only_port_does_not_fail_cleartext_http():
    """A switch with "web-management ssl" and "no web-management plaintext" still answers on TCP 80,
    with a redirect to https:// only: the probe failed LYSS-MGMT-003 on correctly configured switches."""
    seen = {"target": "192.0.2.5", "port": 80, "service": "http", "state": "open", "source_ip": "198.51.100.7",
            "label": "User VLAN 20", "authorized": False, "date": "2026-11-22T10:00:00"}
    assert observed_failures("LYSS-MGMT-003", {"reachability": [{**seen, "http": "redirect-https"}]}) == []
    for other in ({**seen, "http": "page"}, {**seen, "http": ""}, seen):            # older probe files: no "http" field
        assert len(observed_failures("LYSS-MGMT-003", {"reachability": [other]})) == 1
    # the port still answers from a network that must not reach management: LYSS-MGMT-010 is unchanged
    assert len(observed_failures("LYSS-MGMT-010", {"reachability": [{**seen, "http": "redirect-https"}]})) == 1


def test_the_import_keeps_only_known_http_values():
    report = {"kind": "reachability", "results": [
        {"target": "192.0.2.5", "port": 80, "state": "open", "http": "redirect-https"},
        {"target": "192.0.2.6", "port": 80, "state": "open", "http": "<script>"},
        {"target": "192.0.2.7", "port": 22, "state": "open", "http": "redirect-https"}]}
    kept, _ = reachability.validate(report)
    by_target = {r["target"]: r for r in kept}
    assert by_target["192.0.2.5"]["http"] == "redirect-https"
    assert "http" not in by_target["192.0.2.6"] and "http" not in by_target["192.0.2.7"]
