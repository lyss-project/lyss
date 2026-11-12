# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""First field report on real HPE AOS-S switches (2930F, 3810M stack; SwitchDesk discussion #29,
12/11/2026). Each case reproduces what was reported, with fictitious data."""

from pathlib import Path

import pytest

from lyss.config import parse
from lyss.engine import audit, extract_facts, load_adapter

CASES = Path(__file__).parent / "cases"


def case(name: str) -> str:
    return (CASES / name / "config.cfg").read_text(encoding="utf-8")


def verdict(text: str, vendor: str, control: str):
    f = next(f for f in audit(text, vendor, 2) if f.control_id == control)
    return f.verdict, f.evidence


# ---- LYSS-MGMT-012: the word must be inside a banner shown before login

def test_hp_authorized_managers_line_no_longer_satisfies_the_banner():
    base = case("hp-hardened")
    assert verdict(base, "hp_procurve", "LYSS-MGMT-012")[0] == "pass"
    lines = [l for l in base.splitlines() if not l.startswith("banner motd")]
    welcome = "\n".join(lines + ['banner motd "Welcome to the core switch"',
                                 "ip authorized-managers 192.0.2.0 255.255.255.0 access manager"]) + "\n"
    assert verdict(welcome, "hp_procurve", "LYSS-MGMT-012")[0] == "fail"


@pytest.mark.parametrize("vendor, case_name", [("cisco_ios", "ios-hardened"), ("cisco_sb", "sb-hardened")])
def test_an_exec_banner_does_not_count(vendor, case_name):
    base = case(case_name)
    kept = "\n".join(l for l in base.splitlines() if not l.startswith(("banner login", "banner motd")))
    # an exec banner is shown after login; a description elsewhere does not count either
    text = kept + "\nbanner motd ^CWelcome^C\nbanner exec ^CAuthorized access only^C\n"
    assert verdict(text, vendor, "LYSS-MGMT-012")[0] == "fail"
    text = kept + "\nbanner motd ^CAuthorized access only. Activity is logged.^C\n"
    assert verdict(text, vendor, "LYSS-MGMT-012")[0] == "pass"


def test_multi_line_login_banner_body_counts():
    kept = "\n".join(l for l in case("ios-hardened").splitlines() if not l.startswith(("banner login", "banner motd")))
    text = kept + "\nbanner login ^C\nThis system is for\nauthorised use only.\n^C\n"
    assert verdict(text, "cisco_ios", "LYSS-MGMT-012")[0] == "pass"
    lines = parse(text, "", "cisco_ios").lines
    assert "banner-text login authorised use only." in lines


def test_aoscx_and_arista_read_the_banner_body():
    cx = case("cx-hardened")
    assert verdict(cx, "aruba_aoscx", "LYSS-MGMT-012")[0] == "pass"
    welcome = cx.replace("Authorized access only. Activity is logged.", "Welcome to the lab")
    assert verdict(welcome + "user-group authorized-ops\n", "aruba_aoscx", "LYSS-MGMT-012")[0] == "fail"
    eos = case("arista-hardened")
    assert verdict(eos, "arista_eos", "LYSS-MGMT-012")[0] == "pass"


# ---- LYSS-VULN-001: model of a stacked or VSF switch

STACK = """; hpStack_KB Configuration Editor; Created on release #KB.16.10.0010
; Ver #14:01.4f.f8.1d.9b.3f.bf.bb.ef.7c.59.fc.6b.fb.9f.fc.ff.ff.37.ef:01
hostname "lab-stack"
stacking
   member 1 type "JL075A" mac-address 0000.5e00.5301
   member 2 type "JL075A" mac-address 0000.5e00.5302
   exit
"""

VSF = """; hpStack_WC Configuration Editor; Created on release #WC.16.11.0032
hostname "lab-vsf"
vsf
   enable domain 1
   member 1
      type "JL256A" mac-address 0000.5e00.5303
      priority 255
      exit
   exit
"""


@pytest.mark.parametrize("text, model, verdict_expected", [(STACK, "JL075A", "fail"), (VSF, "JL256A", "pass")])
def test_stack_model_comes_from_the_members(text, model, verdict_expected):
    facts = extract_facts(parse(text, "", "hp_procurve"), load_adapter("hp_procurve"))
    assert facts.get("model") == model
    v, evidence = verdict(text, "hp_procurve", "LYSS-VULN-001")
    assert v == verdict_expected and model in evidence[0]      # decided from the release, no longer unknown
