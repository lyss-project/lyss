# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Juniper EX (Junos) adapter: "display set" and curly-brace formats, inactive / deactivated
statements, interface ranges, the order of "authentication-order", detection. Synthetic data."""

from conftest import load_case

from lyss.config import junos_braces_to_set, junos_normalize, parse
from lyss.engine import audit, detect_vendor

BRACES = """## Last commit: 2026-11-10 08:00:00 UTC by lyss-lab
version 23.4R2-S2.1;
system {
    host-name lab-ex-hard;
    root-authentication {
        encrypted-password "$6$FAKEHASH"; ## SECRET-DATA
    }
    login {
        message "Authorized access only. Activity is logged.";
        class admin-10 {
            idle-timeout 10;
            permissions all;
        }
        user netadmin {
            class admin-10;
            authentication {
                encrypted-password "$6$FAKEHASH"; ## SECRET-DATA
            }
        }
    }
    services {
        ssh {
            root-login deny;
        }
        netconf {
            ssh;
        }
        inactive: telnet;
    }
    /* RADIUS first, local accounts only as fallback */
    authentication-order [ radius password ];
    radius-server {
        192.0.2.10 secret "$9$FAKE"; ## SECRET-DATA
    }
    syslog {
        host 192.0.2.60 {
            any notice;
            interactive-commands info;
        }
    }
    ntp {
        server 192.0.2.123;
    }
}
snmp {
    v3 {
        usm {
            local-engine {
                user lyss {
                    authentication-sha256 {
                        authentication-key "$9$FAKE"; ## SECRET-DATA
                    }
                    privacy-aes128 {
                        privacy-key "$9$FAKE"; ## SECRET-DATA
                    }
                }
            }
        }
        vacm {
            access {
                group LYSS {
                    default-context-prefix {
                        security-model usm {
                            security-level privacy {
                                read-view all;
                            }
                        }
                    }
                }
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family ethernet-switching {
                interface-mode access;
                vlan {
                    members USERS;
                }
            }
        }
    }
    ge-0/0/1 {
        disable;
    }
    xe-0/1/0 {
        unit 0 {
            family ethernet-switching {
                interface-mode trunk;
                vlan {
                    members all;
                }
            }
        }
    }
    irb {
        unit 99 {
            family inet {
                address 192.0.2.31/24;
            }
        }
    }
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input PROTECT-RE;
                }
            }
        }
    }
}
protocols {
    rstp {
        interface ge-0/0/0 {
            edge;
        }
        bpdu-block-on-edge;
    }
}
vlans {
    MGMT {
        vlan-id 99;
        l3-interface irb.99;
    }
    USERS {
        vlan-id 10;
    }
}
"""


def verdicts(text: str, state: str = "", context=None, level: int = 2) -> dict[str, str]:
    return {f.control_id: f.verdict for f in audit(text, "juniper_junos", level, state, context)}


def test_braces_are_converted_to_set_lines():
    lines = junos_braces_to_set(BRACES).splitlines()
    assert "set system authentication-order radius" in lines
    assert "set system authentication-order password" in lines
    assert lines.index("set system authentication-order radius") < lines.index("set system authentication-order password")
    assert "set interfaces ge-0/0/0 unit 0 family ethernet-switching interface-mode access" in lines
    assert "set system login message \"Authorized access only. Activity is logged.\"" in lines
    assert not any("telnet" in l for l in lines), "an inactive statement is not in effect"
    assert not any("RADIUS first" in l or "SECRET-DATA" in l for l in lines), "comments are dropped"


def test_brace_format_gives_the_same_verdicts_as_display_set():
    case = load_case("junos-hardened")
    expected = verdicts(case["config"], case["state"], case["context"])
    assert verdicts(BRACES, case["state"], case["context"]) == expected


def test_detection_of_both_formats():
    assert detect_vendor(load_case("junos-hardened")["config"]) == "juniper_junos"
    assert detect_vendor(BRACES) == "juniper_junos"


def test_deactivated_statements_are_not_in_effect():
    config = load_case("junos-hardened")["config"] + "set system services telnet\ndeactivate system services telnet\n"
    assert verdicts(config)["LYSS-MGMT-001"] == "pass"
    assert verdicts(load_case("junos-hardened")["config"] + "set system services telnet\n")["LYSS-MGMT-001"] == "fail"


def test_local_passwords_first_fails_even_with_radius_later():
    case = load_case("junos-hardened")
    swapped = case["config"].replace("set system authentication-order radius\nset system authentication-order password",
                                     "set system authentication-order password\nset system authentication-order radius")
    assert swapped != case["config"]
    assert verdicts(swapped)["LYSS-AUTH-010"] == "fail"
    assert verdicts(case["config"])["LYSS-AUTH-010"] == "pass"


def test_interface_range_members_inherit_the_range_settings():
    cfg = parse("set interfaces interface-range USERS member-range ge-0/0/2 to ge-0/0/4\n"
                "set interfaces interface-range USERS unit 0 family ethernet-switching interface-mode access\n",
                vendor="juniper_junos")
    headers = {b.header for b in cfg.blocks if b.children}
    assert {"interfaces ge-0/0/2", "interfaces ge-0/0/3", "interfaces ge-0/0/4"} <= headers


def test_access_ports_from_a_range_need_bpdu_protection():
    case = load_case("junos-hardened")
    config = case["config"] + ("set interfaces interface-range USERS member-range ge-0/0/2 to ge-0/0/4\n"
                               "set interfaces interface-range USERS unit 0 family ethernet-switching interface-mode access\n")
    assert verdicts(config)["LYSS-ACC-011"] == "fail"
    assert verdicts(config + "set protocols rstp interface all edge\n")["LYSS-ACC-011"] == "pass"
    assert verdicts(case["config"] + "set protocols layer2-control bpdu-block interface all\n")["LYSS-ACC-011"] == "pass"


def test_trunk_aggregation_is_not_an_edge_port_but_a_server_aggregation_is():
    case = load_case("junos-hardened")
    trunk_ae = ("set interfaces ge-0/0/10 ether-options 802.3ad ae0\n"
                "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk\n")
    assert verdicts(case["config"] + trunk_ae)["LYSS-ACC-011"] == "pass"
    server_ae = ("set interfaces ge-0/0/11 ether-options 802.3ad ae1\n"
                 "set interfaces ae1 unit 0 family ethernet-switching interface-mode access\n")
    assert verdicts(case["config"] + server_ae)["LYSS-ACC-011"] == "fail"
    assert verdicts(case["config"] + server_ae + "set protocols rstp interface ae1 edge\n")["LYSS-ACC-011"] == "pass"


def test_idle_timeout_needs_a_custom_class_on_every_account():
    case = load_case("junos-hardened")
    assert verdicts(case["config"] + "set system login user ops class operator\n")["LYSS-MGMT-004"] == "fail"
    longer = case["config"].replace("idle-timeout 10", "idle-timeout 30")
    assert verdicts(longer)["LYSS-MGMT-004"] == "fail"


def test_hidden_hashes_leave_the_password_control_unknown():
    case = load_case("junos-hardened")
    hidden = case["config"].replace('encrypted-password "$6$FAKEHASH"', "encrypted-password /* SECRET-DATA */")
    assert verdicts(hidden)["LYSS-AUTH-002"] == "unknown"


def test_normalize_stays_fast_on_many_deactivate_lines():
    import time
    text = "".join(f"set system services ssh x{i}\n" for i in range(20000))
    text += "".join(f"deactivate system services y{i}\n" for i in range(20000))
    start = time.perf_counter()
    junos_normalize(text)
    assert time.perf_counter() - start < 5


def test_brace_conversion_is_bounded_on_hostile_nesting():
    import time
    start = time.perf_counter()
    out = junos_braces_to_set("a {" * 30000 + "b;" * 100000 + "}" * 30000)
    assert time.perf_counter() - start < 5 and len(out) < 25_000_000


def test_range_settings_cannot_multiply_without_bound():
    import time
    text = "set interfaces interface-range R member-range ge-0/0/0 to ge-0/0/1000\n"
    text += "".join(f"set interfaces interface-range R description d{i}\n" for i in range(5000))
    start = time.perf_counter()
    junos_normalize(text)
    assert time.perf_counter() - start < 5


def test_normalize_is_bounded_on_huge_ranges():
    text = junos_normalize("set interfaces interface-range R member-range ge-0/0/0 to ge-0/0/99999999\n"
                           "set interfaces interface-range R unit 0 family ethernet-switching\n")
    assert text.count("interfaces ge-0/0/") <= 3
