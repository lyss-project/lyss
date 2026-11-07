# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Parse switch configurations into top-level lines and indented blocks: CLI text (Cisco, HPE), or
JSON key/field tables (SONiC config_db) flattened into the same form."""

import json
import re
from dataclasses import dataclass, field


@dataclass
class Block:
    header: str
    children: list[str] = field(default_factory=list)


@dataclass
class Config:
    lines: list[str]    # every meaningful line, stripped, including block children
    blocks: list[Block]  # top-level lines that have indented children
    state: dict[str, list[str]] = field(default_factory=dict)  # device state, by command
    comments: list[str] = field(default_factory=list)  # comment lines, e.g. HP "; J9774A ... release #YA.16.10.0012"


STATE_HEADER = re.compile(r"^=====[ \t]*(.+?)[ \t]*=====(?:[ \t]+#([0-9a-f]{16}))?[ \t]*$")
# first line(s) of a state file written by the collector: every section header carries this
# random value, unknown to the switch, so a "===== x =====" line inside command output (text set
# by a neighbour over CDP/LLDP, a banner...) can never open or replace a section
STATE_NONCE = re.compile(r"^sections:[ \t]+#([0-9a-f]{16})[ \t]*$")
MAX_LINE = 4096   # characters kept per line: configurations and state are untrusted input


def parse_state(text: str) -> dict[str, list[str]]:
    """Split collector output ("===== show x =====" sections) into {command: lines}.
    Collected files: only headers carrying the file's nonce count. Hand-made files (offline
    audit, no nonce): a section that appears twice is dropped (unknown, never a forged pass)."""
    sections: dict[str, list[str]] = {}
    seen: set[str] = set()
    nonce, current = None, None
    for i, raw in enumerate(text.splitlines()):
        raw = raw[:MAX_LINE]
        if i < 3 and nonce is None and (n := STATE_NONCE.match(raw)):
            nonce = n.group(1)
            continue
        m = STATE_HEADER.match(raw)
        if m and (nonce is None or m.group(2) == nonce):
            name = m.group(1)
            if name in seen:
                sections.pop(name, None)   # duplicated: neither copy is trusted
                current = None
            else:
                seen.add(name)
                sections[name] = []
                current = name
        elif current is not None and raw.strip():
            sections[current].append(raw.rstrip())
    return sections


COMMENT_PREFIXES = ("!", "#", ";")


_LINE_BREAKS = re.compile(r"[\x00-\x1f\x7f\x85  ]")   # everything str.splitlines() splits on, and more


def _one_line(value) -> str:
    """JSON text kept on one line: a table, key or field name with a line break could otherwise
    inject configuration lines (e.g. a fake "AAA|authentication" table)."""
    return _LINE_BREAKS.sub(lambda m: "\\n" if m.group() == "\n" else "?", str(value).replace("\r", ""))


def flatten_json(data: dict) -> str:
    """JSON configurations (SONiC config_db: {TABLE: {key: {field: value}}}) as an indented text
    configuration, so the same line and block rules apply:
        SNMP_COMMUNITY|public
          TYPE=RO
    Multi-line values keep their line breaks as "\\n"; lists are joined with ","; tables that are
    not key/field maps (e.g. raw routing configuration text) are left out."""
    out = []
    for table in sorted(data):
        entries = data[table]
        if not isinstance(entries, dict):
            continue
        for key in sorted(entries):
            fields = entries[key]
            out.append(f"{_one_line(table)}|{_one_line(key)}")
            if isinstance(fields, dict):
                for name in sorted(fields):
                    value = fields[name]
                    if isinstance(value, list):
                        value = ",".join(str(v) for v in value)
                    out.append(f"  {_one_line(name)}={_one_line(value)}")
    return "\n".join(out) + "\n"


ROUTEROS_PATH = re.compile(r"^/[a-z0-9][a-z0-9\-]*(?: [a-z0-9][a-z0-9\-]*)*$")
ROUTEROS_VERB = re.compile(r"^(add|set|remove|unset|enable|disable|:\w+)\b")


def routeros_terse(text: str) -> str:
    """RouterOS hierarchical export ("/ip service" then "set telnet disabled=yes" lines, wrapped
    lines ending in a backslash, e.g. an Oxidized backup) -> one full command per line, as
    "/export terse" prints it. Text that is not such an export is returned unchanged."""
    text = re.sub(r"\\\r?\n\s*", "", text)   # wrapped lines join exactly, even inside a word
    lines = text.splitlines()
    if not any(ROUTEROS_PATH.match(l.strip()) for l in lines):
        return text
    out, path = [], None
    for raw in lines:
        line = raw.strip()
        if ROUTEROS_PATH.match(line) and not re.search(r"(?:^/|\s)(?:add|set|remove|unset|enable|disable)(?:\s|$)", line):
            path = line
        elif path and ROUTEROS_VERB.match(line):
            out.append(f"{path} {line}")
        else:
            out.append(raw)
    return "\n".join(out) + "\n"


BANNER_START = re.compile(r"^banner\s+(?:motd|login|exec|incoming|slip-ppp|config-save|prompt-timeout)\b[ \t]*(.*)$")
BANNER_TEXT = "banner-text "


def mark_banners(lines: list[str]) -> list[str]:
    """Banner bodies are free text, not configuration: a banner line such as "logging host
    192.0.2.1" must never satisfy a control. Their lines are kept (the login-banner control reads
    them) but prefixed with "banner-text ", which no configuration rule matches. Formats: IOS
    "banner login ^C...^C" (one or several lines), Cisco SB "banner login ^" ... "^", Arista
    "banner login" ... "EOF", HPE 'banner motd "..."'."""
    out, delim = [], None
    for raw in lines:
        s = raw.strip()
        if delim is not None:
            end = (s == "EOF") if delim == "EOF" else (delim in s)
            if delim == "EOF":
                text = "" if end else s
            else:
                text = s.split(delim)[0] if end else s
            if text:
                out.append(BANNER_TEXT + text)
            if end:
                delim = None
            continue
        m = BANNER_START.match(raw)          # never indented in a running configuration
        if m:
            rest = m.group(1).strip()
            if not rest:
                delim = "EOF"                # Arista: text lines until "EOF"
            else:
                d = "^C" if rest.startswith("^C") else rest[0]
                if d not in rest[len(d):]:
                    delim = d                # the closing delimiter comes on a later line
        out.append(raw)
    return out


# commands that only exist inside a block (line, interface, management ...) on IOS-like platforms:
# a device never prints them unindented, so such a line was written by hand and could escape
# the block it belongs to (e.g. "line vty 0 4" then an unindented "exec-timeout 0 0")
CHILD_ONLY = {
    "cisco_ios": re.compile(r"^(exec-timeout|transport (input|output)|access-class|login authentication|password \d "
                            r"|key [067] |switchport |ip address \S|shutdown$|description )"),
    "arista_eos": re.compile(r"^(exec-timeout|access-class|idle-timeout |switchport |ip address \S|shutdown$|description )"),
    "cisco_sb": re.compile(r"^(exec-timeout|password \d |switchport |shutdown$|description )"),
}


def structure_problems(text: str, vendor: str) -> list[str]:
    """Lines of a hand-made file that a device would have indented (offline audit, CI)."""
    pattern = CHILD_ONLY.get(vendor)
    if pattern is None:
        return []
    lines = mark_banners([raw[:MAX_LINE] for raw in text.lstrip("﻿").splitlines()])
    return [raw.strip()[:80] for raw in lines
            if raw[:1] not in (" ", "\t") and not raw.startswith(BANNER_TEXT) and pattern.match(raw.strip())]


def parse(text: str, state_text: str = "", vendor: str | None = None) -> Config:
    """vendor: the adapter, when known. RouterOS exports are rewritten only for MikroTik (or an
    unknown platform): another configuration with a "/..." line (a banner) is never rewritten."""
    # a file saved by Windows Notepad starts with a byte-order mark: never part of the first line
    text, state_text = text.lstrip("﻿"), state_text.lstrip("﻿")
    if text.lstrip().startswith("{"):
        try:
            text = flatten_json(json.loads(text))
        except ValueError:
            pass  # not JSON after all: parsed as text
    elif vendor in (None, "mikrotik") and re.search(r"(?m)^/[a-z]", text):
        text = routeros_terse(text)
    lines: list[str] = []
    blocks: list[Block] = []
    comments: list[str] = []
    current: Block | None = None

    raw_lines = [raw[:MAX_LINE] for raw in text.splitlines()]
    if vendor != "mikrotik":
        raw_lines = mark_banners(raw_lines)
    for raw in raw_lines:
        if not raw.strip():
            continue
        if raw.strip().startswith(COMMENT_PREFIXES):
            comments.append(raw.strip())
            continue
        stripped = raw.strip()
        indented = raw[0] in (" ", "\t")

        if indented and current is not None:
            current.children.append(stripped)
        elif stripped == "exit":
            # Cisco SB and HP close blocks with "exit"
            current = None
            continue
        else:
            current = Block(header=stripped)
            blocks.append(current)
        lines.append(stripped)

    return Config(lines=lines, blocks=blocks, state=parse_state(state_text), comments=comments)
