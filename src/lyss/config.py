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


STATE_HEADER = re.compile(r"^=====\s*(.+?)\s*=====\s*$")


def parse_state(text: str) -> dict[str, list[str]]:
    """Split collector output ("===== show x =====" sections) into {command: lines}."""
    sections: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        m = STATE_HEADER.match(raw)
        if m:
            current = m.group(1)
            sections[current] = []
        elif current is not None and raw.strip():
            sections[current].append(raw.rstrip())
    return sections


COMMENT_PREFIXES = ("!", "#", ";")


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
            out.append(f"{table}|{key}")
            if isinstance(fields, dict):
                for name in sorted(fields):
                    value = fields[name]
                    if isinstance(value, list):
                        value = ",".join(str(v) for v in value)
                    out.append(f"  {name}={str(value).replace(chr(13), '').replace(chr(10), chr(92) + 'n')}")
    return "\n".join(out) + "\n"


def parse(text: str, state_text: str = "") -> Config:
    if text.lstrip().startswith("{"):
        try:
            text = flatten_json(json.loads(text))
        except ValueError:
            pass  # not JSON after all: parsed as text
    lines: list[str] = []
    blocks: list[Block] = []
    comments: list[str] = []
    current: Block | None = None

    for raw in text.splitlines():
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
