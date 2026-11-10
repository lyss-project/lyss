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


# a state file written by the collector starts with "collected: <date>" then "sections: #<nonce>":
# every section header carries this random value, unknown to the switch, so a "===== x =====" line
# inside command output (text set by a neighbour over CDP/LLDP, a banner...) can never open or
# replace a section
STATE_NONCE = re.compile(r"^sections:[ \t]+#([0-9a-f]{16})[ \t]*$")
MAX_LINE = 4096   # characters kept per line: configurations and state are untrusted input


def _header(raw: str) -> tuple[str, str] | None:
    """("show version", nonce or "") for a "===== show version ===== [#nonce]" line. String
    operations only: a crafted line can never make the parsing slow."""
    s = raw.strip()
    if not s.startswith("====="):
        return None
    nonce = ""
    if len(s) > 18 and s[-17:-16] == "#" and s[-18:-17] in (" ", "\t") and all(c in "0123456789abcdef" for c in s[-16:]):
        nonce, s = s[-16:], s[:-17].rstrip()
    if not s.endswith("=====") or len(s) <= 10:
        return None
    name = s[5:-5].strip()
    return (name, nonce) if name else None


def _nonce(lines: list[str]) -> str | None:
    if len(lines) >= 2 and lines[0].startswith("collected: ") and (n := STATE_NONCE.match(lines[1])):
        return n.group(1)
    return None


def parse_state(text: str) -> dict[str, list[str]]:
    """Split collector output ("===== show x =====" sections) into {command: lines}.
    Collected files: only headers carrying the file's nonce count. Hand-made files (offline
    audit, no nonce): a section keeps its first occurrence; a repeated header is plain text
    (state_problems reports it)."""
    lines = [raw[:MAX_LINE] for raw in text.splitlines()]
    nonce = _nonce(lines)
    sections: dict[str, list[str]] = {}
    current = None
    for raw in lines[2:] if nonce else lines:
        h = _header(raw)
        if h and (h[1] == nonce if nonce else not h[1]) and h[0] not in sections:
            sections[h[0]] = []
            current = h[0]
        elif current is not None and raw.strip():
            sections[current].append(raw.rstrip())
    return sections


def state_problems(text: str) -> list[str]:
    """Section headers repeated in a hand-made state file (offline audit, CI). Text inside a
    command output (a neighbour's CDP/LLDP fields) could imitate a header: such a file is refused
    rather than read with a guess."""
    lines = [raw[:MAX_LINE] for raw in text.splitlines()]
    if _nonce(lines):
        return []   # collected by LYSS: headers are authenticated by the nonce
    seen, repeated = set(), []
    for raw in lines:
        h = _header(raw)
        if h and not h[1]:
            if h[0] in seen and h[0] not in repeated:
                repeated.append(h[0])
            seen.add(h[0])
    return repeated


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


MAX_JUNOS_LINES = 200_000          # a switch configuration is far smaller (untrusted input)
MAX_JUNOS_DEPTH = 64               # real Junos hierarchies are under 20 levels deep
MAX_JUNOS_CHARS = 20_000_000       # total size of the converted "set" text
MAX_RANGE_MEMBERS = 1024


def _junos_tokens(text: str) -> list[str]:
    """Words, quoted strings and { } ; [ ] of a Junos curly-brace configuration, without comments
    (/* ... */ and "#" at the start of a token: "## Last commit", "## SECRET-DATA")."""
    tokens, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c in "{};[]":
            tokens.append(c)
            i += 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            tokens.append(text[i:j + 1])
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in ' \t\r\n{};[]"':
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def junos_braces_to_set(text: str) -> str:
    """Junos curly-brace configuration ("show configuration") -> one "set" line per statement, as
    "show configuration | display set" prints it. Inactive statements ("inactive:") and everything
    under them are left out, because they are not in effect; "protect:" marks are dropped."""
    out: list[str] = []
    path: list[tuple[list[str], bool]] = []
    stmt: list = []
    in_list: list[str] | None = None

    def clean(words: list) -> tuple[list, bool]:
        """(words without the inactive: / protect: marks, True if marked inactive)."""
        inactive = False
        while words and isinstance(words[0], str) and words[0] in ("inactive:", "protect:"):
            inactive = inactive or words[0] == "inactive:"
            words = words[1:]
        return words, inactive

    size = 0
    for tok in _junos_tokens(text):
        if len(out) > MAX_JUNOS_LINES or len(path) > MAX_JUNOS_DEPTH or size > MAX_JUNOS_CHARS:
            break                               # not a real configuration: stop converting
        if in_list is not None:
            if tok == "]":
                stmt.append(in_list)
                in_list = None
            elif tok not in ("{", "}", ";", "["):
                in_list.append(tok)
            continue
        if tok == "[":
            in_list = []
        elif tok == "{":
            words, inactive = clean(stmt)
            path.append(([w for w in words if isinstance(w, str)], inactive))
            stmt = []
        elif tok == "}":
            if path:
                path.pop()
            stmt = []
        elif tok == ";":
            words, inactive = clean(stmt)
            stmt = []
            if not words or inactive or any(off for _, off in path):
                continue
            prefix = " ".join(w for p, _ in path for w in p)
            lists = [w for w in words if isinstance(w, list)]
            head = " ".join(w for w in words if isinstance(w, str))
            base = f"set {prefix} {head}".replace("  ", " ").rstrip()
            new = [f"{base} {value}" for value in lists[0]] if lists else [base]   # "[ a b ]" -> one line each
            out.extend(new)
            size += sum(len(l) + 1 for l in new)
        else:
            stmt.append(tok)
    return "\n".join(out) + "\n"


def _junos_range_members(first: str, last: str) -> list[str]:
    """"ge-0/0/0", "ge-0/0/23" -> ge-0/0/0 ... ge-0/0/23 (same prefix only, bounded)."""
    a, b = re.match(r"^(.*?)(\d+)$", first), re.match(r"^(.*?)(\d+)$", last)
    if not (a and b and a.group(1) == b.group(1)):
        return [first, last]
    lo, hi = int(a.group(2)), int(b.group(2))
    if not 0 <= hi - lo <= MAX_RANGE_MEMBERS:
        return [first, last]
    return [f"{a.group(1)}{n}" for n in range(lo, hi + 1)]


def junos_normalize(text: str) -> str:
    """Junos configuration -> "set" lines (curly braces converted, deactivated statements removed)
    followed by one indented block per interface ("interfaces ge-0/0/1" + the rest of each of its
    "set interfaces ge-0/0/1 ..." lines), so the block rules (where / where_not) work as on other
    platforms. Interface ranges ("interface-range R member-range ge-0/0/0 to ge-0/0/23") give their
    settings to every member."""
    if not re.search(r"(?m)^\s*set ", text) and "{" in text:
        text = junos_braces_to_set(text)
    lines = [l.strip() for l in text.splitlines() if l.strip()][:MAX_JUNOS_LINES]
    # a set lookup of the deactivated paths: linear in the size of the file, even a hostile one
    deactivated = {tuple(l.split()[1:]) for l in lines if l.startswith("deactivate ") and len(l.split()) > 1}
    longest = max((len(d) for d in deactivated), default=0)

    def is_active(line: str) -> bool:
        words = tuple(line.split()[1:])
        return not any(words[:n] in deactivated for n in range(1, min(len(words), longest) + 1))

    set_lines = [l for l in lines if l.startswith("set ") and is_active(l)]
    members: dict[str, list[str]] = {}
    for l in set_lines:
        if m := re.match(r"^set interfaces interface-range (\S+) member-range (\S+) to (\S+)$", l):
            members.setdefault(m.group(1), []).extend(_junos_range_members(m.group(2), m.group(3)))
        elif m := re.match(r"^set interfaces interface-range (\S+) member (\S+)$", l):
            members.setdefault(m.group(1), []).append(m.group(2))
    blocks: dict[str, list[str]] = {}
    children = 0
    for l in set_lines:
        if children > MAX_JUNOS_LINES:
            break                               # ranges multiplied beyond any real switch
        if m := re.match(r"^set interfaces interface-range (\S+) (?!member(?:-range)? )(.+)$", l):
            for name in members.get(m.group(1), [])[:MAX_RANGE_MEMBERS]:
                blocks.setdefault(name, []).append(m.group(2))
                children += 1
        elif m := re.match(r"^set interfaces (?!interface-range )(\S+) (.+)$", l):
            blocks.setdefault(m.group(1), []).append(m.group(2))
            children += 1
    out = [l for l in lines if l.startswith("#")] + set_lines   # "## Last commit ..." stays a comment
    for name, children in blocks.items():
        out.append(f"interfaces {name}")
        out.extend(f"  {c}" for c in children)
    return "\n".join(out) + "\n"


BANNER_START = re.compile(r"^banner\s+(?:motd|login|exec|incoming|slip-ppp|config-save|prompt-timeout)\b[ \t]*(.*)$")
MACRO_START = re.compile(r"^macro name \S+\s*$")
BANNER_TEXT = "banner-text "


def _text_blocks(lines: list[str]) -> tuple[list[str], bool]:
    """(lines with free-text bodies marked, True if a body is still open at the end)."""
    out, delim = [], None
    for raw in lines:
        s = raw.strip()
        if delim is not None:
            # the body ends on the line that ENDS with the delimiter ("Press ^C to quit" inside
            # the text does not end it); Arista "EOF" and IOS macro "@" stand alone on their line
            end = (s == delim) if delim in ("EOF", "@") else s.endswith(delim)
            text = s[:-len(delim)].rstrip() if end and delim not in ("EOF", "@") else ("" if end else s)
            if text:
                out.append(BANNER_TEXT + text)
            if end:
                delim = None
            continue
        if MACRO_START.match(raw):
            delim = "@"                      # IOS "macro name X": commands of a macro until "@"
        elif m := BANNER_START.match(raw):   # never indented in a running configuration
            rest = m.group(1).strip()
            if not rest:
                delim = "EOF"                # Arista: text lines until "EOF"
            else:
                d = "^C" if rest.startswith("^C") else rest[0]
                if not (len(rest) > len(d) and rest.endswith(d)):
                    delim = d                # the closing delimiter comes on a later line
        out.append(raw)
    return out, delim is not None


def mark_banners(lines: list[str]) -> list[str]:
    """Banner bodies are free text, not configuration: a banner line such as "logging host
    192.0.2.1" must never satisfy a control. Their lines are kept (the login-banner control reads
    them) but prefixed with "banner-text ", which no configuration rule matches. Formats: IOS
    "banner login ^C...^C" (one or several lines), Cisco SB "banner login ^" ... "^", Arista
    "banner login" ... "EOF", HPE 'banner motd "..."'. IOS "macro name" bodies (until "@") are
    commands applied only when the macro is run: marked the same way."""
    return _text_blocks(lines)[0]


# commands that only exist inside a block (line, interface, management ...) on IOS-like platforms:
# a device never prints them unindented, so such a line was written by hand and could escape
# the block it belongs to (e.g. "line vty 0 4" then an unindented "exec-timeout 0 0")
CHILD_ONLY = {
    "cisco_ios": re.compile(r"^(exec-timeout|transport (input|output)|access-class|login authentication|password \d "
                            r"|key [067] |switchport |ip address \S|shutdown$|description )"),
    "arista_eos": re.compile(r"^(exec-timeout|access-class|idle-timeout |switchport |ip address \S|shutdown$|description )"),
    "cisco_sb": re.compile(r"^(exec-timeout|password \d |switchport |shutdown$|description )"),
}


# block headers: a device never prints them indented, so an indented one would hide its whole block
# inside the previous block (e.g. an indented "line vty 0 4" escapes the vty checks)
HEADER_ONLY = re.compile(r"^(line (con|vty|aux)\b|interface \S|radius server |tacacs server |username |aaa |"
                         r"ip access-list |hostname |enable (secret|password)\b|management (ssh|telnet|api|console)\b)")


def structure_problems(text: str, vendor: str) -> list[str]:
    """What a device would never print, in a hand-made file (offline audit, CI): block commands
    not indented, block headers indented, a banner or macro that never ends."""
    pattern = CHILD_ONLY.get(vendor)
    if pattern is None:
        return []
    lines, still_open = _text_blocks([raw[:MAX_LINE] for raw in text.lstrip("﻿").splitlines()])
    problems = []
    for raw in lines:
        if raw.startswith(BANNER_TEXT):
            continue
        indented = raw[:1] in (" ", "\t")
        if (not indented and pattern.match(raw.strip())) or (indented and HEADER_ONLY.match(raw.strip())):
            problems.append(raw.strip()[:80])
    if still_open:
        problems.append("a banner or macro that never ends")
    return problems


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
    elif vendor == "juniper_junos":
        text = junos_normalize(text)
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
