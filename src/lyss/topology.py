# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Network topology from collected LLDP/CDP neighbour tables.

Each device's state holds "show lldp neighbors" / "show cdp neighbors". Rows are parsed from the
fixed-width tables (column spans from the dashed separator line, or from the header labels),
neighbours are matched to inventory devices by chassis MAC first (hostnames can be duplicated),
then by unique hostname, and both ends of a link are merged into one edge.
"""

import re
from collections import defaultdict

from . import collector, inventory
from .config import parse_state
from .engine import normalize_port

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:.-]?){5}[0-9a-f]{2}$|^(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}$", re.I)

# column names, in order, for each table layout
LAYOUTS = {
    ("cisco_sb", "lldp"): ["local_port", "chassis", "remote_port", "name", "caps", "ttl"],
    ("cisco_sb", "cdp"): ["device_id", "local_port", "ver", "ttl", "caps", "platform", "remote_port"],
    ("cisco_ios", "lldp"): ["device_id", "local_port", "ttl", "caps", "remote_port"],
    ("cisco_ios", "cdp"): ["device_id", "local_port", "ttl", "caps", "platform", "remote_port"],
}
HEADER_LABELS = {
    "lldp": ["Device ID", "Local Intf", "Hold-time", "Capability", "Port ID"],
    "cdp": ["Device ID", "Local Intrfce", "Holdtme", "Capability", "Platform", "Port ID"],
}


def norm_mac(value: str) -> str | None:
    v = value.strip().lower()
    if not MAC_RE.match(v):
        # HP forms: "00 00 5e 00 53 01" (LLDP chassis id), "0000ab-000001" (show system)
        hexonly = re.sub(r"[\s:.-]", "", v)
        if re.fullmatch(r"(?:[0-9a-f]{2}[ ]){5}[0-9a-f]{2}|[0-9a-f]{6}-[0-9a-f]{6}", v) and len(hexonly) == 12:
            return hexonly
        return None
    return re.sub(r"[^0-9a-f]", "", v)


HP_SEPARATOR = re.compile(r"^\s*-+\s*\+(\s+-+)+\s*$")
HP_LLDP_LAYOUT = ["local_port", "chassis", "remote_port", "port_descr", "name"]


def parse_hp_lldp(lines: list[str]) -> list[dict]:
    """AOS-S "show lldp info remote-device": "LocalPort | ChassisId PortId PortDescr SysName",
    column spans from the "--------- + ------ ..." separator."""
    for i, line in enumerate(lines):
        if HP_SEPARATOR.match(line):
            spans = [(m.start(), m.end()) for m in re.finditer(r"-+", line)]
            break
    else:
        return []
    rows = []
    for line in lines[i + 1:]:
        if "|" not in line:
            continue
        cells = [line[a:b] if k < len(spans) - 1 else line[a:] for k, (a, b) in enumerate(spans)]
        row = dict(zip(HP_LLDP_LAYOUT, (c.replace("|", "").strip() for c in cells)))
        if not row.get("local_port"):
            continue
        row.update(protocol="lldp", caps="", local_port=normalize_port(row["local_port"]),
                   remote_port=normalize_port(row.get("remote_port", "")))
        mac = norm_mac(row.get("chassis", ""))
        if mac:
            row["chassis"] = ":".join(mac[k:k + 2] for k in range(0, 12, 2))
        rows.append(row)
    return rows


def _spans(lines: list[str], protocol: str) -> tuple[int, list[tuple[int, int]]] | None:
    """(index of first data line, column spans)."""
    for i, line in enumerate(lines):
        if re.match(r"^-{3,}( +-{2,})+\s*$", line):  # Cisco SB: dashed separator gives exact spans
            return i + 1, [(m.start(), m.end()) for m in re.finditer(r"-+", line)]
    labels = HEADER_LABELS[protocol]
    for i, line in enumerate(lines):  # IOS: column starts = header label positions
        if all(label in line for label in labels):
            starts = [line.index(label) for label in labels]
            return i + 1, [(s, starts[k + 1] if k + 1 < len(starts) else 10_000) for k, s in enumerate(starts)]
    return None


def parse_neighbors(lines: list[str], vendor: str, protocol: str) -> list[dict]:
    layout = LAYOUTS.get((vendor, protocol))
    found = _spans(lines, protocol) if layout else None
    if not found:
        return []
    first, spans = found
    rows: list[dict] = []
    pending = None
    for line in lines[first:]:
        if re.match(r"^\s*Total ", line) or not line.strip():
            continue
        if layout[0] == "device_id" and re.match(r"^\S+\s*$", line):
            pending = {"device_id": line.strip()}  # IOS: a long device ID sits alone on its own line
            continue
        # the last column takes the rest of the line (IOS prints long platform / port names)
        cells = [line[a:b] if k < len(spans) - 1 else line[a:] for k, (a, b) in enumerate(spans)]
        cells = [c.strip() for c in cells] + [""] * (len(layout) - len(spans))
        row = dict(zip(layout, cells))
        if not row["local_port"]:
            if any(row.values()) and rows and pending is None:
                # wrapped cells continue the previous row (Cisco SB wraps long values)
                for key, value in row.items():
                    if value:
                        rows[-1][key] += (" " if key == "platform" else "") + value
            continue
        if pending is not None and not row.get("device_id"):
            row["device_id"] = pending["device_id"]
        pending = None
        rows.append(row)
    for row in rows:
        row["protocol"] = protocol
        row["local_port"] = normalize_port(row["local_port"])
        row["remote_port"] = normalize_port(row.get("remote_port", ""))
    return rows


DETAIL_FIELDS = {
    "local_port": re.compile(r"^\s*(?:Interface|Local Intf):\s*([^,\s]+)", re.I),
    "remote_port": re.compile(r"(?:Port ID \(outgoing port\)|^\s*Port id):\s*(\S+)", re.I),
    "sysname": re.compile(r"^\s*(?:SysName|System Name):\s*(\S+)", re.I),
    "device_id": re.compile(r"^\s*Device[- ]ID:\s*(\S+)", re.I),
    "chassis": re.compile(r"^\s*Chassis id:\s*(\S+)", re.I),
    "platform": re.compile(r"^\s*Platform:\s*([^,]+?)\s*(?:,|$)", re.I),
    "caps": re.compile(r"Capabilities:\s*(.+)$", re.I),
    "version": re.compile(r"^\s*Version\s*:\s*(\S.*)$", re.I),
}
IP_LINE = re.compile(r"^\s*(?:IP(?:v4)?(?: address)?\s*:?)\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$", re.I)


def parse_neighbor_details(lines: list[str]) -> list[dict]:
    """Blocks of "show cdp/lldp neighbors detail" (separated by dashed lines), any vendor layout."""
    blocks, current = [], []
    for line in lines:
        if re.match(r"^\s*-{8,}\s*$", line):
            if current:
                blocks.append(current)
            current = []
        else:
            current.append(line)
    if current:
        blocks.append(current)
    out = []
    for block in blocks:
        rec = {"ips": []}
        for i, line in enumerate(block):
            for key, pattern in DETAIL_FIELDS.items():
                m = pattern.search(line)
                if m and key not in rec:
                    rec[key] = m.group(1).strip()
            m = IP_LINE.match(line)
            if m and m.group(1) not in rec["ips"]:
                rec["ips"].append(m.group(1))
            if line.strip().lower() == "system description:" and i + 1 < len(block):
                rec.setdefault("platform", block[i + 1].strip()[:120])  # LLDP: description on next line
        if rec.get("local_port"):
            rec["local_port"] = normalize_port(rec["local_port"])
            rec["remote_port"] = normalize_port(rec.get("remote_port", ""))
            out.append(rec)
    return out


def _identity(device: dict) -> dict:
    cfg_path, state_path = collector.config_paths(device)
    ident = {"hostname": "", "mac": None, "neighbors": []}
    if cfg_path.exists():
        text = cfg_path.read_text(encoding="utf-8", errors="replace")
        # Cisco / HP "hostname", RouterOS "/system identity set name=", SONiC config_db "hostname"
        m = (re.search(r'^hostname\s+"?([^"\s]+)"?\s*$', text, re.M)
             or re.search(r'^/system identity set name="?([^"\s]+)"?', text, re.M)
             or re.search(r'"hostname"\s*:\s*"([^"]+)"', text))
        ident["hostname"] = m.group(1) if m else ""
    if not state_path.exists():
        return ident
    state = parse_state(state_path.read_text(encoding="utf-8", errors="replace"))
    for line in state.get("show system", []) + state.get("show version", []):
        m = re.search(r"(?:System MAC Address|Base [Ee]thernet MAC [Aa]ddress|Base MAC Addr)\s*:\s*(\S+)", line)
        if m:
            ident["mac"] = norm_mac(m.group(1))
            break
    for protocol in ("lldp", "cdp"):
        ident["neighbors"] += parse_neighbors(state.get(f"show {protocol} neighbors", []), device["vendor"], protocol)
    ident["neighbors"] += parse_hp_lldp(state.get("show lldp info remote-device", []))
    ident["details"] = []
    for protocol in ("lldp", "cdp"):
        for rec in parse_neighbor_details(state.get(f"show {protocol} neighbors detail", [])):
            rec["protocol"] = protocol
            ident["details"].append(rec)
    # the detailed tables carry the management IP: attach it to the summary rows (same local port)
    by_port = defaultdict(list)
    for rec in ident["details"]:
        by_port[rec["local_port"]] += rec["ips"]
    for row in ident["neighbors"]:
        row["ips"] = sorted(set(by_port.get(row["local_port"], [])))
    return ident


def _kind(row: dict) -> str:
    caps, platform = row.get("caps", ""), row.get("platform", "")
    if "W" in caps.replace(" ", "").split(",") or re.search(r"\bW\b", caps) or "GWN" in row.get("name", ""):
        return "ap"
    if "VMware" in platform:
        return "server"
    if re.search(r"\b(B|S)\b", caps):
        return "switch"
    if re.search(r"\b(T|P)\b", caps):
        return "phone"
    return "device"


def build() -> dict:
    devices = inventory.load_devices()
    idents = {d["id"]: _identity(d) for d in devices}
    by_mac = {i["mac"]: dev_id for dev_id, i in idents.items() if i["mac"]}
    names = defaultdict(list)
    for dev_id, i in idents.items():
        if i["hostname"]:
            names[i["hostname"].lower()].append(dev_id)

    by_ip = {d["host"]: d["id"] for d in devices}

    def candidates(row: dict) -> list[str]:
        ip_hits = sorted({by_ip[ip] for ip in row.get("ips", []) if ip in by_ip})
        if len(ip_hits) == 1:
            return ip_hits  # management address announced by the neighbour
        for value in (row.get("chassis", ""), row.get("device_id", "")):
            mac = norm_mac(value)
            if mac and mac in by_mac:
                return [by_mac[mac]]  # chassis MAC is authoritative
        for value in (row.get("name", ""), row.get("device_id", "")):
            name = value.lower().split(".")[0]
            if names.get(name):
                return names[name]
            # IOS truncates LLDP system names to 20 characters
            prefixed = [i for host, ids in names.items() if len(name) >= 12 and host.startswith(name) for i in ids]
            if prefixed:
                return prefixed
        return []

    def resolve(dev_id: str, row: dict) -> str | None:
        found = candidates(row)
        if len(found) == 1:
            return found[0]
        # duplicate hostnames: keep the candidate that sees this device back on the remote port
        confirmed = [c for c in found
                     if any(r["local_port"] == row["remote_port"] and dev_id in candidates(r)
                            for r in idents[c]["neighbors"])]
        return confirmed[0] if len(confirmed) == 1 else None

    nodes, links = {}, {}
    for d in devices:
        result = inventory.load_result(d["id"]) or {}
        nodes[d["id"]] = {
            "id": d["id"], "kind": "switch", "managed": True, "label": d["id"], "host": d["host"],
            "hostname": idents[d["id"]]["hostname"], "model": result.get("model", ""),
            "firmware": result.get("firmware", ""),
            "level": (result.get("summary") or {}).get("achieved_level"),
            "fail": (result.get("summary") or {}).get("fail"),
        }

    for dev_id, ident in idents.items():
        for row in ident["neighbors"]:
            peer = resolve(dev_id, row)
            if peer is None:
                label = row.get("name") or row.get("device_id") or row.get("chassis") or "unknown"
                key = norm_mac(row.get("chassis", "")) or norm_mac(row.get("device_id", "")) or label.lower()
                peer = f"ext:{key}"
                node = nodes.setdefault(peer, {"id": peer, "kind": _kind(row), "managed": False, "label": label,
                                               "platform": row.get("platform", ""), "protocols": set()})
                if node["label"] == key or (len(label) > len(node["label"]) and not norm_mac(label)):
                    node["label"] = label
                node["protocols"].add(row["protocol"])
                node.setdefault("ips", set()).update(row.get("ips", []))
            if peer == dev_id:
                continue
            a, b = (dev_id, row["local_port"]), (peer, row["remote_port"])
            key = tuple(sorted([a, b]))
            link = links.setdefault(key, {"a": key[0][0], "a_port": key[0][1], "b": key[1][0],
                                          "b_port": key[1][1], "seen_by": set()})
            link["seen_by"].add(f"{dev_id}/{row['protocol']}")

    # one edge per device pair; parallel links (LAG / redundancy) are grouped with their ports
    edges = defaultdict(list)
    for link in links.values():
        edges[tuple(sorted([link["a"], link["b"]]))].append(link)
    out_edges = []
    for (a, b), group in edges.items():
        ports = []
        for l in sorted(group, key=lambda l: (l["a_port"], l["b_port"])):
            pa, pb = (l["a_port"], l["b_port"]) if l["a"] == a else (l["b_port"], l["a_port"])
            ports.append({"a_port": pa, "b_port": pb, "confirmed": len({s.split("/")[0] for s in l["seen_by"]}) > 1})
        out_edges.append({"a": a, "b": b, "ports": ports})

    for node in nodes.values():
        node["protocols"] = sorted(node.get("protocols", []))
        if "ips" in node:
            node["ips"] = sorted(node["ips"])
    return {"nodes": list(nodes.values()), "edges": out_edges}
