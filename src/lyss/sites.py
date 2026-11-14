# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Sites: named groups of address ranges (head office, agencies, subsidiaries...).

A switch belongs to the site set on its record, otherwise to the site whose ranges contain its
address (the most specific range wins). Sites are stored in the settings: no migration needed,
and a switch added later lands in the right site automatically.
"""

import ipaddress
import re

from . import inventory

NAME = re.compile(r"^[^\x00-\x1f<>]{1,60}$")
RANGE_TOKEN = re.compile(r"^([0-9]+\.[0-9]+\.[0-9]+\.)([0-9]+)-([0-9]+)$")


def normalise_range(raw: str) -> str | None:
    """"192.0.2.10-20" checked end to end and rewritten the way ipaddress reads it; None when raw is
    not an a-b range. ValueError when it looks like one and is not valid (leading zeros, 300, 20-10)."""
    m = RANGE_TOKEN.match(raw)
    if not m:
        return None
    first, last = ipaddress.IPv4Address(m.group(1) + m.group(2)), ipaddress.IPv4Address(m.group(1) + m.group(3))
    if first > last:
        raise ValueError(raw)
    return f"{first}-{int(last) & 255}"


def load() -> list[dict]:
    return inventory.load_settings().get("sites", [])


def get(site_id: str) -> dict | None:
    return next((s for s in load() if s["id"] == site_id), None)


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower().translate(str.maketrans("àâäéèêëîïôöùûüç", "aaaeeeeiioouuuc")))
    return s.strip("-")[:30] or "site"


def parse(text: str) -> tuple[list[str], list[str]]:
    """Site ranges: IPv4 CIDRs of any size (a site may be a /16), single IPs, a-b ranges."""
    nets, errors = [], []
    for raw in re.split(r"[\s,;]+", text.strip()):
        if not raw:
            continue
        try:
            ab = normalise_range(raw)
            if ab:
                nets.append(ab)
            else:
                net = ipaddress.ip_network(raw, strict=False)
                if net.version != 4 or net.prefixlen < 8:
                    raise ValueError
                nets.append(str(net))
        except ValueError:
            errors.append(f"{raw}: not an IPv4 address, CIDR (/8 or smaller) or a-b range")
    return nets, errors


def _networks(site: dict) -> list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, int]]:
    """(first, last, specificity) for each range of a site."""
    out = []
    for r in site.get("ranges", []):
        try:
            m = RANGE_TOKEN.match(r)
            if m:
                first = ipaddress.ip_address(m.group(1) + m.group(2))
                last = ipaddress.ip_address(m.group(1) + m.group(3))
                out.append((first, last, 32 - (int(last) - int(first)).bit_length()))
            else:
                net = ipaddress.ip_network(r)
                out.append((net.network_address, net.broadcast_address, net.prefixlen))
        except ValueError:
            continue    # a range saved by an older version that cannot be read: ignored, never a 500
    return out


def site_for_ip(host: str, sites: list[dict] | None = None) -> str:
    """Id of the site whose ranges contain this address (most specific first), or ""."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ""  # host names: set the site on the switch explicitly
    best, best_len = "", -1
    for site in load() if sites is None else sites:
        for first, last, length in _networks(site):
            if first <= ip <= last and length > best_len:
                best, best_len = site["id"], length
    return best


def of(device: dict, sites: list[dict] | None = None) -> str:
    """Effective site of a switch: explicit, else by address."""
    explicit = device.get("site") or ""
    known = {s["id"] for s in (load() if sites is None else sites)}
    return explicit if explicit in known else site_for_ip(device.get("host", ""), sites)


def save(name: str, ranges_text: str, site_id: str = "") -> tuple[str, list[str]]:
    """Create or update a site. Returns (id, errors)."""
    name = name.strip()
    errors = [] if NAME.match(name) else ["Site name: 1-60 characters, no < or >."]
    nets, range_errors = parse(ranges_text)
    errors += range_errors
    if not nets and not range_errors:
        errors.append("Site ranges: at least one address, CIDR or a-b range.")
    settings = inventory.load_settings()
    sites = settings.get("sites", [])
    # saving under an existing name updates that site (e.g. new ranges)
    site_id = site_id or next((s["id"] for s in sites if s["name"].lower() == name.lower()), "")
    sid = site_id or slug(name)
    if not site_id:
        taken = {s["id"] for s in sites}
        base, n = sid, 2
        while sid in taken:
            sid, n = f"{base[:27]}-{n}", n + 1
    elif not any(s["id"] == site_id for s in sites):
        errors.append("Site not found.")
    if errors:
        return sid, errors
    record = {"id": sid, "name": name, "ranges": nets}
    settings["sites"] = sorted([s for s in sites if s["id"] != sid] + [record], key=lambda s: s["name"].lower())
    inventory.save_settings(settings)
    return sid, []


def delete(site_id: str) -> bool:
    """Remove a site; switches pinned to it go back to automatic assignment."""
    settings = inventory.load_settings()
    sites = settings.get("sites", [])
    if not any(s["id"] == site_id for s in sites):
        return False
    settings["sites"] = [s for s in sites if s["id"] != site_id]
    inventory.save_settings(settings)
    for device in inventory.load_devices():
        if device.get("site") == site_id:
            inventory.set_site(device["id"], "")
    return True


def scan_ranges(site: dict) -> tuple[list[str], list[str]]:
    """The site's ranges that a discovery scan may probe (/20 or smaller), and the ones skipped."""
    ok, skipped = [], []
    for r in site.get("ranges", []):
        if RANGE_TOKEN.match(r) or ipaddress.ip_network(r).prefixlen >= 20:
            ok.append(r)
        else:
            skipped.append(r)
    return ok, skipped


def summary(rows: list[dict], sites: list[dict] | None = None) -> list[dict]:
    """Per-site totals for the dashboard. rows: [{"device": ..., "result": ... or None}]."""
    sites = load() if sites is None else sites
    names = {s["id"]: s["name"] for s in sites}
    out: dict[str, dict] = {s["id"]: {"id": s["id"], "name": s["name"], "devices": 0, "scanned": 0,
                                      "level1": 0, "level2": 0, "fail": 0} for s in sites}
    for row in rows:
        sid = of(row["device"], sites)
        entry = out.setdefault(sid, {"id": sid, "name": names.get(sid, "No site"), "devices": 0,
                                     "scanned": 0, "level1": 0, "level2": 0, "fail": 0})
        entry["devices"] += 1
        r = row.get("result")
        if r:
            entry["scanned"] += 1
            entry["fail"] += r["summary"]["fail"]
            entry["level1"] += r["summary"]["achieved_level"] >= 1
            entry["level2"] += r["summary"]["achieved_level"] >= 2
    return [e for e in out.values() if e["devices"] or e["id"]]
