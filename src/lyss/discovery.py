# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Automatic discovery of switches that are not in the inventory yet.

Two vendor-neutral sources:
- neighbours: the detailed CDP/LLDP tables of managed switches announce each neighbour's
  management IP, platform and name (no traffic needed, runs after every scan);
- range scan: TCP 22 on address ranges chosen by the user; the SSH identification string
  hints at the platform (a hint only: the platform is confirmed when the switch is scanned).
Results are stored in private/discovery.json. Nothing is added to the inventory automatically.
"""

import ipaddress
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import collector, inventory, sites, topology

def _store():
    return inventory.PRIVATE / "discovery.json"


# a range scan meets many closed ports; paramiko logs each refused channel as an error
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
MAX_HOSTS = 4096

# (pattern on platform / system description, adapter, label)
PLATFORMS = [
    (r"\b(S[GF]\d{3}|SRW\d{4}|CBS\d{3}|SG\d{3}X?)", "cisco_sb", "Cisco Small Business"),
    (r"Cisco IOS|C1000|WS-C|C9[23]00|Catalyst|cisco\s+C\d", "cisco_ios", "Cisco IOS / IOS-XE"),
    # AOS-CX before AOS-S: both say "Aruba"; AOS-CX releases are XX.10.nn.nnnn (Virtual.10.17.1010 on the
    # simulator), AOS-S releases XX.15 / XX.16
    (r"AOS-CX|ArubaOS-CX|\b(?:[A-Z]{2}|Virtual)\.10\.\d{2}\.\d{4}\b", "aruba_aoscx", "HPE Aruba AOS-CX"),
    (r"ProCurve|Aruba|HP J\d|HPE?\b", "hp_procurve", "HP ProCurve / ArubaOS-Switch"),
    (r"Juniper Networks|\bJUNOS\b", "juniper_junos", "Juniper EX (Junos)"),
    (r"Huawei Versatile Routing Platform|\bHUAWEI S\d{4}", "huawei_vrp", "Huawei S series (VRP)"),
    (r"\bSONiC\b", "sonic", "SONiC"),   # LLDP system description "SONiC Software Version: ..."
    (r"Arista|\bcEOS|\bvEOS|\bEOS version", "arista_eos", "Arista EOS"),
    (r"MikroTik|RouterOS|\bCRS\d{3}", "mikrotik", "MikroTik RouterOS"),
]
# (pattern on the SSH identification string, adapter, label)
SSH_FINGERPRINTS = [
    (r"^SSH-[\d.]+-Cisco-", "cisco_ios", "Cisco IOS / IOS-XE"),
    (r"^SSH-[\d.]+-OpenSSH_[\dp.]+\.RL", "cisco_sb", "Cisco Small Business"),
    (r"^SSH-[\d.]+-Mocana", "hp_procurve", "HPE ArubaOS-Switch (probable)"),
    (r"^SSH-[\d.]+-RomSShell", None, "Embedded switch (RomSShell)"),
    # dropbear is left out on purpose: mostly access points and IoT devices (e.g. Grandstream GWN)
    (r"^SSH-[\d.]+-ROSSSH", "mikrotik", "MikroTik RouterOS"),
    (r"Comware|HUAWEI|VRP", None, "Network device"),
]
NOT_SWITCH = re.compile(r"VMware|ESXi|GWN\d|AP\d|Phone|Linux|Windows", re.I)

_lock = threading.Lock()
_scan = {"running": False, "done": 0, "total": 0, "found": 0, "started": None}


def guess_platform(text: str, table) -> tuple[str | None, str]:
    for pattern, adapter, label in table:
        if re.search(pattern, text or "", re.I):
            return adapter, label
    return None, ""


def load() -> dict:
    return inventory._read(_store(), {"candidates": {}, "ignored": [], "last_neighbors": None, "last_scan": None})


def _save(data: dict) -> None:
    inventory._write(_store(), data)


def _known() -> tuple[set, set]:
    devices = inventory.load_devices()
    return {d["host"] for d in devices}, {d["id"] for d in devices}


def _merge(data: dict, ip: str, info: dict) -> bool:
    """Add or refresh a candidate. Returns True if it is new."""
    now = datetime.now().isoformat(timespec="seconds")
    cand = data["candidates"].get(ip)
    new = cand is None
    cand = cand or {"ip": ip, "first_seen": now, "sources": []}
    for key in ("name", "platform", "adapter", "label", "banner", "version"):
        if info.get(key) and not cand.get(key):
            cand[key] = info[key]
    if info.get("adapter") and cand.get("adapter") is None:
        cand["adapter"] = info["adapter"]
    if info.get("source") and info["source"] not in cand["sources"]:
        cand["sources"] = (cand["sources"] + [info["source"]])[-6:]
    cand["last_seen"] = now
    data["candidates"][ip] = cand
    return new


def from_neighbors() -> int:
    """Switch-like neighbours announced by managed switches, not in the inventory. Returns new count."""
    hosts, _ = _known()
    data = load()
    new = 0
    devices = inventory.load_devices()
    idents = {d["id"]: topology._identity(d) for d in devices}
    # a known switch can announce other addresses (several VLAN interfaces): match it by MAC and
    # by hostname too, not only by its inventory address
    known_macs = {i["mac"] for i in idents.values() if i["mac"]}
    known_names = {i["hostname"].lower() for i in idents.values() if i["hostname"]}
    for device in devices:
        for rec in idents[device["id"]].get("details", []):
            text = " ".join(rec.get(k, "") for k in ("platform", "caps", "sysname", "device_id"))
            if NOT_SWITCH.search(text) or not re.search(r"switch|bridge|\bB\b|\bS\b", rec.get("caps", ""), re.I):
                continue
            macs = {topology.norm_mac(rec.get(k, "")) for k in ("chassis", "device_id")} - {None}
            names = {rec.get(k, "").lower().split(".")[0] for k in ("sysname", "device_id")} - {""}
            if macs & known_macs or names & known_names:
                continue
            adapter, label = guess_platform(rec.get("platform", ""), PLATFORMS)
            for ip in rec["ips"]:
                if ip in hosts or ip in data["ignored"]:
                    continue
                name = rec.get("sysname") or rec.get("device_id", "")
                new += _merge(data, ip, {
                    "name": "" if topology.norm_mac(name) else name.split(".")[0],
                    "platform": rec.get("platform", ""), "adapter": adapter, "label": label,
                    "version": rec.get("version", ""),
                    "source": f"neighbour of {device['id']} port {rec['local_port']} ({rec['protocol'].upper()})",
                })
    data["last_neighbors"] = datetime.now().isoformat(timespec="seconds")
    _save(data)
    return new


def parse_ranges(text: str) -> tuple[list[str], list[str]]:
    """Valid networks and error messages. Accepts CIDRs, single IPs and a-b ranges on the last octet."""
    nets, errors = [], []
    for raw in re.split(r"[\s,;]+", text.strip()):
        if not raw:
            continue
        try:
            ab = sites.normalise_range(raw)     # both ends checked: no leading zeros, no 300
            if ab:
                nets.append(ab)
            else:
                net = ipaddress.ip_network(raw, strict=False)
                if net.version != 4 or net.prefixlen < 20:
                    errors.append(f"{raw}: IPv4 only, /20 or smaller")
                    continue
                nets.append(str(net))
        except ValueError:
            errors.append(f"{raw}: not an address, CIDR or a-b range")
    return nets, errors


def expand(nets: list[str]) -> list[str]:
    out = []
    for n in nets:
        m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", n)
        if m:
            out += [f"{m.group(1)}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
        else:
            net = ipaddress.ip_network(n)
            out += [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]
    return list(dict.fromkeys(out))[:MAX_HOSTS]


def _banner(ip: str, jump, port: int = 22) -> str | None:
    """SSH identification string of ip:port, directly or through the jump host. None if closed."""
    chan = None
    try:
        if jump:
            # connect_timeout: with a source address, nc on the jump host gives up after 4 s
            # instead of waiting for the system TCP timeout (no process left behind)
            chan = jump.channel(ip, port, timeout=4, connect_timeout=4)
            chan.settimeout(5)
            data, deadline = b"", time.monotonic() + 8
            # one overall deadline: a host sending a byte every few seconds cannot hold a worker
            while b"\n" not in data and len(data) < 256 and time.monotonic() < deadline:
                chunk = chan.recv(256)
                if not chunk:
                    break
                data += chunk
        else:
            with socket.create_connection((ip, port), timeout=2) as s:
                s.settimeout(4)
                data = s.recv(256)
        line = data.split(b"\n", 1)[0].decode("ascii", errors="replace").strip()
        return line if line.startswith("SSH-") else None
    except Exception:
        return None
    finally:
        if chan is not None:
            chan.close()  # always: an open channel holds one of the jump host's sessions


def scan_status() -> dict:
    with _lock:
        return dict(_scan)


GENTLE_WORKERS = 6     # remote sites: few parallel probes, so VPN tunnels and remote IPS stay quiet
GENTLE_PAUSE = 0.1     # seconds between two probes of one worker


def start_scan(nets: list[str], via_jump: bool, gentle: bool = False, label: str = "") -> bool:
    """Probe TCP 22 on the ranges in the background. Returns False if a scan is already running.
    gentle: slow rate for ranges behind VPN tunnels or another site's firewall."""
    targets = expand(nets)
    hosts, _ = _known()
    with _lock:
        if _scan["running"]:
            return False
        _scan.update(running=True, done=0, total=len(targets), found=0, started=time.time(),
                     gentle=gentle, label=label)

    def run():
        settings = inventory.load_settings().get("jump", {})
        jump = collector.JumpHost(settings) if via_jump and settings.get("host") else None
        found = []

        def probe(ip):
            if gentle:
                time.sleep(GENTLE_PAUSE)
            banner = _banner(ip, jump)
            with _lock:
                _scan["done"] += 1
            if banner:
                adapter, label = guess_platform(banner, SSH_FINGERPRINTS)
                if label:  # switch-like SSH stacks only; servers (plain OpenSSH) are ignored
                    found.append((ip, banner, adapter, label))
                    with _lock:
                        _scan["found"] += 1

        try:
            workers = GENTLE_WORKERS if gentle else (24 if jump else 64)
            if jump and jump.source:
                workers = min(workers, 6)  # each probe is an exec session on the jump host (MaxSessions 10)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(probe, targets))
        finally:
            if jump:
                jump.close()
        data = load()
        for ip, banner, adapter, label in found:
            if ip not in hosts and ip not in data["ignored"]:
                _merge(data, ip, {"banner": banner, "adapter": adapter, "label": label,
                                  "source": f"range scan (SSH: {banner[:40]})"})
        data["last_scan"] = datetime.now().isoformat(timespec="seconds")
        _save(data)
        with _lock:
            _scan["running"] = False

    threading.Thread(target=run, daemon=True).start()
    return True


def pending() -> list[dict]:
    """Candidates still not in the inventory, newest first."""
    hosts, _ = _known()
    data = load()
    rows = [c for ip, c in data["candidates"].items() if ip not in hosts and ip not in data["ignored"]]
    return sorted(rows, key=lambda c: c.get("first_seen", ""), reverse=True)


def ignore(ip: str) -> None:
    data = load()
    if ip not in data["ignored"]:
        data["ignored"].append(ip)
    _save(data)


def suggest_id(cand: dict) -> str:
    _, ids = _known()
    base = re.sub(r"[^a-z0-9-]+", "-", (cand.get("name") or "").lower()).strip("-")[:32]
    base = base if base and base[0].isalnum() else "sw-" + cand["ip"].replace(".", "-")
    name, i = base, 2
    while name in ids:
        name, i = f"{base}-{i}", i + 1
    return name
