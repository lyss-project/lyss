# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Management reachability: proof, from a real network, that switch management is (not) reachable.

The configuration says "SSH only from the admin network"; a probe run from a user PC shows
whether that is true. Two steps:

1. "lyss probe" on any PC of the network to test (for example a user VLAN): for each switch
   address it only opens and closes TCP connections to the management ports. No data, no
   credentials, no exploit. The result is a JSON file.
2. The file is imported into LYSS (web page "Reachability" or "lyss reachability import"), with a
   label and whether that network is authorised to reach switch management.

Effect on the assessment (engine.observed_failures), probes of the last MAX_AGE_DAYS:
  - LYSS-MGMT-010 fails when a management port answers from a network marked "not authorised";
  - LYSS-MGMT-001 fails when Telnet (TCP 23) answers, from any network;
  - LYSS-MGMT-003 fails when plain HTTP (TCP 80 / 8080) answers, from any network.
A probe never makes a control pass: a closed port from one PC proves nothing about others.
"""

import json
import socket
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from . import __version__, inventory

PORTS = {22: "ssh", 23: "telnet", 80: "http", 443: "https", 830: "netconf", 8080: "http-alt",
         8443: "https-alt", 8291: "winbox", 8728: "routeros-api", 8729: "routeros-api-tls"}
STATES = ("open", "closed", "filtered", "error")
MAX_TARGETS = 4096
MAX_PORTS = 32
MAX_RESULTS = MAX_TARGETS * len(PORTS)
MAX_AGE_DAYS = 90
KEEP_IMPORTS = 30


# ---------------- probe (runs on any PC, needs nothing but Python) ----------------

def _connect(target: str, port: int, timeout: float) -> dict:
    result = {"target": target, "port": port, "service": PORTS.get(port, str(port)), "state": "filtered",
              "source_ip": ""}
    s = None
    try:
        s = socket.socket(socket.AF_INET6 if ":" in target else socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        result["state"] = "open"
        result["source_ip"] = s.getsockname()[0]
    except ConnectionRefusedError:
        result["state"] = "closed"
    except (socket.timeout, TimeoutError):
        result["state"] = "filtered"
    except OSError:
        result["state"] = "error"       # no route, no IPv6 on this PC, network unreachable...
    finally:
        if s is not None:
            s.close()                   # nothing is ever sent
    return result


def canonical(value: str) -> str | None:
    """An exact IP address in one form (IPv4-mapped IPv6 "::ffff:192.0.2.1" -> "192.0.2.1")."""
    import ipaddress
    ip = inventory.strict_ip(str(value).strip())
    if ip is None:
        return None
    addr = ipaddress.ip_address(ip)
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped or addr)


def probe(targets: list[str], ports: list[int] | None = None, timeout: float = 2.0, workers: int = 32) -> dict:
    """TCP connect test of each management port of each target. Targets must be IP addresses of
    switches: no ranges, no "any" address, no broadcast or multicast."""
    import ipaddress
    clean = []
    for t in targets:
        ip = canonical(t)
        if ip is None:
            raise ValueError(f"not an IP address: {t!r}")
        addr = ipaddress.ip_address(ip)
        if addr.is_unspecified or addr.is_multicast or ip == "255.255.255.255":
            raise ValueError(f"not a switch address: {t!r}")
        clean.append(ip)
    clean = list(dict.fromkeys(clean))
    if len(clean) > MAX_TARGETS:
        raise ValueError(f"at most {MAX_TARGETS} addresses per probe")
    ports = sorted(set(ports or PORTS))
    if len(ports) > MAX_PORTS or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError(f"at most {MAX_PORTS} ports, between 1 and 65535 (this is a management check, not a port scan)")
    started = datetime.now().isoformat(timespec="seconds")
    jobs = [(t, p) for t in clean for p in ports]
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 64))) as pool:
        results = list(pool.map(lambda tp: _connect(tp[0], tp[1], timeout), jobs))
    return {"tool": "LYSS", "version": __version__, "kind": "reachability", "started": started,
            "finished": datetime.now().isoformat(timespec="seconds"),
            "source": {"hostname": socket.gethostname()[:100]}, "results": results}


# ---------------- import and use (on the LYSS machine) ----------------

def _file():
    return inventory.PRIVATE / "reachability.json"


_cache: dict = {"key": None, "imports": []}


def load() -> list[dict]:
    """The stored imports. Cached on the file's size and time: every switch of a scan reads them."""
    from . import sealed
    path = _file()
    if not path.exists():
        return []
    st = path.stat()
    key = (str(path), st.st_mtime_ns, st.st_size)
    if _cache["key"] != key:
        _cache.update(key=key, imports=json.loads(sealed.read_text(path)))
    return _cache["imports"]


def _save(imports: list[dict], now: datetime | None = None) -> None:
    from . import sealed   # network layout and exposure: encrypted at rest like the results
    cutoff = ((now or datetime.now()) - timedelta(days=MAX_AGE_DAYS)).isoformat()
    kept = [i for i in imports if i["date"] >= cutoff]   # expired imports first, then the oldest
    sealed.write_text(_file(), json.dumps(kept[-KEEP_IMPORTS:], ensure_ascii=False))


def validate(report: dict, known_hosts: set[str] | None = None) -> tuple[list[dict], dict]:
    """The results of a probe file, checked: the file comes from another PC (untrusted). Kept: the
    OPEN management ports of switches of the inventory (known_hosts), once each; plus counts."""
    if not isinstance(report, dict) or report.get("kind") != "reachability" or not isinstance(report.get("results"), list):
        raise ValueError("not a LYSS reachability file (made by \"lyss probe\")")
    if len(report["results"]) > MAX_RESULTS:
        raise ValueError("too many results in the file")
    kept, targets, tested = {}, set(), 0
    for r in report["results"]:
        if not isinstance(r, dict):
            raise ValueError("invalid result in the file")
        target, port, state = canonical(r.get("target", "")), r.get("port"), r.get("state")
        if target is None or type(port) is not int or not 1 <= port <= 65535 or state not in STATES:
            raise ValueError("invalid result in the file (address, port or state)")
        if port not in PORTS or (known_hosts is not None and target not in known_hosts):
            continue   # not a management port, or not a switch of this inventory
        targets.add(target)
        tested += 1
        if state == "open":
            kept[(target, port)] = {"target": target, "port": port, "service": PORTS[port], "state": "open",
                                    "source_ip": canonical(r.get("source_ip") or "") or ""}
    return list(kept.values()), {"targets": len(targets), "tested": tested}


def _date(value, now: datetime) -> str:
    """The probe date from the file: a real past date, never a future one (a wrong or forged
    clock would otherwise keep the evidence forever)."""
    try:
        dt = datetime.fromisoformat(str(value)[:32])
        dt = dt.replace(tzinfo=None) if dt.tzinfo is None else dt.astimezone().replace(tzinfo=None)
    except ValueError:
        return now.isoformat(timespec="seconds")
    return min(dt, now).isoformat(timespec="seconds")


def import_report(report: dict, label: str, authorized: bool) -> dict:
    from . import locks
    hosts = {canonical(d.get("host", "")) for d in inventory.load_devices()} - {None}
    results, counts = validate(report, hosts)
    source = report.get("source") if isinstance(report.get("source"), dict) else {}
    now = datetime.now()
    entry = {"id": uuid.uuid4().hex[:8], "label": " ".join(str(label).split())[:80] or "unnamed network",
             "authorized": bool(authorized), "date": _date(report.get("started"), now),
             "imported": now.isoformat(timespec="seconds"),
             "source_hostname": " ".join(str(source.get("hostname", "")).split())[:100],
             "results": results, **counts}
    with inventory._lock, locks.file_lock(_file()):
        imports = list(load())
        imports.append(entry)
        _save(imports, now)
    return entry


def delete(import_id: str) -> bool:
    from . import locks
    with inventory._lock, locks.file_lock(_file()):
        imports = list(load())
        kept = [i for i in imports if i["id"] != import_id]
        _save(kept)
    return len(kept) < len(imports)


def for_device(device: dict, now: datetime | None = None) -> list[dict]:
    """Observations about one switch (its inventory address only) from recent imports."""
    host = canonical(device.get("host", ""))
    if host is None:
        return []
    cutoff = ((now or datetime.now()) - timedelta(days=MAX_AGE_DAYS)).isoformat()
    out = []
    for imp in load():
        if imp["date"] < cutoff:
            continue
        for r in imp["results"]:
            if r["target"] == host:
                out.append({**r, "label": imp["label"], "authorized": imp["authorized"], "date": imp["date"]})
    return out


def summary(imp: dict) -> dict:
    return {"targets": imp.get("targets", 0), "open": len(imp["results"]),
            "open_switches": len({r["target"] for r in imp["results"]})}
