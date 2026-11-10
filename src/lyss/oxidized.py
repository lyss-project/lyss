# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Oxidized integration: assess the configurations Oxidized already backs up, without connecting to
the switches (no SSH from LYSS, no extra account on the devices).

Reads the Oxidized REST API (oxidized-web), read-only:
  GET /nodes.json                       the nodes, their model and last backup status
  GET /node/fetch/<group>/<name>        the last configuration of a node
Only configuration-based checks can be assessed: controls that need the device state (listening
services, SSH banner) are "unknown" unless the configuration settles them. A recent successful
Oxidized backup is evidence for LYSS-BKP-001 (automatic configuration backups). Secrets hidden by
Oxidized (remove_secret: <secret hidden>) cannot be checked: those verdicts become "unknown".
"""

import re
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

from .engine import audit, conformance, extract_facts, load_adapter, load_spec
from .config import parse

# Oxidized model -> LYSS adapter
MODELS = {"ios": "cisco_ios", "iosxe": "cisco_ios", "ciscosmb": "cisco_sb", "procurve": "hp_procurve",
          "routeros": "mikrotik", "eos": "arista_eos", "junos": "juniper_junos", "aoscx": "aruba_aoscx", "vrp": "huawei_vrp"}
BACKUP_MAX_AGE_DAYS = 7
HIDDEN = re.compile(r"<(secret hidden|secret removed|removed|configuration removed)>", re.I)
_transport = None  # tests inject an httpx.MockTransport here


def client(url: str, username: str = "", password: str = "", verify_tls: bool = True) -> httpx.Client:
    auth = (username, password) if username else None
    return httpx.Client(base_url=url.rstrip("/"), timeout=60, verify=verify_tls, auth=auth,
                        follow_redirects=True, transport=_transport)


def list_nodes(http: httpx.Client) -> list[dict]:
    r = http.get("/nodes.json")
    r.raise_for_status()
    return r.json()


def fetch_config(http: httpx.Client, node: dict) -> str:
    name = quote(node["name"], safe="")
    path = f"/node/fetch/{quote(node['group'], safe='')}/{name}" if node.get("group") else f"/node/fetch/{name}"
    r = http.get(path)
    r.raise_for_status()
    return r.text


def _parse_time(value) -> datetime | None:
    if not value:
        return None
    text = str(value).replace(" UTC", "+00:00").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S %z"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def backup_context(node: dict, now: datetime | None = None) -> dict:
    """LYSS-BKP-001 evidence from the node's last Oxidized backup."""
    last = node.get("last") or {}
    end = _parse_time(last.get("end"))
    if last.get("status") != "success" or not end:
        return {"last": None, "last_automatic": None, "versions": 0, "attestation": None}
    expires = end + timedelta(days=BACKUP_MAX_AGE_DAYS)
    now = now or datetime.now(timezone.utc)
    att = {"date": end.isoformat(), "expires": expires.isoformat(),
           "reference": f"Oxidized automatic backup, last success {end:%Y-%m-%d %H:%M} UTC"}
    if expires < now:
        att["expired"] = True
    return {"last": None, "last_automatic": None, "versions": 0, "attestation": att}


def assess(node: dict, config: str, level: int = 2, now: datetime | None = None) -> dict:
    """Result of one node, in the same shape as a LYSS scan result (plus source / node fields)."""
    vendor = MODELS[node["model"].lower()]
    findings = audit(config, vendor, level, "", {"backup": backup_context(node, now)})
    # evidence is redacted by the engine, so recognise the hidden lines by what precedes the marker
    hidden = [line[:m.start()].strip() for line in config.splitlines() if (m := HIDDEN.search(line))]
    hidden = [p for p in hidden if p]
    for f in findings:
        if f.verdict in ("fail", "pass") and any(e.strip().startswith(p) for e in f.evidence for p in hidden):
            f.verdict = "unknown"
            f.note = ("Oxidized hides this secret (remove_secret): how it is stored cannot be checked "
                      "from the backup. " + (f.note or "")).strip()
    facts = extract_facts(parse(config, "", vendor), load_adapter(vendor))
    return {
        "device": node["name"], "host": node.get("ip", ""), "group": node.get("group") or "",
        "vendor": vendor, "model": facts.get("model", ""), "firmware": facts.get("version", ""),
        "source": "oxidized", "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "spec_version": load_spec()["spec_version"], "summary": conformance(findings),
        "findings": [asdict(f) for f in findings],
    }


def assess_all(http: httpx.Client, level: int = 2, only: list[str] | None = None) -> tuple[list[dict], list[dict]]:
    """(results, skipped) for every Oxidized node with a supported model."""
    results, skipped = [], []
    for node in list_nodes(http):
        if only and node.get("name") not in only:
            continue
        model = (node.get("model") or "").lower()
        if model not in MODELS:
            skipped.append({"device": node.get("name"), "reason": f"model '{model}' not supported by LYSS"})
            continue
        try:
            config = fetch_config(http, node)
        except httpx.HTTPError as exc:
            skipped.append({"device": node.get("name"), "reason": f"no configuration: {exc}"[:200]})
            continue
        if not config.strip():
            skipped.append({"device": node.get("name"), "reason": "empty configuration (never backed up?)"})
            continue
        results.append(assess(node, config, level))
    return results, skipped
