# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Integrations that act after a scan. All are disabled until configured in Settings.

- E-mail alerts (SMTP): regressions (controls that started failing), collection errors and newly
  discovered switches; or a summary after every scan.
- CISO Assistant (open-source GRC): the fleet report is uploaded as a new revision of an evidence
  (REST API, token authentication), on demand or after scheduled scans.
- SIEM events (events.py): scan results as JSON events over syslog and/or a JSON-lines file.
Secrets (SMTP password, API token) are stored with the vault, never returned to the browser.
"""

import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage

import httpx

from . import PROJECT_LONG_NAME, PROJECT_NAME, events, inventory, vault

_ciso_transport = None  # tests inject an httpx.MockTransport here


# ---------------- e-mail ----------------

def smtp_settings() -> dict:
    return inventory.load_settings().get("smtp", {})


def send_mail(subject: str, body: str, cfg: dict | None = None) -> None:
    cfg = cfg or smtp_settings()
    msg = EmailMessage()
    msg["Subject"] = f"[{PROJECT_NAME}] {subject}"
    msg["From"] = cfg["sender"]
    msg["To"] = ", ".join(cfg["recipients"])
    msg.set_content(body)
    port = int(cfg.get("port") or 587)
    context = ssl.create_default_context()
    if cfg.get("security") == "ssl":
        server = smtplib.SMTP_SSL(cfg["host"], port, timeout=20, context=context)
    else:
        server = smtplib.SMTP(cfg["host"], port, timeout=20)
    with server:
        if cfg.get("security", "starttls") == "starttls":
            server.starttls(context=context)
        if cfg.get("username"):
            server.login(cfg["username"], vault.unprotect(cfg["secret"]))
        server.send_message(msg)


def scan_mail(job: dict, changes: dict, discovered: int) -> tuple[str, str] | None:
    """Subject and body for a finished scan, or None when there is nothing worth sending."""
    cfg = smtp_settings()
    errors = {d: i["message"] for d, i in job["items"].items() if i["status"] == "error"}
    regressions = {d: c["new_fail"] for d, c in changes.items() if c["new_fail"]}
    fixed = {d: c["fixed"] for d, c in changes.items() if c["fixed"]}
    if cfg.get("mode", "regressions") != "always" and not (regressions or errors or discovered):
        return None
    lines = [f"{PROJECT_LONG_NAME}: {job.get('trigger', 'manual')} scan of {len(job['items'])} switch(es) "
             f"finished {datetime.now():%Y-%m-%d %H:%M}.", ""]
    if regressions:
        lines.append("New failures (regressions):")
        lines += [f"  - {d}: {', '.join(c)}" for d, c in regressions.items()]
        lines.append("")
    if fixed:
        lines.append("Fixed since the previous scan:")
        lines += [f"  - {d}: {', '.join(c)}" for d, c in fixed.items()]
        lines.append("")
    if errors:
        lines.append("Collection errors:")
        lines += [f"  - {d}: {m}" for d, m in errors.items()]
        lines.append("")
    if discovered:
        lines += [f"{discovered} new switch(es) discovered on the network: review them in {PROJECT_NAME} > Discovery.", ""]
    lines.append("Details: open LYSS on the administration PC.")
    parts = [f"{sum(len(c) for c in regressions.values())} regression(s)" if regressions else "",
             f"{len(errors)} error(s)" if errors else "", f"{discovered} discovered" if discovered else ""]
    subject = "Scan: " + (", ".join(p for p in parts if p) or "no change")
    return subject, "\n".join(lines)


# ---------------- CISO Assistant ----------------

def ciso_settings() -> dict:
    return inventory.load_settings().get("ciso", {})


def _ciso_client(cfg: dict) -> httpx.Client:
    return httpx.Client(base_url=cfg["url"].rstrip("/"), timeout=60, verify=cfg.get("verify_tls", True),
                        headers={"Authorization": f"Token {vault.unprotect(cfg['secret'])}"},
                        transport=_ciso_transport)


def ciso_test(cfg: dict | None = None) -> str:
    """Name of the configured evidence (proves URL, token and evidence id are right)."""
    cfg = cfg or ciso_settings()
    with _ciso_client(cfg) as client:
        r = client.get(f"/api/evidences/{cfg['evidence_id']}/")
        r.raise_for_status()
        return r.json().get("name", cfg["evidence_id"])


def ciso_push(html: str, observation: str, cfg: dict | None = None) -> str:
    """Upload the report as a new evidence revision. Returns the revision id."""
    cfg = cfg or ciso_settings()
    name = f"{PROJECT_NAME}-report-{datetime.now():%Y%m%d-%H%M}.html"
    with _ciso_client(cfg) as client:
        r = client.post("/api/evidence-revisions/",
                        data={"evidence": cfg["evidence_id"], "observation": observation[:2000]},
                        files={"attachment": (name, html.encode("utf-8"), "text/html")})
        r.raise_for_status()
        return str(r.json().get("id", ""))


# ---------------- after a scan ----------------

def after_scan(job: dict, changes: dict, discovered: int) -> list[str]:
    notices = []
    smtp = smtp_settings()
    if smtp.get("enabled"):
        try:
            mail = scan_mail(job, changes, discovered)
            if mail:
                send_mail(*mail)
                notices.append("alert e-mail sent")
        except Exception as exc:
            notices.append(f"e-mail failed: {type(exc).__name__}: {exc}"[:200])
    siem = events.settings()
    if siem.get("enabled"):
        try:
            sent = events.send(events.build(job, changes, discovered, siem), siem)
            notices.append(f"{sent} event(s) sent to the SIEM")
        except Exception as exc:
            notices.append(f"SIEM events failed: {type(exc).__name__}: {exc}"[:200])
    ciso = ciso_settings()
    if ciso.get("enabled") and ciso.get("auto_push") and job.get("trigger") == "schedule":
        try:
            from . import report  # late import: report imports the inventory too
            ok = sum(1 for i in job["items"].values() if i["status"] == "done")
            ciso_push(report.render_html(), f"{PROJECT_NAME} scheduled scan: {ok} switch(es) assessed.")
            notices.append("report sent to CISO Assistant")
        except Exception as exc:
            notices.append(f"CISO Assistant push failed: {type(exc).__name__}: {exc}"[:200])
    return notices
