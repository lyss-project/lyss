# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""LYSS local web interface.

Security model (local, single administrator):
- listens on 127.0.0.1 only (see `python -m lyss ui`), no API docs exposed
- admin password hashed with scrypt; 5 failed logins lock the login for 5 minutes
- server-side sessions (random token, HttpOnly + SameSite=Strict cookie, 30 min idle timeout)
- every POST needs the session CSRF token and a same-origin Origin header
- strict CSP (no inline script, no external resources), anti-framing, no-referrer
- switch passwords are DPAPI-protected on disk and never sent to the browser
"""

import hmac
import ipaddress
import re
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import (PROJECT_LONG_NAME, PROJECT_NAME, __version__, changes, collector, discovery, events, firmware,
                history, inventory, notify, remediate, report, scan, sites, topology, vault)
from ..engine import ADAPTER_DIR, load_spec

HERE = Path(__file__).parent
SESSION_COOKIE = "lyss_session"
SESSION_IDLE = 30 * 60
MAX_FAILURES, LOCKOUT = 5, 5 * 60
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
BACKUP_FILE = re.compile(r"^\d{8}-\d{6}\.cfg$")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals.update(project=PROJECT_NAME, project_long=PROJECT_LONG_NAME, version=__version__)

_sessions: dict[str, dict] = {}
_failures = {"count": 0, "locked_until": 0.0}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    # not "no-referrer": with it, browsers send "Origin: null" on form POSTs
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class LoginRequired(Exception):
    pass


@app.exception_handler(LoginRequired)
async def _to_login(request: Request, exc: LoginRequired):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "login required"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


@app.middleware("http")
async def _security(request: Request, call_next):
    if request.method == "POST":
        # Browsers send Sec-Fetch-Site; fall back to the Origin header for clients that do not
        site = request.headers.get("sec-fetch-site")
        origin = request.headers.get("origin")
        if site is not None:
            refused = site not in ("same-origin", "none")
        else:
            refused = origin is not None and origin != f"http://{request.headers.get('host')}"
        if refused:
            return PlainTextResponse("Cross-origin request refused", status_code=403)
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    return response


# ---------------- sessions ----------------

def _session(request: Request) -> dict:
    token = request.cookies.get(SESSION_COOKIE, "")
    session = _sessions.get(token)
    if not session or session["expires"] < time.time():
        _sessions.pop(token, None)
        raise LoginRequired()
    session["expires"] = time.time() + SESSION_IDLE
    return session


def _check_csrf(session: dict, token: str) -> None:
    if not hmac.compare_digest(session["csrf"], token or ""):
        raise LoginRequired()


def _new_session(response) -> None:
    token = secrets.token_urlsafe(32)
    _sessions[token] = {"csrf": secrets.token_urlsafe(32), "expires": time.time() + SESSION_IDLE}
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_IDLE)


def _render(request: Request, name: str, session: dict | None = None, status: int = 200, **ctx):
    ctx.update(csrf=(session or {}).get("csrf", ""), logged_in=session is not None)
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def _vendors() -> list[str]:
    return sorted(p.stem for p in ADAPTER_DIR.glob("*.yaml"))


# ---------------- login ----------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    first_run = inventory.load_settings().get("admin") is None
    return _render(request, "setup.html" if first_run else "login.html")


@app.post("/setup")
def setup(request: Request, password: str = Form(...), confirm: str = Form(...)):
    settings = inventory.load_settings()
    if settings.get("admin") is not None:
        return RedirectResponse("/login", status_code=303)
    if len(password) < 12 or password != confirm:
        return _render(request, "setup.html", status=400,
                       error="Use at least 12 characters, typed twice identically.")
    settings["admin"] = inventory.hash_password(password)
    inventory.save_settings(settings)
    response = RedirectResponse("/", status_code=303)
    _new_session(response)
    return response


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    now = time.time()
    if _failures["locked_until"] > now:
        wait = int(_failures["locked_until"] - now) // 60 + 1
        return _render(request, "login.html", status=429, error=f"Too many attempts. Try again in {wait} min.")
    if not inventory.check_password(password, inventory.load_settings().get("admin")):
        _failures["count"] += 1
        if _failures["count"] >= MAX_FAILURES:
            _failures.update(count=0, locked_until=now + LOCKOUT)
        return _render(request, "login.html", status=401, error="Wrong password.")
    _failures["count"] = 0
    response = RedirectResponse("/", status_code=303)
    _new_session(response)
    return response


@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    _sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---------------- dashboard ----------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, site: str = ""):
    session = _session(request)
    all_sites = sites.load()
    names = {s["id"]: s["name"] for s in all_sites}
    every = []
    for device in inventory.load_devices():
        result = inventory.load_result(device["id"])
        every.append({"device": device, "result": result, "site": sites.of(device, all_sites)})
    site_rows = sites.summary(every, all_sites) if all_sites else []
    # ?site=<id> filters the page to one site; "-" = switches outside every site
    current = site if site == "-" or site in names else ""
    rows = [r for r in every if not current or r["site"] == ("" if current == "-" else current)]
    totals = {"devices": len(rows),
              "scanned": sum(1 for r in rows if r["result"]),
              "fail": sum(r["result"]["summary"]["fail"] for r in rows if r["result"]),
              "level1": sum(1 for r in rows if r["result"] and r["result"]["summary"]["achieved_level"] >= 1)}
    top = report.fleet(report.collect_results([r["device"]["id"] for r in rows] if current else None))["top"][:6]
    return _render(request, "dashboard.html", session, rows=rows, totals=totals, top=top,
                   site_rows=site_rows, site_names=names, current_site=current,
                   discovered=len(discovery.pending()),
                   trend=history.fleet_trend([r["device"]["id"] for r in rows]),
                   ciso_enabled=notify.ciso_settings().get("enabled"),
                   schedule=inventory.load_settings().get("schedule", {}),
                   jump_ready=bool(inventory.load_settings().get("jump", {}).get("host")))


@app.get("/topology", response_class=HTMLResponse)
def topology_page(request: Request):
    session = _session(request)
    return _render(request, "topology.html", session)


@app.get("/api/topology")
def topology_data(request: Request):
    _session(request)
    return topology.build()


@app.get("/matrix", response_class=HTMLResponse)
def matrix(request: Request):
    session = _session(request)
    rows = report.collect_results()
    return _render(request, "matrix.html", session, rows=rows, fleet=report.fleet(rows), symbol=report.SYMBOL)


def _download(content: str, filename: str, media_type: str):
    return Response(content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _export_scope(device: str, site: str) -> tuple[list[str] | None, str, str]:
    """(device ids or None for the fleet, file name part, report subtitle)."""
    if device and inventory.get_device(device):
        return [device], device, ""
    site_obj = sites.get(site)
    if site_obj:
        all_sites = sites.load()
        ids = [d["id"] for d in inventory.load_devices() if sites.of(d, all_sites) == site]
        return ids or ["\x00none"], f"site-{site}", site_obj["name"]
    return None, "fleet", ""


@app.get("/export/report.html")
def export_html(request: Request, device: str = "", site: str = ""):
    _session(request)
    ids, part, scope = _export_scope(device, site)
    name = f"{PROJECT_NAME}-{part}-{time.strftime('%Y%m%d-%H%M')}.html"
    return _download(report.render_html(ids, scope=scope), name, "text/html; charset=utf-8")


@app.get("/export/report.json")
def export_json(request: Request, device: str = "", site: str = ""):
    _session(request)
    ids, part, _ = _export_scope(device, site)
    name = f"{PROJECT_NAME}-{part}-{time.strftime('%Y%m%d-%H%M')}.json"
    return _download(report.render_json(ids), name, "application/json")


@app.post("/scan")
def start_scan(request: Request, csrf: str = Form(""), device_id: str = Form(""), site: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    if device_id:
        ids = [device_id]
    elif site:
        all_sites = sites.load()
        wanted = "" if site == "-" else site
        ids = [d["id"] for d in inventory.load_devices() if sites.of(d, all_sites) == wanted]
    else:
        ids = [d["id"] for d in inventory.load_devices()]
    if ids:
        scan.start(ids)
    return RedirectResponse(f"/?site={site}" if site and re.match(r"^[a-z0-9-]{1,31}$", site) else "/", status_code=303)


@app.get("/api/job")
def job_status(request: Request):
    _session(request)
    return scan.current_job() or {}


# ---------------- devices ----------------

def _form_device(id: str, host: str, port: str, vendor: str, username: str, via_jump: str | None,
                 profile: str = "", site: str = "") -> dict:
    return {"id": id.strip().lower(), "host": host.strip(), "port": port.strip() or "22",
            "vendor": vendor, "username": username.strip(), "via_jump": via_jump == "on", "profile": profile,
            "site": site.strip()}


def _device_form(request: Request, session: dict, device: dict, editing: bool, status: int = 200, **ctx):
    all_sites = sites.load()
    auto = sites.site_for_ip(device.get("host") or "", all_sites)
    return _render(request, "device_form.html", session, status=status, device=device, vendors=_vendors(),
                   profiles=inventory.load_profiles(), editing=editing, sites=all_sites,
                   auto_site=next((s["name"] for s in all_sites if s["id"] == auto), ""), **ctx)


@app.get("/devices/new", response_class=HTMLResponse)
def new_device(request: Request, host: str = "", id: str = "", vendor: str = ""):
    session = _session(request)
    # prefilled from the discovery page
    profiles = inventory.load_profiles()
    device = {"port": 22, "via_jump": bool(inventory.load_settings().get("jump", {}).get("host")),
              "host": host[:253], "id": id[:40], "vendor": vendor,
              "profile": profiles[0]["id"] if profiles else ""}
    return _device_form(request, session, device, editing=False)


@app.post("/devices/new")
def create_device(request: Request, csrf: str = Form(""), id: str = Form(""), host: str = Form(""),
                  port: str = Form("22"), vendor: str = Form(""), username: str = Form(""),
                  password: str = Form(""), via_jump: str | None = Form(None), profile: str = Form(""),
                  site: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    data = _form_device(id, host, port, vendor, username, via_jump, profile, site)
    errors = inventory.validate_device(data, _vendors()) if data["port"].isdigit() else ["SSH port: 1-65535."]
    if inventory.get_device(data["id"]):
        errors.append("A switch with this name already exists.")
    if not profile and not password:
        errors.append("Password: required for a new switch (or choose a credential profile).")
    if errors:
        return _device_form(request, session, data, editing=False, status=400, errors=errors)
    inventory.save_device(data, password)
    return RedirectResponse("/", status_code=303)


@app.get("/devices/{device_id}/edit", response_class=HTMLResponse)
def edit_device(request: Request, device_id: str):
    session = _session(request)
    device = inventory.get_device(device_id)
    if not device:
        return RedirectResponse("/", status_code=303)
    return _device_form(request, session, device, editing=True)


@app.post("/devices/{device_id}/edit")
def update_device(request: Request, device_id: str, csrf: str = Form(""), host: str = Form(""),
                  port: str = Form("22"), vendor: str = Form(""), username: str = Form(""),
                  password: str = Form(""), via_jump: str | None = Form(None), profile: str = Form(""),
                  site: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    old = inventory.get_device(device_id)
    if not old:
        return RedirectResponse("/", status_code=303)
    data = _form_device(device_id, host, port, vendor, username, via_jump, profile, site)
    errors = inventory.validate_device(data, _vendors()) if data["port"].isdigit() else ["SSH port: 1-65535."]
    if not profile and not password and not old.get("secret"):
        errors.append("Password: required when not using a credential profile.")
    if errors:
        return _device_form(request, session, data, editing=True, status=400, errors=errors)
    inventory.save_device(data, password or None, original_id=device_id)
    return RedirectResponse("/", status_code=303)


@app.post("/devices/{device_id}/delete")
def remove_device(request: Request, device_id: str, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    inventory.delete_device(device_id)
    return RedirectResponse("/", status_code=303)


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_report(request: Request, device_id: str):
    session = _session(request)
    device = inventory.get_device(device_id)
    if not device:
        return RedirectResponse("/", status_code=303)
    result = inventory.load_result(device_id)
    levels = load_spec()["levels"]
    groups = {}
    for finding in (result or {}).get("findings", []):
        groups.setdefault(finding["level"], []).append(finding)
    scans = history.load_scans(device_id, 60)
    last_change = history.changes(scans[-2], scans[-1]) if len(scans) > 1 else None
    site = sites.get(sites.of(device))
    return _render(request, "device.html", session, device=device, result=result, groups=groups, levels=levels,
                   site=site,
                   host_key=collector.known_fingerprint(device["host"], device["port"]),
                   scans=scans, last_change=last_change, versions=history.versions(device_id)[:15],
                   backup=history.backup_status(device_id), ciso_enabled=notify.ciso_settings().get("enabled"))


@app.get("/devices/{device_id}/backups/{name}", response_class=HTMLResponse)
def backup_diff(request: Request, device_id: str, name: str):
    session = _session(request)
    device = inventory.get_device(device_id)
    if not device or not BACKUP_FILE.match(name):
        return RedirectResponse("/", status_code=303)
    try:
        lines = history.config_diff(device_id, name)
    except FileNotFoundError:
        return RedirectResponse(f"/devices/{device_id}", status_code=303)
    return _render(request, "backup_diff.html", session, device=device, version_file=name, lines=lines)


@app.post("/devices/{device_id}/forget-key")
def forget_key(request: Request, device_id: str, csrf: str = Form("")):
    """After a legitimate re-key or replacement: the next connection records the new key."""
    session = _session(request)
    _check_csrf(session, csrf)
    device = inventory.get_device(device_id)
    if device:
        collector.forget_host_key(device["host"], device["port"])
    return RedirectResponse(f"/devices/{device_id}#hostkey", status_code=303)


@app.post("/devices/{device_id}/attest")
def attest_backup(request: Request, device_id: str, csrf: str = Form(""), reference: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    if inventory.get_device(device_id) and reference.strip():
        history.attest(device_id, reference)
        _reaudit(device_id)
    return RedirectResponse(f"/devices/{device_id}#backups", status_code=303)


@app.post("/devices/{device_id}/attest/revoke")
def revoke_backup(request: Request, device_id: str, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    if inventory.get_device(device_id):
        history.revoke_attestation(device_id)
        _reaudit(device_id)
    return RedirectResponse(f"/devices/{device_id}#backups", status_code=303)


def _reaudit(device_id: str) -> None:
    """Re-evaluate the last collection (no new connection) after the backup evidence changed."""
    device = inventory.get_device(device_id)
    cfg_path, _ = collector.config_paths(device)
    if cfg_path.exists():
        scan.audit_device(device, "manual", archive=False)


# ---------------- settings ----------------

def _public(cfg: dict) -> dict:
    """Integration settings for the browser: the stored secret is replaced by a flag."""
    return {**{k: v for k, v in cfg.items() if k != "secret"}, "has_secret": bool(cfg.get("secret"))}


def _settings_page(request: Request, session: dict, status: int = 200, **ctx):
    settings = inventory.load_settings()
    ctx.setdefault("jump", settings.get("jump", {}))
    devices = inventory.load_devices()
    profiles = [{**{k: v for k, v in p.items() if k != "secret"},
                 "used": sum(1 for d in devices if d.get("profile") == p["id"])}
                for p in inventory.load_profiles()]
    all_sites = sites.load()
    site_list = [{**s, "used": sum(1 for d in devices if sites.of(d, all_sites) == s["id"])} for s in all_sites]
    return _render(request, "settings.html", session, status=status, profiles=profiles, sites=site_list,
                   unsited=sum(1 for d in devices if not sites.of(d, all_sites)),
                   organization=settings.get("organization", ""), level3=bool(settings.get("level3")),
                   schedule=settings.get("schedule", {"time": "02:30", "days": list(range(7))}),
                   smtp=_public(settings.get("smtp", {})), ciso=_public(settings.get("ciso", {})),
                   siem=settings.get("siem", {}), siem_default_file=str(inventory.PRIVATE / "lyss-events.jsonl"),
                   changes=_public(settings.get("change_watch", {})),
                   remediation=remediate.settings(), suggested=remediate.suggest_defaults(),
                   weekdays=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], **ctx)


@app.post("/settings/sites")
def save_site(request: Request, csrf: str = Form(""), name: str = Form(""), ranges: str = Form(""),
              site_id: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    _, errors = sites.save(name, ranges, site_id)
    if errors:
        return _settings_page(request, session, status=400, errors=errors)
    return _settings_page(request, session, saved=f"Site {name.strip()} saved.")


@app.post("/settings/sites/{site_id}/delete")
def delete_site(request: Request, site_id: str, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    sites.delete(site_id)
    return _settings_page(request, session, saved="Site deleted. Its switches are assigned automatically again.")


@app.post("/settings/schedule")
def save_schedule(request: Request, csrf: str = Form(""), enabled: str | None = Form(None),
                  at: str = Form("02:30"), days: list[int] = Form(default=[])):
    session = _session(request)
    _check_csrf(session, csrf)
    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", at):
        return _settings_page(request, session, status=400, errors=["Schedule: time must be HH:MM (24 h)."])
    days = sorted({d for d in days if 0 <= d <= 6})
    if enabled == "on" and not days:
        return _settings_page(request, session, status=400, errors=["Schedule: choose at least one day."])
    settings = inventory.load_settings()
    old = settings.get("schedule", {})
    settings["schedule"] = {"enabled": enabled == "on", "time": at, "days": days, "last_run": old.get("last_run")}
    inventory.save_settings(settings)
    state = f"on, {at}" if enabled == "on" else "off"
    return _settings_page(request, session, saved=f"Scheduled scans {state}. They run while LYSS is open.")


def _save_integration(key: str, values: dict, secret: str) -> None:
    settings = inventory.load_settings()
    old = settings.get(key, {})
    values["secret"] = vault.protect(secret) if secret else old.get("secret", "")
    settings[key] = values
    inventory.save_settings(settings)


@app.post("/settings/smtp")
def save_smtp(request: Request, csrf: str = Form(""), enabled: str | None = Form(None), host: str = Form(""),
              port: str = Form("587"), security: str = Form("starttls"), username: str = Form(""),
              password: str = Form(""), sender: str = Form(""), recipients: str = Form(""),
              mode: str = Form("regressions")):
    session = _session(request)
    _check_csrf(session, csrf)
    rcpt = [r for r in re.split(r"[\s,;]+", recipients) if r]
    errors = []
    if enabled == "on" and (not inventory.HOST_PATTERN.match(host.strip()) or not port.isdigit()):
        errors.append("E-mail: SMTP server and port are required.")
    if enabled == "on" and (not EMAIL.match(sender.strip()) or not rcpt or not all(EMAIL.match(r) for r in rcpt)):
        errors.append("E-mail: valid sender and recipient addresses are required.")
    if security not in ("starttls", "ssl", "none") or mode not in ("regressions", "always"):
        errors.append("E-mail: invalid option.")
    if errors:
        return _settings_page(request, session, status=400, errors=errors)
    _save_integration("smtp", {"enabled": enabled == "on", "host": host.strip(), "port": int(port or 587),
                               "security": security, "username": username.strip(), "sender": sender.strip(),
                               "recipients": rcpt, "mode": mode}, password)
    return _settings_page(request, session, saved="E-mail alerts saved.")


@app.post("/settings/smtp/test")
def test_smtp(request: Request, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    cfg = inventory.load_settings().get("smtp", {})
    if not cfg.get("host") or not cfg.get("recipients"):
        return _settings_page(request, session, status=400, errors=["E-mail: save the SMTP settings first."])
    try:
        notify.send_mail("Test e-mail", f"This is a test e-mail from {PROJECT_LONG_NAME}.", cfg)
    except Exception as exc:
        return _settings_page(request, session, status=502, errors=[f"E-mail test failed: {type(exc).__name__}: {exc}"[:300]])
    return _settings_page(request, session, saved=f"Test e-mail sent to {', '.join(cfg['recipients'])}.")


@app.post("/settings/ciso")
def save_ciso(request: Request, csrf: str = Form(""), enabled: str | None = Form(None), url: str = Form(""),
              token: str = Form(""), evidence_id: str = Form(""), verify_tls: str | None = Form(None),
              auto_push: str | None = Form(None)):
    session = _session(request)
    _check_csrf(session, csrf)
    errors = []
    if enabled == "on" and not re.match(r"^https?://[A-Za-z0-9.-]+(:\d+)?(/[\w./-]*)?$", url.strip()):
        errors.append("CISO Assistant: URL must look like https://host[:port].")
    if enabled == "on" and not re.match(r"^[A-Za-z0-9-]{1,64}$", evidence_id.strip()):
        errors.append("CISO Assistant: evidence id is required (copy it from the evidence URL).")
    if errors:
        return _settings_page(request, session, status=400, errors=errors)
    _save_integration("ciso", {"enabled": enabled == "on", "url": url.strip().rstrip("/"),
                               "evidence_id": evidence_id.strip(), "verify_tls": verify_tls == "on",
                               "auto_push": auto_push == "on"}, token)
    return _settings_page(request, session, saved="CISO Assistant settings saved.")


@app.post("/settings/ciso/test")
def test_ciso(request: Request, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    cfg = inventory.load_settings().get("ciso", {})
    if not cfg.get("url") or not cfg.get("secret"):
        return _settings_page(request, session, status=400, errors=["CISO Assistant: save URL and token first."])
    try:
        name = notify.ciso_test(cfg)
    except Exception as exc:
        return _settings_page(request, session, status=502, errors=[f"CISO Assistant test failed: {type(exc).__name__}: {exc}"[:300]])
    return _settings_page(request, session, saved=f"Connected: evidence \"{name}\" found.")


@app.post("/settings/siem")
def save_siem(request: Request, csrf: str = Form(""), enabled: str | None = Form(None), host: str = Form(""),
              port: str = Form("514"), protocol: str = Form("udp"), file: str = Form(""),
              findings: str = Form("all")):
    session = _session(request)
    _check_csrf(session, csrf)
    host, file = host.strip(), file.strip()
    errors = []
    if host and not inventory.HOST_PATTERN.match(host):
        errors.append("SIEM: invalid syslog server address.")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        errors.append("SIEM: port must be a number between 1 and 65535.")
    if protocol not in ("udp", "tcp") or findings not in ("all", "changes"):
        errors.append("SIEM: invalid option.")
    if file and not (Path(file).is_absolute() and Path(file).suffix.lower() in (".jsonl", ".json", ".log")):
        errors.append("SIEM: the events file must be an absolute path ending in .jsonl, .json or .log.")
    if enabled == "on" and not (host or file):
        errors.append("SIEM: give a syslog server, an events file, or both.")
    if errors:
        return _settings_page(request, session, status=400, errors=errors)
    settings = inventory.load_settings()
    settings["siem"] = {"enabled": enabled == "on", "host": host, "port": int(port), "protocol": protocol,
                        "file": file, "findings": findings}
    inventory.save_settings(settings)
    return _settings_page(request, session, saved="SIEM events saved.")


@app.post("/settings/siem/test")
def test_siem(request: Request, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    cfg = inventory.load_settings().get("siem", {})
    if not (cfg.get("host") or cfg.get("file")):
        return _settings_page(request, session, status=400, errors=["SIEM: save a syslog server or an events file first."])
    try:
        events.send([events.test_event()], cfg)
    except Exception as exc:
        return _settings_page(request, session, status=502, errors=[f"SIEM test failed: {type(exc).__name__}: {exc}"[:300]])
    where = " and ".join(x for x in (f"{cfg['host']}:{cfg['port']}/{cfg.get('protocol', 'udp')}" if cfg.get("host") else "",
                                     cfg.get("file", "")) if x)
    return _settings_page(request, session, saved=f"Test event sent to {where} (lyss.event = test).")


@app.post("/settings/changes")
def save_changes(request: Request, csrf: str = Form(""), enabled: str | None = Form(None), url: str = Form(""),
                 username: str = Form(""), password: str = Form(""), interval: str = Form("5"),
                 verify_tls: str | None = Form(None)):
    session = _session(request)
    _check_csrf(session, csrf)
    errors = []
    if enabled == "on" and not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?/?$", url.strip()):
        errors.append("Rescan on change: the Wazuh dashboard URL must look like https://host[:port].")
    if enabled == "on" and not re.match(r"^[\w.@-]{1,64}$", username.strip()):
        errors.append("Rescan on change: a read-only Wazuh account is required.")
    if not interval.isdigit() or not 1 <= int(interval) <= 60:
        errors.append("Rescan on change: the interval must be 1 to 60 minutes.")
    if errors:
        return _settings_page(request, session, status=400, errors=errors)
    old = inventory.load_settings().get("change_watch", {})
    _save_integration("change_watch", {"enabled": enabled == "on", "url": url.strip().rstrip("/"),
                                       "username": username.strip(), "interval_minutes": int(interval),
                                       "verify_tls": verify_tls == "on",
                                       "last_checked": old.get("last_checked")}, password)
    return _settings_page(request, session, saved="Rescan on change saved.")


@app.post("/settings/changes/test")
def test_changes(request: Request, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    cfg = inventory.load_settings().get("change_watch", {})
    if not cfg.get("url") or not cfg.get("secret"):
        return _settings_page(request, session, status=400, errors=["Rescan on change: save the URL and account first."])
    try:
        message = changes.test_connection(cfg)
    except Exception as exc:
        return _settings_page(request, session, status=502, errors=[f"Rescan on change test failed: {type(exc).__name__}: {exc}"[:300]])
    return _settings_page(request, session, saved=f"Rescan on change: {message}.")


@app.post("/export/ciso")
def push_ciso(request: Request, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    cfg = inventory.load_settings().get("ciso", {})
    if not cfg.get("enabled"):
        return _settings_page(request, session, status=400, errors=["CISO Assistant is not enabled."])
    try:
        rev = notify.ciso_push(report.render_html(), f"{PROJECT_NAME} report pushed manually.", cfg)
    except Exception as exc:
        return _settings_page(request, session, status=502, errors=[f"CISO Assistant push failed: {type(exc).__name__}: {exc}"[:300]])
    return _settings_page(request, session, saved=f"Report sent to CISO Assistant (revision {rev}).")


@app.post("/settings/profiles")
def add_profile(request: Request, csrf: str = Form(""), name: str = Form(""), username: str = Form(""),
                password: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    if not name.strip() or not username.strip() or not password:
        return _settings_page(request, session, status=400,
                              errors=["Credential profile: name, username and password are required."])
    inventory.save_profile(name, username, password)
    return _settings_page(request, session, saved=f"Credential profile \"{name.strip()[:60]}\" saved.")


@app.post("/settings/profiles/{profile_id}/delete")
def remove_profile(request: Request, profile_id: str, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    if not inventory.delete_profile(profile_id):
        return _settings_page(request, session, status=400,
                              errors=["This profile is still used by switches: change them first."])
    return _settings_page(request, session, saved="Credential profile deleted.")


# ---------------- remediation ----------------

@app.post("/settings/remediation")
def save_remediation(request: Request, csrf: str = Form(""), enabled: str | None = Form(None),
                     syslog: str = Form(""), ntp: str = Form(""), banner: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    ntp_list = [n for n in re.split(r"[\s,;]+", ntp) if n][:4]
    errors = remediate.validate_params(syslog.strip(), ntp_list, banner.strip())
    if errors:
        return _settings_page(request, session, status=400, errors=errors)
    settings = inventory.load_settings()
    settings["remediation"] = {"enabled": enabled == "on", "syslog": syslog.strip(), "ntp": ntp_list,
                               "banner": banner.strip()}
    inventory.save_settings(settings)
    return _settings_page(request, session, saved="Remediation " + ("enabled." if enabled == "on" else "disabled."))


@app.get("/remediation", response_class=HTMLResponse)
def remediation_page(request: Request, device: str = ""):
    session = _session(request)
    rows = []
    for d in inventory.load_devices():
        if device and d["id"] != device:
            continue
        fixes = [remediate.fix_dict(f) for f in remediate.plan(d)]
        if fixes:
            rows.append({"device": d, "fixes": fixes, "result": inventory.load_result(d["id"])})
    return _render(request, "remediation.html", session, rows=rows, cfg=remediate.settings(),
                   job=remediate.current_job(), changes=remediate.load_changes(30), only=device)


@app.post("/remediation/apply")
async def remediation_apply(request: Request):
    session = _session(request)
    form = await request.form()
    _check_csrf(session, form.get("csrf", ""))
    selection: dict[str, list[str]] = {}
    for value in form.getlist("fix"):
        device_id, _, control_id = str(value).partition("|")
        if inventory.get_device(device_id) and re.match(r"^LYSS-[A-Z]+-\d{3}$", control_id):
            selection.setdefault(device_id, []).append(control_id)
    if not selection:
        return RedirectResponse("/remediation", status_code=303)
    try:
        started = remediate.start(selection)
    except PermissionError:
        return RedirectResponse("/settings", status_code=303)
    if started is None:
        return _render(request, "remediation.html", session, status=409, rows=[], cfg=remediate.settings(),
                       job=remediate.current_job(), changes=remediate.load_changes(30), only="",
                       errors=["A scan or a remediation is already running: wait for it to finish."])
    return RedirectResponse("/remediation", status_code=303)


@app.get("/api/remediation")
def remediation_status(request: Request):
    _session(request)
    return remediate.current_job() or {}


# ---------------- firmware ----------------

def _links_of(device_id: str) -> list[str]:
    """Links of a switch from the topology: what loses connectivity while it reboots."""
    topo = topology.build()
    labels = {n["id"]: n["label"] for n in topo["nodes"]}
    out = []
    for e in topo["edges"]:
        if device_id in (e["a"], e["b"]):
            peer = e["b"] if e["a"] == device_id else e["a"]
            for p in e["ports"]:
                mine, theirs = (p["a_port"], p["b_port"]) if e["a"] == device_id else (p["b_port"], p["a_port"])
                out.append(f"{mine} → {labels.get(peer, peer)} {theirs}")
    return out


def _firmware_page(request: Request, session: dict, status: int = 200, **ctx):
    devices = []
    for d in inventory.load_devices():
        if firmware.eligible(d):
            devices.append({"device": d, "result": inventory.load_result(d["id"]),
                            "state": firmware.device_state(d["id"]), "links": _links_of(d["id"])})
    return _render(request, "firmware.html", session, status=status, images=firmware.list_images(),
                   devices=devices, job=firmware.current_job(), **ctx)


@app.get("/firmware", response_class=HTMLResponse)
def firmware_page(request: Request):
    return _firmware_page(request, _session(request))


@app.post("/firmware/upload")
async def firmware_upload(request: Request):
    session = _session(request)
    form = await request.form()
    _check_csrf(session, str(form.get("csrf", "")))
    upload = form.get("image")
    if upload is None or not hasattr(upload, "read"):
        return _firmware_page(request, session, status=400, errors=["Choose the image file."])
    data = await upload.read(firmware.MAX_IMAGE + 1)
    try:
        meta = firmware.save_image(Path(upload.filename or "").name, data, str(form.get("hash", "")))
    except ValueError as exc:
        return _firmware_page(request, session, status=400, errors=[str(exc)])
    return _firmware_page(request, session, saved=f"{meta['file']} stored: {meta['checked_against'].upper()} matches Cisco's.")


@app.post("/firmware/stage")
def firmware_stage(request: Request, csrf: str = Form(""), device_id: str = Form(""), image: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    try:
        started = firmware.start("stage", device_id, image)
    except ValueError as exc:
        return _firmware_page(request, session, status=400, errors=[str(exc)])
    if started is None:
        return _firmware_page(request, session, status=409, errors=["Another scan, remediation or upgrade is running."])
    return RedirectResponse("/firmware", status_code=303)


@app.post("/firmware/activate")
def firmware_activate(request: Request, csrf: str = Form(""), device_id: str = Form(""), confirm: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    if confirm.strip() != device_id:
        return _firmware_page(request, session, status=400,
                              errors=["Type the switch name exactly to confirm the reboot."])
    try:
        started = firmware.start("activate", device_id)
    except ValueError as exc:
        return _firmware_page(request, session, status=400, errors=[str(exc)])
    if started is None:
        return _firmware_page(request, session, status=409, errors=["Another scan, remediation or upgrade is running."])
    return RedirectResponse("/firmware", status_code=303)


@app.get("/api/firmware")
def firmware_status(request: Request):
    _session(request)
    return firmware.current_job() or {}


# ---------------- discovery ----------------

def _discovery_page(request: Request, session: dict, status: int = 200, **ctx):
    settings = inventory.load_settings()
    all_sites = sites.load()
    names = {s["id"]: s["name"] for s in all_sites}
    candidates = [{**c, "suggest": discovery.suggest_id(c), "site": names.get(sites.site_for_ip(c["ip"], all_sites), "")}
                  for c in discovery.pending()]
    site_scans = [{**s, "scannable": sites.scan_ranges(s)[0], "too_big": sites.scan_ranges(s)[1]} for s in all_sites]
    return _render(request, "discovery.html", session, status=status, candidates=candidates, sites=site_scans,
                   state=discovery.load(), scan=discovery.scan_status(),
                   ranges=ctx.pop("ranges", settings.get("discovery_ranges", "")),
                   jump_ready=bool(settings.get("jump", {}).get("host")),
                   jump_source=settings.get("jump", {}).get("source", "") if settings.get("jump", {}).get("host") else "",
                   profiles=inventory.load_profiles(), vendors=_vendors(), **ctx)


@app.get("/discovery", response_class=HTMLResponse)
def discovery_page(request: Request):
    return _discovery_page(request, _session(request))


@app.get("/api/discovery")
def discovery_status(request: Request):
    _session(request)
    return discovery.scan_status()


@app.post("/discovery/neighbors")
def discover_neighbors(request: Request, csrf: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    found = discovery.from_neighbors()
    return _discovery_page(request, session, saved=f"Neighbour discovery done: {found} new switch(es).")


@app.post("/discovery/scan")
def discover_ranges(request: Request, csrf: str = Form(""), ranges: str = Form(""), via_jump: str | None = Form(None)):
    session = _session(request)
    _check_csrf(session, csrf)
    nets, errors = discovery.parse_ranges(ranges)
    if not nets and not errors:
        errors = ["Enter at least one range, e.g. 192.0.2.0/24 or 198.51.100.1-50."]
    if errors:
        return _discovery_page(request, session, status=400, errors=errors, ranges=ranges)
    settings = inventory.load_settings()
    settings["discovery_ranges"] = " ".join(nets)
    inventory.save_settings(settings)
    if not discovery.start_scan(nets, via_jump == "on"):
        return _discovery_page(request, session, status=409, errors=["A range scan is already running."])
    return RedirectResponse("/discovery", status_code=303)


@app.post("/discovery/site")
def discover_site(request: Request, csrf: str = Form(""), site_id: str = Form(""), via_jump: str | None = Form(None)):
    """Scan one site's ranges at a gentle rate (remote sites are often behind VPN tunnels)."""
    session = _session(request)
    _check_csrf(session, csrf)
    site = sites.get(site_id)
    if not site:
        return _discovery_page(request, session, status=400, errors=["Site not found."])
    nets, too_big = sites.scan_ranges(site)
    if not nets:
        return _discovery_page(request, session, status=400,
                               errors=[f"{site['name']}: no range of /20 or smaller to scan ({', '.join(too_big)})."])
    if not discovery.start_scan(nets, via_jump == "on", gentle=True, label=site["name"]):
        return _discovery_page(request, session, status=409, errors=["A range scan is already running."])
    return RedirectResponse("/discovery", status_code=303)


@app.post("/discovery/ignore")
def discover_ignore(request: Request, csrf: str = Form(""), ip: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    discovery.ignore(ip.strip())
    return RedirectResponse("/discovery", status_code=303)


@app.post("/discovery/add")
def discover_add(request: Request, csrf: str = Form(""), ips: list[str] = Form(default=[]),
                 profile: str = Form(""), scan_now: str | None = Form(None)):
    """Add the selected discovered switches with a credential profile, then optionally scan them."""
    session = _session(request)
    _check_csrf(session, csrf)
    if not inventory.get_profile(profile):
        return _discovery_page(request, session, status=400,
                               errors=["Choose a credential profile (Settings → Credential profiles)."])
    candidates = {c["ip"]: c for c in discovery.pending()}
    via_jump = bool(inventory.load_settings().get("jump", {}).get("host"))
    added, skipped = [], []
    for ip in ips:
        cand = candidates.get(ip)
        if not cand or not cand.get("adapter"):
            skipped.append(ip)  # unknown platform: add it manually and choose the platform
            continue
        data = {"id": discovery.suggest_id(cand), "host": ip, "port": "22", "vendor": cand["adapter"],
                "username": "", "via_jump": via_jump, "profile": profile}
        if inventory.validate_device(data, _vendors()):
            skipped.append(ip)
            continue
        inventory.save_device(data, None)
        added.append(data["id"])
    if added and scan_now == "on":
        scan.start(added)
        return RedirectResponse("/", status_code=303)
    msg = f"Added {len(added)} switch(es)." + (f" Skipped (add manually): {', '.join(skipped)}." if skipped else "")
    return _discovery_page(request, session, saved=msg)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return _settings_page(request, _session(request))


@app.post("/settings/organization")
def save_organization(request: Request, csrf: str = Form(""), organization: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    settings = inventory.load_settings()
    settings["organization"] = organization.strip()[:120]
    inventory.save_settings(settings)
    return _settings_page(request, session, saved="Organization saved.")


@app.post("/settings/assessment")
def save_assessment(request: Request, csrf: str = Form(""), level3: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    settings = inventory.load_settings()
    settings["level3"] = level3 == "1"
    inventory.save_settings(settings)
    redone = 0
    for device in inventory.load_devices():
        if collector.config_paths(device)[0].exists():
            _reaudit(device["id"])
            redone += 1
    return _settings_page(request, session, saved=f"Assessment saved: Level 3 {'on' if settings['level3'] else 'off'}; "
                                                   f"{redone} switch(es) re-assessed.")


@app.post("/settings/jump")
def save_jump(request: Request, csrf: str = Form(""), host: str = Form(""), port: str = Form("22"),
              user: str = Form(""), key_file: str = Form(""), source: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    errors = []
    if host and not inventory.HOST_PATTERN.match(host.strip()):
        errors.append("Jump host: not a valid address.")
    if host and not Path(key_file.strip()).is_file():
        errors.append("Private key file: not found on this PC.")
    if source.strip():
        try:
            ipaddress.ip_address(source.strip())
        except ValueError:
            errors.append("Source address: must be an IP address of the jump host.")
    jump = {"host": host.strip(), "port": int(port) if port.isdigit() else 22,
            "user": user.strip(), "key_file": key_file.strip(), "source": source.strip()}
    if errors:
        return _settings_page(request, session, status=400, jump=jump, errors=errors)
    settings = inventory.load_settings()
    settings["jump"] = jump if host else {}
    inventory.save_settings(settings)
    return _settings_page(request, session, saved="Jump host saved.")


@app.post("/settings/password")
def change_password(request: Request, csrf: str = Form(""), current: str = Form(""),
                    password: str = Form(""), confirm: str = Form("")):
    session = _session(request)
    _check_csrf(session, csrf)
    settings = inventory.load_settings()
    if not inventory.check_password(current, settings.get("admin")):
        return _settings_page(request, session, status=400, errors=["Current password is wrong."])
    if len(password) < 12 or password != confirm:
        return _settings_page(request, session, status=400,
                              errors=["New password: at least 12 characters, typed twice identically."])
    settings["admin"] = inventory.hash_password(password)
    inventory.save_settings(settings)
    # sign out every other session
    current_token = request.cookies.get(SESSION_COOKIE, "")
    for token in [t for t in _sessions if t != current_token]:
        _sessions.pop(token, None)
    return _settings_page(request, session, saved="Password changed.")
