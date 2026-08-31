import asyncio
import base64
import difflib
import ipaddress
import os
import secrets
import time
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .crypto import encrypt
from .operator_session import create_session as create_operator_session, delete_session as delete_operator_session, get_session as get_operator_session, SESSION_TTL_SECONDS
from .db import Base, SessionLocal, engine, get_db
from .migrate import migrate_legacy_db
from .models import AuditLog, AvailabilitySample, InterfaceSample, Shortcut, Switch
from .network import (
    apply_motd,
    build_motd_banner,
    backup_path,
    close_terminal,
    close_terminals_for_operator,
    create_backup,
    get_facts,
    get_neighbors,
    get_ports,
    get_topology_neighbors,
    list_backups,
    open_terminal,
    run_command,
    search_mac_one,
    tcp_probe,
    terminal_command,
)
from .schemas import BannerRequest, CommandRequest, DiscoveryRequest, MacSearchRequest, OperatorSessionRequest, ShortcutCreate, SwitchCreate, SwitchUpdate
from .snmp import snmp_health, snmp_interfaces, snmp_metrics
from .port_detail import get_port_detail, validate_interface

BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "static"
ADMIN_USER = os.getenv("CSM_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("CSM_ADMIN_PASSWORD", "ChangeMeNow!")
STATUS_INTERVAL = max(60, int(os.getenv("CSM_STATUS_INTERVAL_SECONDS", "300")))
BACKUP_INTERVAL_HOURS = max(1, int(os.getenv("CSM_BACKUP_INTERVAL_HOURS", "24")))
AVAILABILITY_RETENTION_DAYS = max(7, int(os.getenv("CSM_AVAILABILITY_RETENTION_DAYS", "30")))
PORT_POLL_INTERVAL = max(300, int(os.getenv("CSM_PORT_POLL_INTERVAL_SECONDS", "900")))
PORT_HISTORY_RETENTION_DAYS = max(7, int(os.getenv("CSM_PORT_HISTORY_RETENTION_DAYS", "30")))
OPERATOR_COOKIE_NAME = "csm_operator_session"
OPERATOR_COOKIE_SECURE = os.getenv("CSM_SESSION_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}
AUTOMATIC_CLI_BACKUP_ENABLED = os.getenv("CSM_AUTOMATIC_CLI_BACKUP_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
BACKUP_CLI_CREDENTIALS = {
    "username": os.getenv("CSM_BACKUP_CLI_USER", "").strip(),
    "password": os.getenv("CSM_BACKUP_CLI_PASSWORD", ""),
    "secret": os.getenv("CSM_BACKUP_CLI_SECRET", ""),
}

Base.metadata.create_all(bind=engine)
migrate_legacy_db()

DEFAULT_SHORTCUTS = [
    ("Interfaces", "show interfaces status", "Resumo das portas"),
    ("IP Interfaces", "show ip interface brief", "Interfaces L3/SVI"),
    ("VLANs", "show vlan brief", "VLANs configuradas"),
    ("EtherChannel", "show etherchannel summary", "Port-channels"),
    ("STP", "show spanning-tree summary", "Spanning Tree"),
    ("CDP", "show cdp neighbors", "Vizinhos Cisco"),
    ("LLDP", "show lldp neighbors", "Vizinhos LLDP"),
    ("MAC Table", "show mac address-table", "Tabela MAC"),
    ("PoE", "show power inline", "Status PoE"),
    ("Uptime", "show version | include uptime", "Tempo ligado"),
    ("CPU", "show processes cpu sorted | exclude 0.00", "CPU via CLI"),
    ("Erros", "show interfaces counters errors", "Erros de interfaces"),
]


def seed_shortcuts():
    db = SessionLocal()
    try:
        if db.scalar(select(Shortcut.id).limit(1)) is None:
            for name, command, description in DEFAULT_SHORTCUTS:
                db.add(Shortcut(name=name, command=command, description=description))
            db.commit()
    finally:
        db.close()


seed_shortcuts()


def snmp_configured(sw):
    if (sw.snmp_version or "v2c").lower() == "v3":
        return bool(sw.snmp_v3_user_enc)
    return bool(sw.snmp_community_enc)


def snmp_label(sw):
    return "snmpv3" if (sw.snmp_version or "v2c").lower() == "v3" else "snmpv2c"


def sw_public(sw):
    return {
        "id": sw.id,
        "hostname": sw.hostname,
        "management_ip": sw.management_ip,
        "site": sw.site,
        "platform": sw.platform,
        "protocol": sw.protocol or "telnet",
        "port": sw.port or (23 if (sw.protocol or "telnet") == "telnet" else 22),
        "snmp_version": sw.snmp_version or "v2c",
        "snmp_port": sw.snmp_port or 161,
        "snmp_enabled": snmp_configured(sw),
        "snmp_v3_auth_protocol": sw.snmp_v3_auth_protocol or "SHA",
        "snmp_v3_priv_protocol": sw.snmp_v3_priv_protocol or "AES",
        "monitor_method": sw.monitor_method or "snmp",
        "model": sw.model,
        "serial": sw.serial,
        "ios_version": sw.ios_version,
        "notes": sw.notes,
        "is_online": sw.is_online,
        "last_seen": sw.last_seen,
        "last_status_source": sw.last_status_source,
        "created_at": sw.created_at,
        "updated_at": sw.updated_at,
    }


def audit(db, sw, action, command="", success=True, message="", portal_user="", operator_user=""):
    db.add(AuditLog(
        switch_id=sw.id if sw else None,
        hostname=sw.hostname if sw else "",
        action=action,
        portal_user=portal_user or "",
        operator_user=operator_user or "",
        command=command,
        success=success,
        message=str(message)[:8000],
    ))
    db.commit()


def operator_context(request: Request, required=True):
    token = request.cookies.get(OPERATOR_COOKIE_NAME)
    session = get_operator_session(token)
    if not session and required:
        raise HTTPException(428, "Sessao Cisco necessaria. Ative sua credencial adm- antes de usar Telnet/SSH.")
    return session


def audit_identity(request: Request, operator=None):
    return {
        "portal_user": getattr(request.state, "portal_user", ""),
        "operator_user": (operator or {}).get("username", ""),
    }


async def _probe_one(sw):
    started = time.perf_counter()
    snmp_error = ""
    if snmp_configured(sw):
        try:
            info = await snmp_health(sw)
            latency = round((time.perf_counter() - started) * 1000, 1)
            return True, snmp_label(sw), f"{snmp_label(sw).upper()} OK: {info.get('sys_name') or sw.hostname}", latency
        except Exception as exc:
            snmp_error = str(exc)
    online, message = await asyncio.to_thread(tcp_probe, sw)
    latency = round((time.perf_counter() - started) * 1000, 1)
    if online:
        return True, sw.protocol or "telnet", message, latency
    if snmp_error:
        message = f"SNMP: {snmp_error}; CLI: {message}"
    return False, "", message, latency


async def _refresh_all_status(db):
    switches = db.scalars(select(Switch)).all()
    sem = asyncio.Semaphore(24)

    async def limited(sw):
        async with sem:
            return sw.id, await _probe_one(sw)

    probed = await asyncio.gather(*(limited(sw) for sw in switches)) if switches else []
    results_by_id = dict(probed)
    now = datetime.now(timezone.utc)
    results = []
    for sw in switches:
        online, source, message, latency = results_by_id[sw.id]
        sw.is_online = online
        sw.last_status_source = source
        if online:
            sw.last_seen = now
        db.add(AvailabilitySample(switch_id=sw.id, online=online, source=source, latency_ms=latency))
        results.append({"id": sw.id, "hostname": sw.hostname, "online": online, "source": source, "message": message, "latency_ms": latency})
    cutoff = now - timedelta(days=AVAILABILITY_RETENTION_DAYS)
    db.execute(delete(AvailabilitySample).where(AvailabilitySample.created_at < cutoff))
    db.commit()
    return results


async def status_monitor_loop():
    await asyncio.sleep(8)
    while True:
        db = SessionLocal()
        try:
            await _refresh_all_status(db)
        except Exception:
            db.rollback()
        finally:
            db.close()
        await asyncio.sleep(STATUS_INTERVAL)


def _int_error(value):
    try:
        return max(0, int(str(value or "0")))
    except (TypeError, ValueError):
        return 0


async def _snapshot_ports_for_switch(db, sw):
    if not snmp_configured(sw):
        return {"stored": 0, "ports": 0, "source": "none"}
    ports = await snmp_interfaces(sw)
    recent_rows = db.scalars(
        select(InterfaceSample).where(InterfaceSample.switch_id == sw.id).order_by(desc(InterfaceSample.id)).limit(max(200, len(ports) * 4))
    ).all()
    latest = {}
    for row in recent_rows:
        latest.setdefault(row.port, row)
    now = datetime.now(timezone.utc)
    heartbeat_cutoff = now - timedelta(hours=1)
    stored = 0
    for port in ports:
        name = str(port.get("port") or "").strip()
        if not name:
            continue
        current = {
            "status": str(port.get("status") or "unknown"),
            "admin_status": str(port.get("admin_status") or "unknown"),
            "speed": str(port.get("speed") or ""),
            "description": str(port.get("name") or "")[:240],
            "in_errors": _int_error(port.get("in_errors")),
            "out_errors": _int_error(port.get("out_errors")),
        }
        old = latest.get(name)
        old_time = old.created_at if old else None
        if old_time and old_time.tzinfo is None:
            old_time = old_time.replace(tzinfo=timezone.utc)
        changed = not old or any(getattr(old, key) != value for key, value in current.items())
        heartbeat_due = not old_time or old_time < heartbeat_cutoff
        if changed or heartbeat_due:
            db.add(InterfaceSample(switch_id=sw.id, port=name, source=snmp_label(sw), **current))
            stored += 1
    db.commit()
    return {"stored": stored, "ports": len(ports), "source": snmp_label(sw)}


async def port_monitor_loop():
    await asyncio.sleep(30)
    while True:
        db = SessionLocal()
        try:
            switches = db.scalars(select(Switch).where(Switch.is_online == True).order_by(Switch.hostname)).all()
            for sw in switches:
                if not snmp_configured(sw):
                    continue
                try:
                    await _snapshot_ports_for_switch(db, sw)
                except Exception:
                    db.rollback()
            cutoff = datetime.now(timezone.utc) - timedelta(days=PORT_HISTORY_RETENTION_DAYS)
            db.execute(delete(InterfaceSample).where(InterfaceSample.created_at < cutoff))
            db.commit()
        finally:
            db.close()
        await asyncio.sleep(PORT_POLL_INTERVAL)


async def backup_scheduler_loop():
    await asyncio.sleep(BACKUP_INTERVAL_HOURS * 3600)
    while True:
        db = SessionLocal()
        try:
            switches = db.scalars(select(Switch).order_by(Switch.hostname)).all()
            for sw in switches:
                try:
                    await asyncio.to_thread(create_backup, sw, BACKUP_CLI_CREDENTIALS)
                    audit(db, sw, "backup.scheduled", command="show running-config", success=True, operator_user=f"service:{BACKUP_CLI_CREDENTIALS['username']}")
                except Exception as exc:
                    audit(db, sw, "backup.scheduled", command="show running-config", success=False, message=exc, operator_user=f"service:{BACKUP_CLI_CREDENTIALS['username']}")
        finally:
            db.close()
        await asyncio.sleep(BACKUP_INTERVAL_HOURS * 3600)


@asynccontextmanager
async def lifespan(app):
    tasks = [asyncio.create_task(status_monitor_loop()), asyncio.create_task(port_monitor_loop())]
    if AUTOMATIC_CLI_BACKUP_ENABLED and BACKUP_CLI_CREDENTIALS["username"] and BACKUP_CLI_CREDENTIALS["password"]:
        tasks.append(asyncio.create_task(backup_scheduler_loop()))
    yield
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(title="Cisco Switch Manager", version="0.3.2", lifespan=lifespan)


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    ok = False
    if auth.startswith("Basic "):
        try:
            userpass = base64.b64decode(auth.split(" ", 1)[1]).decode()
            user, password = userpass.split(":", 1)
            ok = secrets.compare_digest(user, ADMIN_USER) and secrets.compare_digest(password, ADMIN_PASSWORD)
        except Exception:
            pass
    if not ok:
        return JSONResponse({"detail": "Authentication required"}, status_code=401, headers={"WWW-Authenticate": "Basic realm=CSM"})
    request.state.portal_user = user
    return await call_next(request)


app.add_middleware(CORSMiddleware, allow_origins=[], allow_credentials=True, allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["*"])


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.3.2", "status_interval_seconds": STATUS_INTERVAL, "backup_interval_hours": BACKUP_INTERVAL_HOURS, "automatic_cli_backup_enabled": AUTOMATIC_CLI_BACKUP_ENABLED, "operator_session_minutes": SESSION_TTL_SECONDS // 60, "port_poll_interval_seconds": PORT_POLL_INTERVAL, "port_history_retention_days": PORT_HISTORY_RETENTION_DAYS}


@app.get("/api/operator-session")
def operator_session_status(request: Request):
    session = operator_context(request, required=False)
    if not session:
        return {"active": False, "session_minutes": SESSION_TTL_SECONDS // 60}
    return session["public"]


@app.post("/api/operator-session")
def operator_session_create(payload: OperatorSessionRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        token, public = create_operator_session(payload.username, payload.password, payload.secret)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    response.set_cookie(
        OPERATOR_COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, httponly=True,
        secure=OPERATOR_COOKIE_SECURE, samesite="strict", path="/",
    )
    audit(db, None, "operator.session.open", portal_user=getattr(request.state, "portal_user", ""), operator_user=public["username"])
    return public


@app.delete("/api/operator-session")
def operator_session_delete(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(OPERATOR_COOKIE_NAME)
    session = get_operator_session(token, touch=False)
    operator_user = (session or {}).get("username", "")
    if operator_user:
        close_terminals_for_operator(operator_user)
    delete_operator_session(token)
    response.delete_cookie(OPERATOR_COOKIE_NAME, path="/")
    audit(db, None, "operator.session.close", portal_user=getattr(request.state, "portal_user", ""), operator_user=operator_user)
    return {"ok": True}


@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db)):
    switches = db.scalars(select(Switch).order_by(Switch.site, Switch.hostname)).all()
    by_site = defaultdict(lambda: {"total": 0, "online": 0, "offline": 0})
    for sw in switches:
        by_site[sw.site]["total"] += 1
        by_site[sw.site]["online" if sw.is_online else "offline"] += 1
    return {
        "total": len(switches),
        "online": sum(1 for s in switches if s.is_online),
        "offline": sum(1 for s in switches if not s.is_online),
        "snmpv2": sum(1 for s in switches if (s.snmp_version or "v2c").lower() != "v3" and snmp_configured(s)),
        "snmpv3": sum(1 for s in switches if (s.snmp_version or "v2c").lower() == "v3" and snmp_configured(s)),
        "telnet": sum(1 for s in switches if (s.protocol or "telnet") == "telnet"),
        "ssh": sum(1 for s in switches if s.protocol == "ssh"),
        "sites": [{"site": site, **counts} for site, counts in sorted(by_site.items())],
        "switches": [sw_public(s) for s in switches],
    }


@app.get("/api/switches")
def list_switches(db: Session = Depends(get_db)):
    return [sw_public(s) for s in db.scalars(select(Switch).order_by(Switch.site, Switch.hostname)).all()]


def _validate_protocols(protocol, snmp_version):
    protocol = (protocol or "telnet").lower()
    snmp_version = (snmp_version or "v2c").lower()
    if protocol not in {"ssh", "telnet"}:
        raise HTTPException(400, "Protocol must be ssh or telnet")
    if snmp_version not in {"v2c", "v2", "v3"}:
        raise HTTPException(400, "SNMP version must be v2c or v3")
    return protocol, "v3" if snmp_version == "v3" else "v2c"


def _apply_secrets(sw, data, creating=False):
    plain_to_enc = {
        "snmp_community": "snmp_community_enc", "snmp_v3_user": "snmp_v3_user_enc",
        "snmp_v3_auth_key": "snmp_v3_auth_key_enc", "snmp_v3_priv_key": "snmp_v3_priv_key_enc",
    }
    for plain, enc in plain_to_enc.items():
        if plain in data and (creating or data[plain] not in {None, ""}):
            setattr(sw, enc, encrypt(data.get(plain) or ""))


@app.post("/api/switches")
def create_switch(payload: SwitchCreate, db: Session = Depends(get_db)):
    protocol, snmp_version = _validate_protocols(payload.protocol, payload.snmp_version)
    sw = Switch(
        hostname=payload.hostname.strip(), management_ip=payload.management_ip.strip(), site=payload.site.strip(),
        platform=payload.platform.strip() or "cisco_ios", protocol=protocol,
        port=payload.port or (23 if protocol == "telnet" else 22), snmp_version=snmp_version,
        snmp_port=payload.snmp_port or 161, monitor_method=payload.monitor_method or "snmp",
        snmp_v3_auth_protocol=(payload.snmp_v3_auth_protocol or "SHA").upper(),
        snmp_v3_priv_protocol=(payload.snmp_v3_priv_protocol or "AES").upper(), notes=payload.notes,
    )
    _apply_secrets(sw, payload.model_dump(), creating=True)
    db.add(sw)
    try:
        db.commit(); db.refresh(sw)
    except IntegrityError:
        db.rollback(); raise HTTPException(409, "Hostname or management IP already exists")
    audit(db, sw, "inventory.create")
    return sw_public(sw)


@app.put("/api/switches/{switch_id}")
def update_switch(switch_id: int, payload: SwitchUpdate, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    data = payload.model_dump(exclude_unset=True)
    if "protocol" in data or "snmp_version" in data:
        protocol, snmp_version = _validate_protocols(data.get("protocol") or sw.protocol, data.get("snmp_version") or sw.snmp_version)
        sw.protocol, sw.snmp_version = protocol, snmp_version
    for field in ["hostname", "management_ip", "site", "platform", "notes", "monitor_method", "snmp_v3_auth_protocol", "snmp_v3_priv_protocol"]:
        if field in data and data[field] is not None:
            setattr(sw, field, data[field])
    if data.get("port"):
        sw.port = data["port"]
    if data.get("snmp_port"):
        sw.snmp_port = data["snmp_port"]
    _apply_secrets(sw, data)
    try:
        db.commit(); db.refresh(sw)
    except IntegrityError:
        db.rollback(); raise HTTPException(409, "Hostname or management IP already exists")
    audit(db, sw, "inventory.update")
    return sw_public(sw)


@app.delete("/api/switches/{switch_id}")
def delete_switch(switch_id: int, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    hostname = sw.hostname
    db.execute(delete(AvailabilitySample).where(AvailabilitySample.switch_id == switch_id))
    db.execute(delete(InterfaceSample).where(InterfaceSample.switch_id == switch_id))
    db.execute(delete(AuditLog).where(AuditLog.switch_id == switch_id))
    db.delete(sw); db.commit()
    audit(db, None, "inventory.delete", message=hostname)
    return {"ok": True}


@app.post("/api/status/refresh")
async def refresh_status(db: Session = Depends(get_db)):
    return await _refresh_all_status(db)


@app.post("/api/switches/{switch_id}/test")
async def test_switch(switch_id: int, request: Request, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    operator = operator_context(request, required=False)
    result = {"cli": None, "snmp": None, "errors": []}
    if operator:
        try:
            facts = await asyncio.to_thread(get_facts, sw, operator)
            sw.model = facts.get("model") or sw.model; sw.serial = facts.get("serial") or sw.serial; sw.ios_version = facts.get("version") or sw.ios_version
            result["cli"] = {k: v for k, v in facts.items() if k != "raw"}
        except Exception as exc:
            result["errors"].append(f"CLI: {exc}")
    elif not snmp_configured(sw):
        operator_context(request, required=True)
    if snmp_configured(sw):
        try:
            result["snmp"] = await snmp_health(sw)
        except Exception as exc:
            result["errors"].append(f"SNMP: {exc}")
    identity = audit_identity(request, operator)
    if result["cli"] or result["snmp"]:
        sw.is_online = True; sw.last_seen = datetime.now(timezone.utc); sw.last_status_source = snmp_label(sw) if result["snmp"] else (sw.protocol or "telnet")
        db.add(AvailabilitySample(switch_id=sw.id, online=True, source=sw.last_status_source)); db.commit()
        audit(db, sw, "connection.test", command=f"{snmp_label(sw)} + {sw.protocol}", **identity)
        return {"ok": True, **result, "facts": result["cli"] or {}, "operator_session": bool(operator)}
    sw.is_online = False; db.add(AvailabilitySample(switch_id=sw.id, online=False, source="")); db.commit()
    audit(db, sw, "connection.test", success=False, message="; ".join(result["errors"]), **identity)
    raise HTTPException(502, "; ".join(result["errors"]) or "Connection failed")


@app.get("/api/switches/{switch_id}/metrics")
async def metrics(switch_id: int, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    if not snmp_configured(sw):
        raise HTTPException(400, "SNMP is not configured for this switch")
    try:
        result = await snmp_metrics(sw)
        audit(db, sw, "snmp.metrics", command=f"{snmp_label(sw)} system/Cisco/ENTITY/PoE MIBs")
        return {"switch": sw_public(sw), "source": snmp_label(sw), **result}
    except Exception as exc:
        audit(db, sw, "snmp.metrics", command=snmp_label(sw), success=False, message=exc)
        raise HTTPException(502, str(exc))


@app.get("/api/switches/{switch_id}/ports")
async def ports(switch_id: int, request: Request, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    source, snmp_error, result = f"{sw.protocol}/cli", "", None
    if snmp_configured(sw):
        try:
            result = await snmp_interfaces(sw)
            if result:
                source = snmp_label(sw)
        except Exception as exc:
            snmp_error = str(exc)
    operator = None
    if not result:
        operator = operator_context(request, required=True)
        try:
            result = await asyncio.to_thread(get_ports, sw, operator)
        except Exception as exc:
            message = f"SNMP: {snmp_error}; CLI: {exc}" if snmp_error else str(exc)
            audit(db, sw, "ports.view", success=False, message=message, **audit_identity(request, operator)); raise HTTPException(502, message)
    summary = Counter((p.get("status") or "unknown") for p in result)
    error_ports = sum(1 for p in result if str(p.get("in_errors") or "0").isdigit() and str(p.get("out_errors") or "0").isdigit() and (int(str(p.get("in_errors") or "0")) + int(str(p.get("out_errors") or "0")) > 0))
    audit(db, sw, "ports.view", command=f"source={source}", **audit_identity(request, operator))
    return {"switch": sw_public(sw), "source": source, "snmp_fallback_error": snmp_error, "summary": dict(summary), "error_ports": error_ports, "ports": result}


@app.post("/api/switches/{switch_id}/ports/snapshot")
async def port_snapshot(switch_id: int, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    try:
        result = await _snapshot_ports_for_switch(db, sw)
        audit(db, sw, "ports.snapshot", command=result.get("source", "snmp"))
        return result
    except Exception as exc:
        db.rollback()
        audit(db, sw, "ports.snapshot", success=False, message=exc)
        raise HTTPException(502, str(exc))


@app.get("/api/switches/{switch_id}/port-history")
def port_history(switch_id: int, port: str, hours: int = 168, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    try:
        port = validate_interface(port)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    hours = min(max(hours, 1), 24 * PORT_HISTORY_RETENTION_DAYS)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.scalars(select(InterfaceSample).where(InterfaceSample.switch_id == switch_id, InterfaceSample.port == port, InterfaceSample.created_at >= cutoff).order_by(InterfaceSample.created_at)).all()
    return {
        "port": port,
        "hours": hours,
        "samples": [{"time": r.created_at, "status": r.status, "admin_status": r.admin_status, "speed": r.speed, "description": r.description, "in_errors": r.in_errors, "out_errors": r.out_errors, "source": r.source} for r in rows],
    }


@app.get("/api/switches/{switch_id}/port-detail")
async def port_detail(switch_id: int, port: str, request: Request, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    operator = operator_context(request, required=True)
    identity = audit_identity(request, operator)
    try:
        port = validate_interface(port)
        detail = await asyncio.to_thread(get_port_detail, sw, port, operator)
        audit(db, sw, "port.detail", command=f"interface {port}", **identity)
        return {"switch": sw_public(sw), **detail}
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        audit(db, sw, "port.detail", command=f"interface {port}", success=False, message=exc, **identity)
        raise HTTPException(502, str(exc))


@app.get("/api/switches/{switch_id}/availability")
def availability(switch_id: int, hours: int = 168, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw:
        raise HTTPException(404, "Switch not found")
    hours = min(max(hours, 1), 24 * AVAILABILITY_RETENTION_DAYS)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.scalars(select(AvailabilitySample).where(AvailabilitySample.switch_id == switch_id, AvailabilitySample.created_at >= cutoff).order_by(AvailabilitySample.created_at)).all()
    pct = round(sum(1 for r in rows if r.online) * 100 / len(rows), 2) if rows else None
    return {"hours": hours, "availability_percent": pct, "samples": [{"time": r.created_at, "online": r.online, "source": r.source, "latency_ms": r.latency_ms} for r in rows]}


@app.post("/api/switches/{switch_id}/command")
async def command(switch_id: int, payload: CommandRequest, request: Request, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw: raise HTTPException(404, "Switch not found")
    operator = operator_context(request, required=True); identity = audit_identity(request, operator)
    cmd = payload.command.strip()
    try:
        output = await asyncio.to_thread(run_command, sw, cmd, False, operator); audit(db, sw, "terminal.command", command=cmd, **identity); return {"output": output}
    except Exception as exc:
        audit(db, sw, "terminal.command", command=cmd, success=False, message=exc, **identity); raise HTTPException(502, str(exc))


@app.post("/api/switches/{switch_id}/terminal/open")
async def terminal_open(switch_id: int, request: Request, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw: raise HTTPException(404, "Switch not found")
    operator = operator_context(request, required=True); identity = audit_identity(request, operator)
    try:
        result = await asyncio.to_thread(open_terminal, sw, operator, operator["username"]); audit(db, sw, "terminal.open", command=sw.protocol or "telnet", **identity); return result
    except Exception as exc:
        audit(db, sw, "terminal.open", success=False, message=exc, **identity); raise HTTPException(502, str(exc))


@app.post("/api/terminal/{session_id}/command")
async def terminal_session_command(session_id: str, payload: CommandRequest, request: Request, db: Session = Depends(get_db)):
    operator = operator_context(request, required=True)
    try:
        result = await asyncio.to_thread(terminal_command, session_id, payload.command, operator["username"])
        sw = db.scalar(select(Switch).where(Switch.hostname == result.get("hostname")))
        audit(db, sw, "terminal.session.command", command=payload.command, **audit_identity(request, operator)); return result
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except Exception as exc:
        raise HTTPException(502, str(exc))


@app.delete("/api/terminal/{session_id}")
async def terminal_close(session_id: str):
    return {"ok": await asyncio.to_thread(close_terminal, session_id)}


@app.get("/api/switches/{switch_id}/neighbors")
async def neighbors(switch_id: int, request: Request, protocol: str = "both", db: Session = Depends(get_db)):
    if protocol not in {"cdp", "lldp", "both"}: raise HTTPException(400, "protocol must be cdp, lldp or both")
    sw = db.get(Switch, switch_id)
    if not sw: raise HTTPException(404, "Switch not found")
    operator = operator_context(request, required=True)
    result = await asyncio.to_thread(get_neighbors, sw, protocol, operator); audit(db, sw, "neighbors.view", command=protocol, **audit_identity(request, operator)); return result


@app.get("/api/topology")
async def topology(request: Request, db: Session = Depends(get_db)):
    operator = operator_context(request, required=True)
    switches = db.scalars(select(Switch).order_by(Switch.site, Switch.hostname)).all()
    nodes = [{"id": s.hostname, "switch_id": s.id, "hostname": s.hostname, "ip": s.management_ip, "site": s.site, "known": True, "online": s.is_online} for s in switches]
    node_ids = {n["id"] for n in nodes}; external, edges = {}, []
    sem = asyncio.Semaphore(8)
    async def collect(sw):
        async with sem:
            try: return sw, await asyncio.to_thread(get_topology_neighbors, sw, operator), None
            except Exception as exc: return sw, [], str(exc)
    results = await asyncio.gather(*(collect(sw) for sw in switches)) if switches else []
    identity = audit_identity(request, operator)
    for sw, _, error in results:
        audit(db, sw, "topology.view", command="cdp/lldp", success=not bool(error), message=error or "", **identity)
    known_lower = {s.hostname.lower(): s.hostname for s in switches}; edge_keys = set()
    for sw, rows, _ in results:
        for n in rows:
            raw = (n.get("device_id") or "unknown").split(".")[0]; target = known_lower.get(raw.lower(), raw)
            if target not in node_ids:
                external[target] = {"id": target, "switch_id": None, "hostname": target, "ip": n.get("ip", ""), "site": n.get("protocol", "neighbor").upper(), "known": False, "online": None}
            key = (sw.hostname.lower(), target.lower(), n.get("local_interface", ""), n.get("remote_interface", ""))
            if key not in edge_keys:
                edge_keys.add(key); edges.append({"source": sw.hostname, "target": target, "local_interface": n.get("local_interface", ""), "remote_interface": n.get("remote_interface", ""), "protocol": n.get("protocol", "")})
    nodes.extend(external.values())
    return {"nodes": nodes, "edges": edges}


@app.post("/api/discovery/scan")
async def discovery_scan(payload: DiscoveryRequest, db: Session = Depends(get_db)):
    try:
        network = ipaddress.ip_network(payload.network, strict=False)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if network.version != 4 or network.num_addresses > 1024:
        raise HTTPException(400, "Discovery is limited to IPv4 networks with up to 1024 addresses")
    protocol, snmp_version = _validate_protocols(payload.protocol, payload.snmp_version)
    template = dict(
        snmp_port=payload.snmp_port or 161, snmp_version=snmp_version,
        snmp_community_enc=encrypt(payload.snmp_community), snmp_v3_user_enc=encrypt(payload.snmp_v3_user),
        snmp_v3_auth_key_enc=encrypt(payload.snmp_v3_auth_key), snmp_v3_priv_key_enc=encrypt(payload.snmp_v3_priv_key),
        snmp_v3_auth_protocol=(payload.snmp_v3_auth_protocol or "SHA").upper(), snmp_v3_priv_protocol=(payload.snmp_v3_priv_protocol or "AES").upper(),
    )
    sem = asyncio.Semaphore(64)
    async def scan(ip):
        async with sem:
            target = SimpleNamespace(management_ip=str(ip), **template)
            try:
                info = await snmp_health(target)
                if "cisco" not in (info.get("sys_descr") or "").lower(): return None
                return {"ip": str(ip), **info}
            except Exception: return None
    found = [r for r in await asyncio.gather(*(scan(ip) for ip in network.hosts())) if r]
    added = []
    if payload.add_found:
        existing_ips = set(db.scalars(select(Switch.management_ip)).all()); existing_hosts = set(h.lower() for h in db.scalars(select(Switch.hostname)).all())
        for item in found:
            if item["ip"] in existing_ips: continue
            base = (item.get("sys_name") or f"SW-{item['ip'].replace('.', '-')}").split(".")[0][:120]; hostname = base; suffix = 2
            while hostname.lower() in existing_hosts:
                hostname = f"{base[:110]}-{suffix}"; suffix += 1
            sw = Switch(hostname=hostname, management_ip=item["ip"], site=payload.site or "Descoberta", platform="cisco_ios", protocol=protocol,
                port=payload.cli_port or (23 if protocol == "telnet" else 22),
                snmp_version=snmp_version, snmp_port=payload.snmp_port or 161, snmp_community_enc=template["snmp_community_enc"], snmp_v3_user_enc=template["snmp_v3_user_enc"],
                snmp_v3_auth_key_enc=template["snmp_v3_auth_key_enc"], snmp_v3_priv_key_enc=template["snmp_v3_priv_key_enc"], snmp_v3_auth_protocol=template["snmp_v3_auth_protocol"],
                snmp_v3_priv_protocol=template["snmp_v3_priv_protocol"], monitor_method="snmp", is_online=True, last_seen=datetime.now(timezone.utc), last_status_source=snmp_label(SimpleNamespace(snmp_version=snmp_version)))
            db.add(sw); db.flush(); existing_ips.add(item["ip"]); existing_hosts.add(hostname.lower()); added.append({"hostname": hostname, "ip": item["ip"]})
        db.commit()
    return {"network": str(network), "scanned": max(0, network.num_addresses - 2), "found_count": len(found), "found": found, "added": added}


@app.post("/api/mac/search")
async def mac_search(payload: MacSearchRequest, request: Request, db: Session = Depends(get_db)):
    operator = operator_context(request, required=True)
    query = select(Switch)
    if payload.switch_ids: query = query.where(Switch.id.in_(payload.switch_ids))
    switches = db.scalars(query.order_by(Switch.site, Switch.hostname)).all()
    if not switches: raise HTTPException(404, "No switches selected")
    sem = asyncio.Semaphore(10)
    async def lookup(sw):
        async with sem:
            try: return await asyncio.to_thread(search_mac_one, sw, payload.mac, operator)
            except Exception as exc: return {"switch_id": sw.id, "hostname": sw.hostname, "site": sw.site, "management_ip": sw.management_ip, "found": False, "interfaces": [], "error": str(exc)}
    results = await asyncio.gather(*(lookup(sw) for sw in switches))
    identity = audit_identity(request, operator)
    by_id = {sw.id: sw for sw in switches}
    for result in results:
        sw = by_id.get(result.get("switch_id"))
        audit(db, sw, "mac.search", command=payload.mac, success=not bool(result.get("error")), message=result.get("error", ""), **identity)
    return {"mac": payload.mac, "found_count": sum(1 for r in results if r.get("found")), "results": results}


@app.post("/api/banner/motd")
async def banner_motd(payload: BannerRequest, request: Request, db: Session = Depends(get_db)):
    operator = operator_context(request, required=True); identity = audit_identity(request, operator)
    legacy_banner = payload.banner.strip() if payload.banner and payload.banner.strip() else None
    if not legacy_banner:
        if not payload.email.strip() or not payload.phone.strip() or not payload.restricted_message.strip():
            raise HTTPException(422, "E-mail, telefone e mensagem de acesso restrito sao obrigatorios")
    switches = db.scalars(select(Switch).where(Switch.id.in_(payload.switch_ids))).all(); results = []
    for sw in switches:
        try:
            # v0.3.2: gera um banner proprio para cada switch. O campo banner permanece
            # aceito para compatibilidade com chamadas antigas da API.
            banner_text = legacy_banner or build_motd_banner(
                sw, payload.email.strip(), payload.phone.strip(), payload.restricted_message.strip()
            )
            output = await asyncio.to_thread(apply_motd, sw, banner_text, payload.save_config, operator)
            results.append({"switch_id": sw.id, "hostname": sw.hostname, "management_ip": sw.management_ip, "success": True, "banner": banner_text, "output": output})
            audit(db, sw, "banner.motd", command="banner motd", message=f"Contato: {payload.email or '-'} / {payload.phone or '-'}", **identity)
        except Exception as exc:
            results.append({"switch_id": sw.id, "hostname": sw.hostname, "management_ip": sw.management_ip, "success": False, "error": str(exc)})
            audit(db, sw, "banner.motd", command="banner motd", success=False, message=exc, **identity)
    return results


@app.post("/api/switches/{switch_id}/backups")
async def backup_create(switch_id: int, request: Request, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw: raise HTTPException(404, "Switch not found")
    operator = operator_context(request, required=True); identity = audit_identity(request, operator)
    try:
        path = await asyncio.to_thread(create_backup, sw, operator); audit(db, sw, "backup.create", command="show running-config", **identity); return {"ok": True, "name": path.name}
    except Exception as exc:
        audit(db, sw, "backup.create", command="show running-config", success=False, message=exc, **identity); raise HTTPException(502, str(exc))


@app.get("/api/switches/{switch_id}/backups")
def backups_list(switch_id: int, db: Session = Depends(get_db)):
    sw = db.get(Switch, switch_id)
    if not sw: raise HTTPException(404, "Switch not found")
    return list_backups(sw)


@app.get("/api/backups/download")
def backup_download(path: str):
    try: file_path = backup_path(path)
    except (ValueError, FileNotFoundError) as exc: raise HTTPException(404, str(exc))
    return FileResponse(file_path, filename=file_path.name, media_type="text/plain")


@app.get("/api/backups/diff", response_class=PlainTextResponse)
def backup_diff(old: str, new: str):
    try:
        old_path, new_path = backup_path(old), backup_path(new)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(404, str(exc))
    old_lines = old_path.read_text(encoding="utf-8", errors="replace").splitlines(); new_lines = new_path.read_text(encoding="utf-8", errors="replace").splitlines()
    diff = list(difflib.unified_diff(old_lines, new_lines, fromfile=old_path.name, tofile=new_path.name, lineterm=""))
    return "\n".join(diff[:12000]) or "Sem alteracoes entre os backups selecionados."


@app.get("/api/shortcuts")
def list_shortcuts(db: Session = Depends(get_db)):
    return [{"id": s.id, "name": s.name, "command": s.command, "description": s.description} for s in db.scalars(select(Shortcut).order_by(Shortcut.name)).all()]


@app.post("/api/shortcuts")
def create_shortcut(payload: ShortcutCreate, db: Session = Depends(get_db)):
    item = Shortcut(name=payload.name.strip(), command=payload.command.strip(), description=payload.description.strip()); db.add(item)
    try: db.commit(); db.refresh(item)
    except IntegrityError: db.rollback(); raise HTTPException(409, "Shortcut name already exists")
    return {"id": item.id, "name": item.name, "command": item.command, "description": item.description}


@app.delete("/api/shortcuts/{shortcut_id}")
def delete_shortcut(shortcut_id: int, db: Session = Depends(get_db)):
    item = db.get(Shortcut, shortcut_id)
    if not item: raise HTTPException(404, "Shortcut not found")
    db.delete(item); db.commit(); return {"ok": True}


@app.get("/api/audit")
def audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    limit = min(max(limit, 1), 500)
    rows = db.scalars(select(AuditLog).order_by(desc(AuditLog.id)).limit(limit)).all()
    return [{"id": r.id, "hostname": r.hostname, "portal_user": r.portal_user, "operator_user": r.operator_user, "action": r.action, "command": r.command, "success": r.success, "message": r.message, "created_at": r.created_at} for r in rows]


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")
