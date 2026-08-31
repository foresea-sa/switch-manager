import re
import secrets
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from netmiko import ConnectHandler

BASE_DIR = Path(__file__).resolve().parents[1]
BACKUP_DIR = BASE_DIR / "data" / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

TERMINAL_SESSIONS = {}
TERMINAL_SESSIONS_LOCK = threading.Lock()
SESSION_IDLE_SECONDS = 15 * 60


def utcnow():
    return datetime.now(timezone.utc)


def device_params(sw, credentials=None):
    protocol = (sw.protocol or "telnet").lower()
    if protocol not in {"ssh", "telnet"}:
        protocol = "telnet"
    device_type = sw.platform or "cisco_ios"
    if protocol == "telnet" and not device_type.endswith("_telnet"):
        device_type = f"{device_type}_telnet"
    credentials = credentials or {}
    username = credentials.get("username") or ""
    password = credentials.get("password") or ""
    secret = credentials.get("secret") or ""
    if not username or not password:
        raise ValueError("Sessao Cisco necessaria. Informe seu usuario adm- e senha antes de usar Telnet/SSH.")
    return {
        "device_type": device_type,
        "host": sw.management_ip,
        "port": sw.port or (23 if protocol == "telnet" else 22),
        "username": username,
        "password": password,
        "secret": secret,
        "conn_timeout": 7,
        "auth_timeout": 8,
        "banner_timeout": 12,
        "blocking_timeout": 20,
        "fast_cli": False,
    }


def tcp_probe(sw, timeout=2.5):
    port = sw.port or (23 if (sw.protocol or "telnet").lower() == "telnet" else 22)
    try:
        with socket.create_connection((sw.management_ip, port), timeout=timeout):
            return True, f"TCP/{port} reachable"
    except Exception as exc:
        return False, str(exc)


def connect(sw, credentials=None):
    conn = ConnectHandler(**device_params(sw, credentials))
    if (credentials or {}).get("secret"):
        try:
            conn.enable()
        except Exception:
            pass
    return conn


def run_command(sw, command, use_textfsm=False, credentials=None):
    conn = connect(sw, credentials)
    try:
        output = conn.send_command(command, use_textfsm=use_textfsm, read_timeout=25)
        return output
    finally:
        conn.disconnect()


def run_config(sw, commands, save_config=False, credentials=None):
    conn = connect(sw, credentials)
    try:
        output = conn.send_config_set(commands, read_timeout=40)
        if save_config:
            try:
                output += "\n" + conn.save_config()
            except Exception:
                output += "\nWARNING: configuration applied, but automatic save failed."
        return output
    finally:
        conn.disconnect()


DEFAULT_RESTRICTED_MESSAGE = (
    "ACESSO RESTRITO. O acesso a este equipamento e permitido somente a usuarios autorizados. "
    "Todas as atividades podem ser monitoradas e registradas."
)


def build_motd_banner(sw, email="", phone="", restricted_message=""):
    """Gera um MOTD individual com identidade do switch e contatos de suporte."""
    hostname = str(getattr(sw, "hostname", "") or "N/D").strip()
    management_ip = str(getattr(sw, "management_ip", "") or "N/D").strip()
    message = str(restricted_message or DEFAULT_RESTRICTED_MESSAGE).strip()
    email = str(email or "N/D").strip()
    phone = str(phone or "N/D").strip()

    return "\n".join([
        "============================================================",
        "                    ACESSO RESTRITO",
        "============================================================",
        f"Equipamento : {hostname}",
        f"IP          : {management_ip}",
        "------------------------------------------------------------",
        message,
        "------------------------------------------------------------",
        f"E-mail      : {email}",
        f"Telefone    : {phone}",
        "============================================================",
    ])


def apply_motd(sw, banner, save_config=False, credentials=None):
    delimiter = "^"
    safe_banner = banner.replace(delimiter, "-").strip()
    return run_config(sw, [f"banner motd {delimiter}{safe_banner}{delimiter}"], save_config=save_config, credentials=credentials)


def normalize_mac(mac):
    raw = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(raw) != 12:
        raise ValueError("MAC must contain exactly 12 hexadecimal characters")
    raw = raw.lower()
    return f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}"


def search_mac_one(sw, mac, credentials=None):
    normalized = normalize_mac(mac)
    output = run_command(sw, f"show mac address-table address {normalized}", credentials=credentials)
    interfaces = []
    for line in str(output).splitlines():
        if normalized in line.lower():
            tokens = line.split()
            if tokens:
                candidate = tokens[-1]
                if re.match(r"^(Gi|Te|Fa|Eth|Po|Hu|Twe|Fo|Vl|Port-channel)", candidate, re.I):
                    interfaces.append(candidate)
    return {
        "switch_id": sw.id,
        "hostname": sw.hostname,
        "site": sw.site,
        "management_ip": sw.management_ip,
        "mac": normalized,
        "found": bool(interfaces),
        "interfaces": sorted(set(interfaces)),
        "raw": output,
    }


def parse_show_version(text):
    text = str(text)
    version = ""
    model = ""
    serial = ""
    m = re.search(r"Cisco IOS(?: XE)? Software.*?Version\s+([^,\s]+)", text, re.I | re.S)
    if m:
        version = m.group(1)
    m = re.search(r"Model [Nn]umber\s*:\s*(\S+)", text)
    if m:
        model = m.group(1)
    if not model:
        m = re.search(r"cisco\s+(\S+)\s+\(.+processor", text, re.I)
        if m:
            model = m.group(1)
    m = re.search(r"System [Ss]erial [Nn]umber\s*:\s*(\S+)", text)
    if m:
        serial = m.group(1)
    return {"version": version, "model": model, "serial": serial}


def get_facts(sw, credentials=None):
    output = run_command(sw, "show version", credentials=credentials)
    facts = parse_show_version(output)
    facts["raw"] = output
    return facts


def get_neighbors(sw, protocol="both", credentials=None):
    commands = []
    if protocol in {"cdp", "both"}:
        commands.append(("cdp", "show cdp neighbors detail"))
    if protocol in {"lldp", "both"}:
        commands.append(("lldp", "show lldp neighbors detail"))
    results = []
    for name, cmd in commands:
        try:
            results.append({"protocol": name, "output": run_command(sw, cmd, credentials=credentials)})
        except Exception as exc:
            results.append({"protocol": name, "output": f"ERROR: {exc}"})
    return results


def parse_cdp_neighbors(text):
    neighbors = []
    chunks = re.split(r"\n(?=Device ID:)", str(text))
    for chunk in chunks:
        device = re.search(r"Device ID:\s*(.+)", chunk)
        if not device:
            continue
        ip = re.search(r"IP address:\s*([^\s]+)", chunk, re.I)
        iface = re.search(r"Interface:\s*([^,\n]+),\s*Port ID \(outgoing port\):\s*([^\n]+)", chunk, re.I)
        platform = re.search(r"Platform:\s*([^,\n]+)", chunk, re.I)
        neighbors.append({
            "device_id": device.group(1).strip(),
            "ip": ip.group(1).strip() if ip else "",
            "local_interface": iface.group(1).strip() if iface else "",
            "remote_interface": iface.group(2).strip() if iface else "",
            "platform": platform.group(1).strip() if platform else "",
        })
    return neighbors


def get_cdp_parsed(sw, credentials=None):
    return parse_cdp_neighbors(run_command(sw, "show cdp neighbors detail", credentials=credentials))


def get_ports(sw, credentials=None):
    result = run_command(sw, "show interfaces status", use_textfsm=True, credentials=credentials)
    if isinstance(result, list):
        ports = []
        for row in result:
            port = row.get("port") or row.get("interface") or row.get("intf") or ""
            status = row.get("status") or "unknown"
            ports.append({
                "port": port,
                "name": row.get("name", ""),
                "status": status,
                "admin_status": "",
                "vlan": row.get("vlan", ""),
                "duplex": row.get("duplex", ""),
                "speed": row.get("speed", ""),
                "type": row.get("type", ""),
                "in_errors": "",
                "out_errors": "",
            })
        return ports
    return fallback_parse_ports(str(result))


def fallback_parse_ports(text):
    ports = []
    statuses = {"connected", "notconnect", "disabled", "err-disabled", "inactive", "monitoring", "sfpAbsent"}
    for line in text.splitlines():
        line = line.rstrip()
        if not re.match(r"^(Gi|Te|Fa|Eth|Po|Hu|Twe|Fo)\S*\s+", line, re.I):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        status_idx = next((i for i, p in enumerate(parts[1:], 1) if p in statuses), None)
        if status_idx is None:
            continue
        port = parts[0]
        name = " ".join(parts[1:status_idx])
        status = parts[status_idx]
        vlan = parts[status_idx + 1] if len(parts) > status_idx + 1 else ""
        duplex = parts[status_idx + 2] if len(parts) > status_idx + 2 else ""
        speed = parts[status_idx + 3] if len(parts) > status_idx + 3 else ""
        ptype = " ".join(parts[status_idx + 4:]) if len(parts) > status_idx + 4 else ""
        ports.append({"port": port, "name": name, "status": status, "admin_status": "", "vlan": vlan, "duplex": duplex, "speed": speed, "type": ptype, "in_errors": "", "out_errors": ""})
    return ports


def create_backup(sw, credentials=None):
    output = run_command(sw, "show running-config", credentials=credentials)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", sw.hostname)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = BACKUP_DIR / safe_host
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{safe_host}_{stamp}_running-config.txt"
    path.write_text(str(output), encoding="utf-8")
    return path


def list_backups(sw):
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", sw.hostname)
    directory = BACKUP_DIR / safe_host
    if not directory.exists():
        return []
    rows = []
    for path in sorted(directory.glob("*_running-config.txt"), reverse=True):
        stat = path.stat()
        rows.append({
            "name": path.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            "relative_path": f"{safe_host}/{path.name}",
        })
    return rows


def backup_path(relative_path):
    candidate = (BACKUP_DIR / relative_path).resolve()
    root = BACKUP_DIR.resolve()
    if root not in candidate.parents:
        raise ValueError("Invalid backup path")
    if not candidate.is_file():
        raise FileNotFoundError("Backup not found")
    return candidate


def _cleanup_sessions():
    now = datetime.now(timezone.utc).timestamp()
    stale = []
    with TERMINAL_SESSIONS_LOCK:
        for token, item in list(TERMINAL_SESSIONS.items()):
            if now - item["last_used"] > SESSION_IDLE_SECONDS:
                stale.append((token, item))
                TERMINAL_SESSIONS.pop(token, None)
    for _, item in stale:
        try:
            item["conn"].disconnect()
        except Exception:
            pass


def open_terminal(sw, credentials=None, operator_user=""):
    _cleanup_sessions()
    conn = connect(sw, credentials)
    token = secrets.token_urlsafe(24)
    prompt = ""
    try:
        prompt = conn.find_prompt()
    except Exception:
        pass
    item = {
        "conn": conn,
        "switch_id": sw.id,
        "hostname": sw.hostname,
        "operator_user": operator_user or (credentials or {}).get("username", ""),
        "last_used": datetime.now(timezone.utc).timestamp(),
        "lock": threading.Lock(),
    }
    with TERMINAL_SESSIONS_LOCK:
        TERMINAL_SESSIONS[token] = item
    return {"session_id": token, "prompt": prompt, "hostname": sw.hostname}


def terminal_command(session_id, command, expected_operator_user=""):
    _cleanup_sessions()
    with TERMINAL_SESSIONS_LOCK:
        item = TERMINAL_SESSIONS.get(session_id)
    if not item:
        raise KeyError("Terminal session expired or not found")
    if expected_operator_user and item.get("operator_user") != expected_operator_user:
        raise PermissionError("Esta sessao de terminal pertence a outro usuario Cisco")
    with item["lock"]:
        item["last_used"] = datetime.now(timezone.utc).timestamp()
        conn = item["conn"]
        # send_command_timing preserves mode changes such as configure terminal/interface.
        output = conn.send_command_timing(
            command,
            strip_prompt=False,
            strip_command=False,
            read_timeout=20,
            last_read=1.0,
        )
        return {"output": output, "prompt": conn.find_prompt(), "hostname": item["hostname"], "operator_user": item.get("operator_user", "")}


def close_terminal(session_id):
    with TERMINAL_SESSIONS_LOCK:
        item = TERMINAL_SESSIONS.pop(session_id, None)
    if item:
        try:
            item["conn"].disconnect()
        except Exception:
            pass
        return True
    return False


def close_terminals_for_operator(operator_user):
    if not operator_user:
        return 0
    closed = []
    with TERMINAL_SESSIONS_LOCK:
        for token, item in list(TERMINAL_SESSIONS.items()):
            if item.get("operator_user") == operator_user:
                closed.append(TERMINAL_SESSIONS.pop(token))
    for item in closed:
        try:
            item["conn"].disconnect()
        except Exception:
            pass
    return len(closed)


def parse_lldp_neighbors(text):
    neighbors = []
    chunks = re.split(r"\n(?=Local Intf:|Chassis id:)", str(text), flags=re.I)
    for chunk in chunks:
        local = re.search(r"Local Intf:\s*([^\n]+)", chunk, re.I)
        port = re.search(r"Port id:\s*([^\n]+)", chunk, re.I)
        sysname = re.search(r"System Name:\s*([^\n]+)", chunk, re.I)
        mgmt = re.search(r"Management Address(?:es)?:\s*(?:IP:\s*)?([^\s\n]+)", chunk, re.I)
        descr = re.search(r"System Description:\s*\n?([^\n]+)", chunk, re.I)
        if not (sysname or port or local):
            continue
        neighbors.append({
            "device_id": (sysname.group(1).strip() if sysname else (port.group(1).strip() if port else "LLDP-neighbor")),
            "ip": mgmt.group(1).strip() if mgmt else "",
            "local_interface": local.group(1).strip() if local else "",
            "remote_interface": port.group(1).strip() if port else "",
            "platform": descr.group(1).strip() if descr else "LLDP",
        })
    return neighbors


def get_topology_neighbors(sw, credentials=None):
    rows = []
    try:
        for item in parse_cdp_neighbors(run_command(sw, "show cdp neighbors detail", credentials=credentials)):
            item["protocol"] = "cdp"
            rows.append(item)
    except Exception:
        pass
    try:
        for item in parse_lldp_neighbors(run_command(sw, "show lldp neighbors detail", credentials=credentials)):
            item["protocol"] = "lldp"
            rows.append(item)
    except Exception:
        pass
    # De-duplicate the same neighbor learned by both protocols.
    unique = {}
    for row in rows:
        key = (row.get("device_id", "").split(".")[0].lower(), row.get("local_interface", "").lower(), row.get("remote_interface", "").lower())
        unique.setdefault(key, row)
    return list(unique.values())
