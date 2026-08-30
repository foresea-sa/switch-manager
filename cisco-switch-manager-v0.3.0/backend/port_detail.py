import re
from .network import connect, parse_cdp_neighbors, parse_lldp_neighbors

_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9./:_-]{0,63}$")
_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}")


def validate_interface(interface: str) -> str:
    value = (interface or "").strip()
    if not _IFACE_RE.fullmatch(value):
        raise ValueError("Invalid interface name")
    return value


def _run_on_connection(conn, command):
    try:
        return str(conn.send_command(command, read_timeout=25))
    except Exception as exc:
        return f"ERROR: {exc}"


def _parse_interface(raw):
    first = raw.splitlines()[0].strip() if raw.splitlines() else ""
    status = "unknown"
    protocol = "unknown"
    m = re.search(r"is\s+([^,]+),\s+line protocol is\s+([^\s,]+)", first, re.I)
    if m:
        status, protocol = m.group(1).strip(), m.group(2).strip()
    in_err = re.search(r"(\d+)\s+input errors", raw, re.I)
    out_err = re.search(r"(\d+)\s+output errors", raw, re.I)
    rate_in = re.search(r"5 minute input rate\s+(\d+)\s+bits/sec", raw, re.I)
    rate_out = re.search(r"5 minute output rate\s+(\d+)\s+bits/sec", raw, re.I)
    desc = re.search(r"Description:\s*([^\n]+)", raw, re.I)
    return {
        "interface_status": status,
        "line_protocol": protocol,
        "description": desc.group(1).strip() if desc else "",
        "input_errors": int(in_err.group(1)) if in_err else 0,
        "output_errors": int(out_err.group(1)) if out_err else 0,
        "input_bps_5m": int(rate_in.group(1)) if rate_in else None,
        "output_bps_5m": int(rate_out.group(1)) if rate_out else None,
    }


def _parse_macs(raw):
    rows = []
    seen = set()
    for line in raw.splitlines():
        match = _MAC_RE.search(line)
        if not match:
            continue
        mac = match.group(0).lower()
        if mac in seen:
            continue
        seen.add(mac)
        parts = line.split()
        vlan = parts[0] if parts and parts[0].isdigit() else ""
        kind = "dynamic" if "DYNAMIC" in line.upper() else ("static" if "STATIC" in line.upper() else "")
        rows.append({"mac": mac, "vlan": vlan, "type": kind})
    return rows


def _field(raw, name):
    m = re.search(rf"^{re.escape(name)}\s*:\s*(.+)$", raw, re.I | re.M)
    return m.group(1).strip() if m else ""


def _parse_switchport(raw):
    return {
        "name": _field(raw, "Name"),
        "switchport": _field(raw, "Switchport"),
        "administrative_mode": _field(raw, "Administrative Mode"),
        "operational_mode": _field(raw, "Operational Mode"),
        "access_vlan": _field(raw, "Access Mode VLAN"),
        "native_vlan": _field(raw, "Trunking Native Mode VLAN"),
        "trunk_vlans": _field(raw, "Trunking VLANs Enabled"),
    }


def get_port_detail(sw, interface: str):
    interface = validate_interface(interface)
    conn = connect(sw)
    try:
        raw_interface = _run_on_connection(conn, f"show interfaces {interface}")
        raw_mac = _run_on_connection(conn, f"show mac address-table interface {interface}")
        raw_switchport = _run_on_connection(conn, f"show interfaces {interface} switchport")
        raw_poe = _run_on_connection(conn, f"show power inline {interface}")
        raw_cdp = _run_on_connection(conn, f"show cdp neighbors {interface} detail")
        raw_lldp = _run_on_connection(conn, f"show lldp neighbors {interface} detail")
    finally:
        conn.disconnect()
    detail = _parse_interface(raw_interface)
    return {
        "port": interface,
        **detail,
        "switchport": _parse_switchport(raw_switchport),
        "macs": _parse_macs(raw_mac),
        "neighbors": [
            *[{**x, "protocol": "cdp"} for x in parse_cdp_neighbors(raw_cdp)],
            *[{**x, "protocol": "lldp"} for x in parse_lldp_neighbors(raw_lldp)],
        ],
        "poe_raw": raw_poe[:12000],
        "raw": {
            "interface": raw_interface[:20000],
            "mac_table": raw_mac[:12000],
            "switchport": raw_switchport[:12000],
        },
    }
