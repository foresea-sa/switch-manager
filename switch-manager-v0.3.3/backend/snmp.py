from .crypto import decrypt

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine,
        CommunityData,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        get_cmd,
        bulk_walk_cmd,
        USM_AUTH_HMAC96_MD5,
        USM_AUTH_HMAC96_SHA,
        USM_AUTH_NONE,
        USM_PRIV_CFB128_AES,
        USM_PRIV_CBC56_DES,
        USM_PRIV_NONE,
    )
except Exception as exc:  # runtime dependency check
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
IF_OPER = "1.3.6.1.2.1.2.2.1.8"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
VENDOR_CPU_5S = "1.3.6.1.4.1.9.9.109.1.1.1.1.3"
VENDOR_MEM_USED = "1.3.6.1.4.1.9.9.48.1.1.1.5"
VENDOR_MEM_FREE = "1.3.6.1.4.1.9.9.48.1.1.1.6"
ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
ENT_SENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"
ENT_SENSOR_SCALE = "1.3.6.1.2.1.99.1.1.1.2"
ENT_SENSOR_PRECISION = "1.3.6.1.2.1.99.1.1.1.3"
ENT_SENSOR_VALUE = "1.3.6.1.2.1.99.1.1.1.4"
ENT_SENSOR_STATUS = "1.3.6.1.2.1.99.1.1.1.5"
POE_MAIN_CONSUMPTION = "1.3.6.1.2.1.105.1.3.1.1.4"
POE_PORT_DETECTION = "1.3.6.1.2.1.105.1.1.1.6"


def _require_module():
    if _IMPORT_ERROR:
        raise RuntimeError(f"PySNMP unavailable: {_IMPORT_ERROR}")


def _secret(sw, attr):
    return decrypt(getattr(sw, attr, "") or "")


def _auth(sw):
    _require_module()
    version = (getattr(sw, "snmp_version", "v2c") or "v2c").lower()
    if version in {"v2", "v2c", "2c"}:
        community = _secret(sw, "snmp_community_enc")
        if not community:
            raise RuntimeError("SNMPv2c community is not configured")
        return CommunityData(community, mpModel=1)
    if version != "v3":
        raise RuntimeError("SNMP version must be v2c or v3")

    username = _secret(sw, "snmp_v3_user_enc")
    auth_key = _secret(sw, "snmp_v3_auth_key_enc")
    priv_key = _secret(sw, "snmp_v3_priv_key_enc")
    if not username:
        raise RuntimeError("SNMPv3 username is not configured")

    auth_name = (getattr(sw, "snmp_v3_auth_protocol", "SHA") or "SHA").upper()
    priv_name = (getattr(sw, "snmp_v3_priv_protocol", "AES") or "AES").upper()
    auth_proto = {"NONE": USM_AUTH_NONE, "NOAUTH": USM_AUTH_NONE, "MD5": USM_AUTH_HMAC96_MD5, "SHA": USM_AUTH_HMAC96_SHA}.get(auth_name, USM_AUTH_HMAC96_SHA)
    priv_proto = {"NONE": USM_PRIV_NONE, "NOPRIV": USM_PRIV_NONE, "DES": USM_PRIV_CBC56_DES, "AES": USM_PRIV_CFB128_AES}.get(priv_name, USM_PRIV_CFB128_AES)

    if auth_proto == USM_AUTH_NONE:
        return UsmUserData(username)
    if not auth_key:
        raise RuntimeError("SNMPv3 authentication key is required")
    if priv_proto == USM_PRIV_NONE:
        return UsmUserData(username, authKey=auth_key, authProtocol=auth_proto)
    if not priv_key:
        raise RuntimeError("SNMPv3 privacy key is required")
    return UsmUserData(username, authKey=auth_key, privKey=priv_key, authProtocol=auth_proto, privProtocol=priv_proto)


def _idx(oid: str, base: str):
    suffix = oid[len(base) + 1 :]
    return suffix


async def snmp_get(sw, oids, timeout=1.5, retries=1):
    auth = _auth(sw)
    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create((sw.management_ip, int(getattr(sw, "snmp_port", 161) or 161)), timeout=timeout, retries=retries)
        error_indication, error_status, error_index, var_binds = await get_cmd(
            engine,
            auth,
            target,
            ContextData(),
            *[ObjectType(ObjectIdentity(oid)) for oid in oids],
            lookupMib=False,
        )
        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(error_status.prettyPrint())
        return {var_bind[0].prettyPrint(): var_bind[1].prettyPrint() for var_bind in var_binds}
    finally:
        try:
            engine.close_dispatcher()
        except Exception:
            pass


async def snmp_walk(sw, base_oid, max_rows=1024, timeout=2, retries=1):
    auth = _auth(sw)
    engine = SnmpEngine()
    rows = []
    try:
        target = await UdpTransportTarget.create((sw.management_ip, int(getattr(sw, "snmp_port", 161) or 161)), timeout=timeout, retries=retries)
        async for error_indication, error_status, error_index, var_binds in bulk_walk_cmd(
            engine,
            auth,
            target,
            ContextData(),
            0,
            25,
            ObjectType(ObjectIdentity(base_oid)),
            lookupMib=False,
            lexicographicMode=False,
            maxRows=max_rows,
        ):
            if error_indication:
                raise RuntimeError(str(error_indication))
            if error_status:
                raise RuntimeError(error_status.prettyPrint())
            for var_bind in var_binds:
                oid = var_bind[0].prettyPrint()
                if oid.startswith(base_oid + "."):
                    rows.append((oid, var_bind[1].prettyPrint()))
        return rows
    finally:
        try:
            engine.close_dispatcher()
        except Exception:
            pass


async def snmp_health(sw):
    data = await snmp_get(sw, [SYS_NAME, SYS_DESCR, SYS_UPTIME])
    ticks_raw = data.get(SYS_UPTIME, "0")
    try:
        ticks = int(ticks_raw)
    except (TypeError, ValueError):
        ticks = 0
    return {
        "online": True,
        "sys_name": data.get(SYS_NAME, ""),
        "sys_descr": data.get(SYS_DESCR, ""),
        "uptime_ticks": ticks,
        "uptime_seconds": ticks // 100,
    }


async def snmp_interfaces(sw):
    walks = {}
    for key, oid in [
        ("name", IF_NAME), ("alias", IF_ALIAS), ("admin", IF_ADMIN), ("oper", IF_OPER),
        ("speed", IF_SPEED), ("high_speed", IF_HIGH_SPEED), ("in_errors", IF_IN_ERRORS), ("out_errors", IF_OUT_ERRORS),
    ]:
        try:
            walks[key] = {_idx(o, oid): v for o, v in await snmp_walk(sw, oid)}
        except Exception:
            walks[key] = {}
    indexes = sorted(set().union(*(set(v.keys()) for v in walks.values())), key=lambda x: [int(p) if p.isdigit() else p for p in x.split(".")])
    admin_map = {"1": "up", "2": "down", "3": "testing"}
    oper_map = {"1": "connected", "2": "notconnect", "3": "testing", "4": "unknown", "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}
    ports = []
    for index in indexes:
        name = walks["name"].get(index, f"ifIndex {index}")
        lower = name.lower()
        if lower.startswith(("vlan", "null", "loopback", "stackport")):
            continue
        try:
            hs = int(walks["high_speed"].get(index, "0") or 0)
            bps = int(walks["speed"].get(index, "0") or 0)
            speed = f"{hs} Mbps" if hs > 0 else (f"{bps // 1000000} Mbps" if bps > 0 else "")
        except ValueError:
            speed = ""
        ports.append({
            "index": index,
            "port": name,
            "name": walks["alias"].get(index, ""),
            "status": oper_map.get(walks["oper"].get(index, ""), "unknown"),
            "admin_status": admin_map.get(walks["admin"].get(index, ""), "unknown"),
            "vlan": "",
            "duplex": "",
            "speed": speed,
            "type": "SNMP IF-MIB",
            "in_errors": walks["in_errors"].get(index, "0"),
            "out_errors": walks["out_errors"].get(index, "0"),
        })
    return ports


def _scale_value(raw_value, scale, precision):
    scale_factors = {-8: 1e-24, -7: 1e-21, -6: 1e-18, -5: 1e-15, -4: 1e-12, -3: 1e-9, -2: 1e-6, -1: 1e-3, 0: 1, 1: 1e3, 2: 1e6, 3: 1e9, 4: 1e12, 5: 1e15, 6: 1e18, 7: 1e21, 8: 1e24}
    try:
        return float(raw_value) * scale_factors.get(int(scale), 1) * (10 ** (-int(precision)))
    except (TypeError, ValueError):
        return None


async def snmp_sensors(sw):
    names = {_idx(o, ENT_PHYSICAL_NAME): v for o, v in await snmp_walk(sw, ENT_PHYSICAL_NAME)}
    data = {}
    for key, oid in [("type", ENT_SENSOR_TYPE), ("scale", ENT_SENSOR_SCALE), ("precision", ENT_SENSOR_PRECISION), ("value", ENT_SENSOR_VALUE), ("status", ENT_SENSOR_STATUS)]:
        try:
            data[key] = {_idx(o, oid): v for o, v in await snmp_walk(sw, oid)}
        except Exception:
            data[key] = {}
    sensors = []
    for idx, sensor_type in data.get("type", {}).items():
        # ENTITY-SENSOR-MIB celsius(8)
        if sensor_type != "8":
            continue
        value = _scale_value(data["value"].get(idx), data["scale"].get(idx, "0"), data["precision"].get(idx, "0"))
        if value is None:
            continue
        sensors.append({"name": names.get(idx, f"Sensor {idx}"), "celsius": round(value, 1), "status": data["status"].get(idx, "")})
    return sensors


async def snmp_poe(sw):
    consumption = []
    detections = []
    try:
        consumption = [int(float(v)) for _, v in await snmp_walk(sw, POE_MAIN_CONSUMPTION) if str(v).replace('.', '', 1).isdigit()]
    except Exception:
        consumption = []
    try:
        detections = [v for _, v in await snmp_walk(sw, POE_PORT_DETECTION)]
    except Exception:
        detections = []
    # detectionStatus deliveringPower(3) in POWER-ETHERNET-MIB.
    delivering = sum(1 for v in detections if v == "3")
    return {"consumption_w": sum(consumption), "ports_delivering": delivering, "ports_seen": len(detections)}


async def snmp_metrics(sw):
    health = await snmp_health(sw)
    cpu_values, used_values, free_values = [], [], []
    for oid, target in [(VENDOR_CPU_5S, cpu_values), (VENDOR_MEM_USED, used_values), (VENDOR_MEM_FREE, free_values)]:
        try:
            for _, value in await snmp_walk(sw, oid):
                try:
                    target.append(float(value))
                except ValueError:
                    pass
        except Exception:
            pass
    cpu = round(max(cpu_values), 1) if cpu_values else None
    mem_used = sum(used_values) if used_values else 0
    mem_free = sum(free_values) if free_values else 0
    mem_pct = round((mem_used / (mem_used + mem_free)) * 100, 1) if (mem_used + mem_free) else None
    try:
        sensors = await snmp_sensors(sw)
    except Exception:
        sensors = []
    try:
        poe = await snmp_poe(sw)
    except Exception:
        poe = {"consumption_w": 0, "ports_delivering": 0, "ports_seen": 0}
    return {
        **health,
        "cpu_percent": cpu,
        "memory_percent": mem_pct,
        "memory_used_bytes": int(mem_used) if mem_used else None,
        "memory_free_bytes": int(mem_free) if mem_free else None,
        "temperature": sensors,
        "poe": poe,
    }
