from sqlalchemy import inspect, text
from .db import engine


def migrate_legacy_db():
    inspector = inspect(engine)
    if "switches" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("switches")}
    additions = {
        "snmp_version": "VARCHAR(10) DEFAULT 'v2c'",
        "snmp_port": "INTEGER DEFAULT 161",
        "snmp_community_enc": "TEXT DEFAULT ''",
        "snmp_v3_user_enc": "TEXT DEFAULT ''",
        "snmp_v3_auth_key_enc": "TEXT DEFAULT ''",
        "snmp_v3_priv_key_enc": "TEXT DEFAULT ''",
        "snmp_v3_auth_protocol": "VARCHAR(20) DEFAULT 'SHA'",
        "snmp_v3_priv_protocol": "VARCHAR(20) DEFAULT 'AES'",
        "monitor_method": "VARCHAR(20) DEFAULT 'snmp'",
        "last_status_source": "VARCHAR(20) DEFAULT ''",
    }
    with engine.begin() as conn:
        for name, ddl in additions.items():
            if name not in columns:
                conn.execute(text(f"ALTER TABLE switches ADD COLUMN {name} {ddl}"))
        conn.execute(text("UPDATE switches SET snmp_version='v2c' WHERE snmp_version IS NULL OR snmp_version=''"))
        conn.execute(text("UPDATE switches SET snmp_port=161 WHERE snmp_port IS NULL OR snmp_port=0"))
        conn.execute(text("UPDATE switches SET monitor_method='snmp' WHERE monitor_method IS NULL OR monitor_method=''"))
        conn.execute(text("UPDATE switches SET snmp_v3_auth_protocol='SHA' WHERE snmp_v3_auth_protocol IS NULL OR snmp_v3_auth_protocol=''"))
        conn.execute(text("UPDATE switches SET snmp_v3_priv_protocol='AES' WHERE snmp_v3_priv_protocol IS NULL OR snmp_v3_priv_protocol=''"))
