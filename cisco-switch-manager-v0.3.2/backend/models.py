from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base


def utcnow():
    return datetime.now(timezone.utc)


class Switch(Base):
    __tablename__ = "switches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    management_ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    site: Mapped[str] = mapped_column(String(120), index=True)
    platform: Mapped[str] = mapped_column(String(80), default="cisco_ios")

    # CLI: Telnet remains the operational default for this environment.
    protocol: Mapped[str] = mapped_column(String(10), default="telnet")
    port: Mapped[int] = mapped_column(Integer, default=23)
    username_enc: Mapped[str] = mapped_column(Text, default="")
    password_enc: Mapped[str] = mapped_column(Text, default="")
    secret_enc: Mapped[str] = mapped_column(Text, default="")

    # Monitoring: SNMPv2c default, SNMPv3 optional per switch.
    snmp_version: Mapped[str] = mapped_column(String(10), default="v2c")
    snmp_port: Mapped[int] = mapped_column(Integer, default=161)
    snmp_community_enc: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_user_enc: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_auth_key_enc: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_priv_key_enc: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_auth_protocol: Mapped[str] = mapped_column(String(20), default="SHA")
    snmp_v3_priv_protocol: Mapped[str] = mapped_column(String(20), default="AES")
    monitor_method: Mapped[str] = mapped_column(String(20), default="snmp")

    model: Mapped[str] = mapped_column(String(120), default="")
    serial: Mapped[str] = mapped_column(String(120), default="")
    ios_version: Mapped[str] = mapped_column(String(120), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    is_online: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status_source: Mapped[str] = mapped_column(String(20), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Shortcut(Base):
    __tablename__ = "shortcuts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    command: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int | None] = mapped_column(ForeignKey("switches.id"), nullable=True)
    hostname: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(120))
    portal_user: Mapped[str] = mapped_column(String(120), default="")
    operator_user: Mapped[str] = mapped_column(String(120), default="")
    command: Mapped[str] = mapped_column(Text, default="")
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AvailabilitySample(Base):
    __tablename__ = "availability_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("switches.id"), index=True)
    online: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(20), default="")
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class InterfaceSample(Base):
    __tablename__ = "interface_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("switches.id"), index=True)
    port: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    admin_status: Mapped[str] = mapped_column(String(32), default="unknown")
    speed: Mapped[str] = mapped_column(String(40), default="")
    description: Mapped[str] = mapped_column(String(240), default="")
    in_errors: Mapped[int] = mapped_column(Integer, default=0)
    out_errors: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(20), default="snmp")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
