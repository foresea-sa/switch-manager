from pydantic import BaseModel, Field


class SwitchCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=120)
    management_ip: str = Field(min_length=1, max_length=64)
    site: str = Field(min_length=1, max_length=120)
    platform: str = "cisco_ios"
    protocol: str = "telnet"
    port: int | None = None
    username: str = ""
    password: str = ""
    secret: str = ""
    snmp_version: str = "v2c"
    snmp_port: int = 161
    snmp_community: str = ""
    snmp_v3_user: str = ""
    snmp_v3_auth_key: str = ""
    snmp_v3_priv_key: str = ""
    snmp_v3_auth_protocol: str = "SHA"
    snmp_v3_priv_protocol: str = "AES"
    monitor_method: str = "snmp"
    notes: str = ""


class SwitchUpdate(BaseModel):
    hostname: str | None = None
    management_ip: str | None = None
    site: str | None = None
    platform: str | None = None
    protocol: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    secret: str | None = None
    snmp_version: str | None = None
    snmp_port: int | None = None
    snmp_community: str | None = None
    snmp_v3_user: str | None = None
    snmp_v3_auth_key: str | None = None
    snmp_v3_priv_key: str | None = None
    snmp_v3_auth_protocol: str | None = None
    snmp_v3_priv_protocol: str | None = None
    monitor_method: str | None = None
    notes: str | None = None


class CommandRequest(BaseModel):
    command: str = Field(min_length=1, max_length=4000)


class MacSearchRequest(BaseModel):
    mac: str = Field(min_length=4, max_length=32)
    switch_ids: list[int] | None = None


class BannerRequest(BaseModel):
    switch_ids: list[int] = Field(min_length=1)
    banner: str = Field(min_length=1, max_length=4000)
    save_config: bool = False


class ShortcutCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    command: str = Field(min_length=1, max_length=4000)
    description: str = ""


class DiscoveryRequest(BaseModel):
    network: str = Field(min_length=3, max_length=64)
    site: str = Field(default="Descoberta", max_length=120)
    snmp_version: str = "v2c"
    snmp_port: int = 161
    snmp_community: str = ""
    snmp_v3_user: str = ""
    snmp_v3_auth_key: str = ""
    snmp_v3_priv_key: str = ""
    snmp_v3_auth_protocol: str = "SHA"
    snmp_v3_priv_protocol: str = "AES"
    protocol: str = "telnet"
    cli_port: int | None = None
    username: str = ""
    password: str = ""
    secret: str = ""
    add_found: bool = False
