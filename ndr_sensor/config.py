import os
import logging
import yaml
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator


class SensorInfo(BaseModel):
    id: str = "pi4-ndr-01"
    description: str = "Raspberry Pi 4 Passive NDR Sensor"
    network_zone: str = "perimeter-tap"
    interface: str = "eth0"


class SuricataLogConfig(BaseModel):
    enabled: bool = True
    path: str = "/var/log/suricata/eve.json"
    types: List[str] = ["alert", "flow", "dns", "http", "tls", "stats"]


class ZeekLogConfig(BaseModel):
    enabled: bool = True
    dir: str = "/var/log/zeek/current"
    files: List[str] = ["conn.log", "dns.log", "http.log", "ssl.log", "notice.log"]


class LogsConfig(BaseModel):
    suricata: SuricataLogConfig = Field(default_factory=SuricataLogConfig)
    zeek: ZeekLogConfig = Field(default_factory=ZeekLogConfig)


class AuthConfig(BaseModel):
    type: str = "bearer"
    token: str = ""
    header_name: str = "Authorization"

    @field_validator("header_name")
    @classmethod
    def sanitize_header_name(cls, v: str) -> str:
        return v.replace("\r", "").replace("\n", "").strip()

    @field_validator("token")
    @classmethod
    def resolve_and_sanitize_token(cls, v: str) -> str:
        v = v.replace("\r", "").replace("\n", "").strip()
        if v.startswith("${") and v.endswith("}"):
            env_var = v[2:-1]
            resolved = os.environ.get(env_var, "")
            if not resolved:
                logging.getLogger("ndr_sensor.config").warning(
                    "Environment variable %s not set for auth token", env_var
                )
            return resolved
        return v


class ForwardingConfig(BaseModel):
    endpoint_url: str = "http://127.0.0.1:8000/api/v1/alerts/investigate"
    mode: str = "aegis_soar"
    batch_size: int = 50
    max_queue_size: int = 5000
    flush_interval_seconds: float = 2.0
    timeout_seconds: float = 5.0
    max_retries: int = 3
    backoff_factor: float = 1.5
    tls_verify: bool = True
    tls_ca_bundle: Optional[str] = None
    auth: AuthConfig = Field(default_factory=AuthConfig)

    @field_validator("endpoint_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        clean = v.strip()
        if not (clean.startswith("http://") or clean.startswith("https://")):
            raise ValueError("endpoint_url must start with http:// or https://")
        return clean


class FiltersConfig(BaseModel):
    always_forward_alerts: bool = True
    suricata_forward_flow: bool = False
    suricata_forward_dns: bool = True
    suricata_forward_http: bool = True
    suricata_forward_tls: bool = True
    zeek_forward_conn: bool = False
    zeek_forward_dns: bool = True
    zeek_forward_http: bool = True
    zeek_forward_ssl: bool = True
    zeek_forward_notice: bool = True
    dedup_window_seconds: float = 60.0


class StateConfig(BaseModel):
    offset_file: str = "/var/lib/pi4-ndr/offset_state.json"


class AppConfig(BaseModel):
    sensor: SensorInfo = Field(default_factory=SensorInfo)
    logs: LogsConfig = Field(default_factory=LogsConfig)
    state: StateConfig = Field(default_factory=StateConfig)
    forwarding: ForwardingConfig = Field(default_factory=ForwardingConfig)
    filters: FiltersConfig = Field(default_factory=FiltersConfig)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "AppConfig":
        if not path:
            search_paths = [
                os.getenv("NDR_CONFIG_PATH"),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "forwarder.yaml"),
                "/etc/pi4-ndr/forwarder.yaml",
                "config/forwarder.yaml"
            ]
            for p in search_paths:
                if p and os.path.exists(p):
                    path = p
                    break

        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return cls(**data)
        return cls()
