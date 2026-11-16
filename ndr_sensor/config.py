import os
import yaml
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class SensorInfo(BaseModel):
    id: str = "pi4-ndr-01"
    description: str = "Raspberry Pi 4 Passive NDR Sensor"
    network_zone: str = "perimeter-tap"


class SuricataLogConfig(BaseModel):
    enabled: bool = True
    path: str = "/var/log/suricata/eve.json"
    types: List[str] = ["alert", "flow", "dns", "http", "tls"]


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


class ForwardingConfig(BaseModel):
    endpoint_url: str = "http://127.0.0.1:8000/api/v1/alerts/investigate"
    mode: str = "aegis_soar"  # "aegis_soar" or "ndr_spec"
    batch_size: int = 50
    flush_interval_seconds: float = 2.0
    timeout_seconds: float = 5.0
    max_retries: int = 3
    backoff_factor: float = 1.5
    auth: AuthConfig = Field(default_factory=AuthConfig)


class FiltersConfig(BaseModel):
    always_forward_alerts: bool = True
    zeek_forward_conn: bool = False
    zeek_forward_dns: bool = True
    zeek_forward_http: bool = True
    zeek_forward_ssl: bool = True
    zeek_forward_notice: bool = True


class StateConfig(BaseModel):
    offset_file: str = "/var/run/pi4-ndr/offset_state.json"


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
