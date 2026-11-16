import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Literal, List
from pydantic import BaseModel, Field

SAFE_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9.\-]+(:[0-9]{1,5})?$")
SAFE_URL_PATTERN = re.compile(r"^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")


class NDREvent(BaseModel):
    sensor_id: str = "pi4-ndr-01"
    source: Literal["suricata", "zeek"]
    event_type: Literal["alert", "conn", "dns", "http", "ssl", "notice", "flow", "tls"]
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = "tcp"
    severity: Literal["low", "medium", "high", "critical"] = "low"
    signature: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)

    def to_aegis_alert(self) -> Dict[str, Any]:
        alert_id = f"NDR-{uuid.uuid4().hex[:8].upper()}"
        soar_severity = self.severity.upper()

        rule_id = None
        if self.source == "suricata":
            sig_id = self.raw.get("alert", {}).get("signature_id")
            rule_id = str(sig_id) if sig_id is not None else "SURICATA-ALERT"
        elif self.source == "zeek":
            rule_id = f"ZEEK-{self.event_type.upper()}"

        description = self.signature or f"[{self.source.upper()}:{self.event_type.upper()}] Telemetry"

        extracted_urls = []
        if self.event_type == "http":
            hostname = self.raw.get("http", {}).get("hostname") or self.raw.get("host")
            uri = self.raw.get("http", {}).get("url") or self.raw.get("uri", "/")
            if hostname and isinstance(hostname, str) and isinstance(uri, str):
                cleaned_host = re.sub(r"[\r\n\t]", "", hostname).strip()
                cleaned_uri = re.sub(r"[\r\n\t]", "", uri).strip()
                if not cleaned_uri.startswith("/"):
                    cleaned_uri = f"/{cleaned_uri}"
                if SAFE_HOST_PATTERN.match(cleaned_host):
                    candidate_url = f"http://{cleaned_host}{cleaned_uri}"
                    if SAFE_URL_PATTERN.match(candidate_url) and len(candidate_url) <= 2048:
                        extracted_urls.append(candidate_url)

        return {
            "alert_id": alert_id,
            "source": f"ndr-{self.source}",
            "timestamp": self.timestamp,
            "event_type": f"ndr_{self.event_type}",
            "severity": soar_severity,
            "rule_id": rule_id,
            "rule_description": description,
            "source_ip": self.src_ip,
            "destination_ip": self.dest_ip,
            "target_host": self.dest_ip,
            "extracted_urls": extracted_urls,
            "raw_log": str(self.raw),
            "metadata": {
                "sensor_id": self.sensor_id,
                "src_port": self.src_port,
                "dest_port": self.dest_port,
                "protocol": self.proto,
                "ndr_signature": self.signature,
                "community_id": self.raw.get("community_id")
            }
        }
