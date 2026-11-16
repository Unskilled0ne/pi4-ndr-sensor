from datetime import datetime, timezone
from typing import Dict, Any, Optional, Literal, List
from pydantic import BaseModel, Field
import uuid


class NDREvent(BaseModel):
    """
    Normalized alert schema defined in Section 5 of the Pi4 NDR Sensor Spec.
    """
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
        """
        Converts the NDR event directly into the Aegis-SOAR SecurityAlert schema
        expected by the /api/v1/alerts/investigate endpoint.
        """
        alert_id = f"NDR-{uuid.uuid4().hex[:8].upper()}"

        # Map severity to Aegis-SOAR format (LOW, MEDIUM, HIGH, CRITICAL)
        soar_severity = self.severity.upper()

        rule_id = None
        if self.source == "suricata":
            rule_id = str(self.raw.get("alert", {}).get("signature_id", "SURICATA-ALERT"))
        elif self.source == "zeek":
            rule_id = f"ZEEK-{self.event_type.upper()}"

        description = self.signature or f"NDR Telemetry Event [{self.source.upper()}:{self.event_type.upper()}]"

        extracted_urls = []
        if self.event_type == "http":
            hostname = self.raw.get("http", {}).get("hostname") or self.raw.get("host")
            uri = self.raw.get("http", {}).get("url") or self.raw.get("uri", "/")
            if hostname:
                extracted_urls.append(f"http://{hostname}{uri}")

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
