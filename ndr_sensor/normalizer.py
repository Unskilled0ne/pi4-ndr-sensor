import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from ndr_sensor.models import NDREvent

logger = logging.getLogger("ndr_sensor.normalizer")


def parse_iso_or_epoch(val: Any) -> str:
    """Safely converts epoch float/int or ISO string to ISO-8601 UTC string."""
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    if isinstance(val, str):
        if "T" in val or "-" in val:
            return val
        try:
            epoch = float(val)
            return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat()


def map_suricata_severity(raw_sev: Any) -> str:
    """
    Maps Suricata integer severity (1 = high/critical, 2 = medium/high, 3 = medium, 4 = info)
    to normalized scale: low, medium, high, critical.
    """
    try:
        s = int(raw_sev)
        if s == 1:
            return "critical"
        elif s == 2:
            return "high"
        elif s == 3:
            return "medium"
        return "low"
    except (ValueError, TypeError):
        return "low"


def normalize_suricata(
    line: str,
    sensor_id: str = "pi4-ndr-01",
    allowed_types: Optional[List[str]] = None
) -> Optional[NDREvent]:
    """
    Parses a Suricata eve.json record and normalizes it to the NDR spec schema.
    """
    line = line.strip()
    if not line:
        return None

    try:
        record: Dict[str, Any] = json.loads(line)
    except json.JSONDecodeError:
        logger.debug("Failed to decode JSON from Suricata line: %s", line[:80])
        return None

    event_type = record.get("event_type", "unknown").lower()
    if allowed_types and event_type not in allowed_types:
        return None

    valid_types = {"alert", "conn", "dns", "http", "ssl", "notice", "flow", "tls"}
    normalized_type = event_type if event_type in valid_types else "alert"

    timestamp = parse_iso_or_epoch(record.get("timestamp"))
    src_ip = record.get("src_ip")
    dest_ip = record.get("dest_ip")
    src_port = record.get("src_port")
    dest_port = record.get("dest_port")
    proto = record.get("proto", "tcp").lower()

    signature = None
    severity = "low"

    if event_type == "alert":
        alert_data = record.get("alert", {})
        raw_sev = alert_data.get("severity", 3)
        severity = map_suricata_severity(raw_sev)
        signature = alert_data.get("signature")

    return NDREvent(
        sensor_id=sensor_id,
        source="suricata",
        event_type=normalized_type,
        timestamp=timestamp,
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=dest_port,
        proto=proto,
        severity=severity,
        signature=signature,
        raw=record
    )


def normalize_zeek(
    log_name: str,
    line: str,
    sensor_id: str = "pi4-ndr-01"
) -> Optional[NDREvent]:
    """
    Parses a Zeek log line (JSON or TSV) and normalizes it to the NDR spec schema.
    Supported logs: conn.log, dns.log, http.log, ssl.log, notice.log.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    record: Dict[str, Any] = {}
    if line.startswith("{") and line.endswith("}"):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None
    else:
        # Basic TSV fallback if LogAscii::use_json is not active
        parts = line.split("\t")
        record = {"raw_tsv": parts}

    base_name = log_name.split(".")[0].lower()
    type_map = {
        "conn": "conn",
        "dns": "dns",
        "http": "http",
        "ssl": "ssl",
        "notice": "notice"
    }
    event_type = type_map.get(base_name, "conn")

    timestamp = parse_iso_or_epoch(record.get("ts"))
    src_ip = record.get("id.orig_h") or record.get("orig_h")
    dest_ip = record.get("id.resp_h") or record.get("resp_h")
    src_port = record.get("id.orig_p") or record.get("orig_p")
    dest_port = record.get("id.resp_p") or record.get("resp_p")
    proto = str(record.get("proto", "tcp")).lower()

    signature = None
    severity = "low"

    if event_type == "notice":
        signature = record.get("note") or record.get("msg")
        action = str(record.get("actions", ""))
        sub = str(record.get("sub", ""))

        # Check notice keywords to elevate severity
        check_text = f"{signature} {action} {sub}".lower()
        if any(w in check_text for w in ["drop", "alarm", "attack", "exploit", "critical"]):
            severity = "critical"
        elif any(w in check_text for w in ["scan", "brute", "violation", "suspicious"]):
            severity = "high"
        else:
            severity = "medium"

    return NDREvent(
        sensor_id=sensor_id,
        source="zeek",
        event_type=event_type,
        timestamp=timestamp,
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=dest_port,
        proto=proto,
        severity=severity,
        signature=signature,
        raw=record
    )
