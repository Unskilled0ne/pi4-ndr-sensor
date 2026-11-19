import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from ndr_sensor.models import NDREvent

logger = logging.getLogger("ndr_sensor.normalizer")
MAX_LINE_BYTES = 524288
IP_CLEAN_REGEX = re.compile(r"[^0-9a-fA-F:.]")


def sanitize_str(val: Any, max_len: int = 256) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    s = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s)
    return s[:max_len] if s else None


def sanitize_ip(val: Any) -> Optional[str]:
    if not val or not isinstance(val, str):
        return None
    cleaned = IP_CLEAN_REGEX.sub("", val).strip()
    return cleaned[:45] if cleaned else None


def parse_iso_or_epoch(val: Any) -> str:
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
    if isinstance(val, str):
        if "T" in val or "-" in val:
            clean = sanitize_str(val, 64)
            if clean:
                return clean
        try:
            epoch = float(val)
            return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
    return datetime.now(timezone.utc).isoformat()


def map_suricata_severity(raw_sev: Any) -> str:
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
    if not line or len(line) > MAX_LINE_BYTES:
        return None

    line = line.strip()
    if not line or not (line.startswith("{") and line.endswith("}")):
        return None

    try:
        record: Dict[str, Any] = json.loads(line)
    except json.JSONDecodeError:
        return None

    event_type = sanitize_str(record.get("event_type", "unknown"), 32)
    if not event_type:
        return None
    event_type = event_type.lower()

    if allowed_types and event_type not in allowed_types:
        return None

    if event_type == "stats":
        capture = record.get("stats", {}).get("capture", {})
        kernel_drops = capture.get("kernel_drops", 0)
        if isinstance(kernel_drops, int) and kernel_drops > 0:
            logger.warning("Suricata kernel drops detected: %d", kernel_drops)
        return None

    valid_types = {"alert", "conn", "dns", "http", "ssl", "notice", "flow", "tls"}
    normalized_type = event_type if event_type in valid_types else "alert"

    timestamp = parse_iso_or_epoch(record.get("timestamp"))
    src_ip = sanitize_ip(record.get("src_ip"))
    dest_ip = sanitize_ip(record.get("dest_ip"))
    src_port = record.get("src_port") if isinstance(record.get("src_port"), int) and 0 <= record.get("src_port") <= 65535 else None
    dest_port = record.get("dest_port") if isinstance(record.get("dest_port"), int) and 0 <= record.get("dest_port") <= 65535 else None
    proto = sanitize_str(record.get("proto", "tcp"), 16) or "tcp"

    signature = None
    severity = "low"

    if event_type == "alert":
        alert_data = record.get("alert")
        if isinstance(alert_data, dict):
            raw_sev = alert_data.get("severity", 3)
            severity = map_suricata_severity(raw_sev)
            signature = sanitize_str(alert_data.get("signature"), 512)

    return NDREvent(
        sensor_id=sanitize_str(sensor_id, 64) or "pi4-ndr-01",
        source="suricata",
        event_type=normalized_type,
        timestamp=timestamp,
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=dest_port,
        proto=proto.lower(),
        severity=severity,
        signature=signature,
        raw=record
    )


def normalize_zeek(
    log_name: str,
    line: str,
    sensor_id: str = "pi4-ndr-01"
) -> Optional[NDREvent]:
    if not line or len(line) > MAX_LINE_BYTES:
        return None

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
    src_ip = sanitize_ip(record.get("id.orig_h") or record.get("orig_h"))
    dest_ip = sanitize_ip(record.get("id.resp_h") or record.get("resp_h"))
    src_port = record.get("id.orig_p") or record.get("orig_p")
    src_port = src_port if isinstance(src_port, int) and 0 <= src_port <= 65535 else None
    dest_port = record.get("id.resp_p") or record.get("resp_p")
    dest_port = dest_port if isinstance(dest_port, int) and 0 <= dest_port <= 65535 else None
    proto = sanitize_str(record.get("proto", "tcp"), 16) or "tcp"

    signature = None
    severity = "low"

    if event_type == "notice":
        signature = sanitize_str(record.get("note") or record.get("msg"), 512)
        action = str(record.get("actions", ""))
        sub = str(record.get("sub", ""))

        check_text = f"{signature} {action} {sub}".lower()
        if any(w in check_text for w in ["drop", "alarm", "attack", "exploit", "critical"]):
            severity = "critical"
        elif any(w in check_text for w in ["scan", "brute", "violation", "suspicious"]):
            severity = "high"
        else:
            severity = "medium"

    return NDREvent(
        sensor_id=sanitize_str(sensor_id, 64) or "pi4-ndr-01",
        source="zeek",
        event_type=event_type,
        timestamp=timestamp,
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=dest_port,
        proto=proto.lower(),
        severity=severity,
        signature=signature,
        raw=record
    )
