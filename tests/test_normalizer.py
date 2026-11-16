import json
import pytest
from ndr_sensor.normalizer import (
    normalize_suricata,
    normalize_zeek,
    map_suricata_severity,
    parse_iso_or_epoch
)
from ndr_sensor.models import NDREvent


def test_map_suricata_severity():
    assert map_suricata_severity(1) == "critical"
    assert map_suricata_severity("1") == "critical"
    assert map_suricata_severity(2) == "high"
    assert map_suricata_severity(3) == "medium"
    assert map_suricata_severity(4) == "low"
    assert map_suricata_severity(99) == "low"
    assert map_suricata_severity(None) == "low"


def test_parse_iso_or_epoch():
    iso_str = "2026-11-16T10:30:00Z"
    assert parse_iso_or_epoch(iso_str) == iso_str

    epoch = 1700000000.0
    parsed = parse_iso_or_epoch(epoch)
    assert "2023-" in parsed or "T" in parsed


def test_normalize_suricata_alert():
    raw_event = {
        "timestamp": "2026-11-16T12:00:00.000123+0000",
        "flow_id": 123456789,
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "src_port": 49201,
        "dest_ip": "192.168.1.50",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": "ET MALWARE Suspicious User-Agent",
            "signature_id": 2010001,
            "severity": 2
        }
    }

    event = normalize_suricata(json.dumps(raw_event), sensor_id="test-sensor-01")
    assert event is not None
    assert isinstance(event, NDREvent)
    assert event.sensor_id == "test-sensor-01"
    assert event.source == "suricata"
    assert event.event_type == "alert"
    assert event.severity == "high"
    assert event.signature == "ET MALWARE Suspicious User-Agent"
    assert event.src_ip == "10.0.0.5"
    assert event.dest_ip == "192.168.1.50"
    assert event.src_port == 49201
    assert event.dest_port == 80
    assert event.proto == "tcp"

    # Test conversion to Aegis-SOAR format
    soar_alert = event.to_aegis_alert()
    assert soar_alert["source"] == "ndr-suricata"
    assert soar_alert["severity"] == "HIGH"
    assert soar_alert["rule_id"] == "2010001"
    assert soar_alert["rule_description"] == "ET MALWARE Suspicious User-Agent"


def test_normalize_suricata_filtered_types():
    raw_event = {"event_type": "stats", "stats": {}}
    assert normalize_suricata(json.dumps(raw_event), allowed_types=["alert", "dns"]) is None


def test_normalize_suricata_invalid_json():
    assert normalize_suricata("THIS IS NOT JSON {{{") is None
    assert normalize_suricata("") is None


def test_normalize_zeek_dns():
    dns_line = json.dumps({
        "ts": 1700000000.5,
        "uid": "Cdns123",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 54000,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "malicious.test",
        "qtype_name": "A"
    })

    event = normalize_zeek("dns.log", dns_line, sensor_id="test-sensor-01")
    assert event is not None
    assert event.source == "zeek"
    assert event.event_type == "dns"
    assert event.src_ip == "192.168.1.100"
    assert event.dest_ip == "8.8.8.8"
    assert event.src_port == 54000
    assert event.dest_port == 53
    assert event.proto == "udp"
    assert event.severity == "low"


def test_normalize_zeek_notice_escalation():
    notice_line = json.dumps({
        "ts": 1700000000.5,
        "note": "Scan::Port_Scan",
        "msg": "Host scanned 50 ports",
        "actions": ["Notice::ACTION_ALARM"],
        "id.orig_h": "10.10.10.10",
        "id.resp_h": "192.168.1.1"
    })

    event = normalize_zeek("notice.log", notice_line, sensor_id="test-sensor-01")
    assert event is not None
    assert event.source == "zeek"
    assert event.event_type == "notice"
    assert event.severity == "critical"  # contains 'alarm'
    assert event.signature == "Scan::Port_Scan"


def test_normalize_zeek_comment_lines():
    assert normalize_zeek("conn.log", "#separator \\x09") is None
    assert normalize_zeek("conn.log", "#fields ts uid id.orig_h") is None
    assert normalize_zeek("conn.log", "") is None
