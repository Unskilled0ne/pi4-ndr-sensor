#!/usr/bin/env python3
"""
Synthetic Telemetry Generator for NDR Testing
Simulates Suricata eve.json alerts and Zeek protocol logs to verify the
normalization pipeline, batch queue, and forwarder without requiring a physical SPAN port.
"""

import os
import sys
import time
import json
from datetime import datetime, timezone


def generate_synthetic_suricata_alert(eve_file_path: str):
    alert_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "flow_id": 1829384910293,
        "event_type": "alert",
        "src_ip": "198.51.100.44",
        "src_port": 54210,
        "dest_ip": "192.168.1.100",
        "dest_port": 80,
        "proto": "TCP",
        "community_id": "1:9J0aBzC9wQe4x4mZ1Pr==",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000004,
            "rev": 1,
            "signature": "ET MALWARE Known Malicious User-Agent Detected (sqlmap probe)",
            "category": "Attempted Information Leak",
            "severity": 2
        },
        "http": {
            "hostname": "internal.apexfin.corp",
            "url": "/login.php?id=1%20UNION%20SELECT%20null,null--",
            "http_user_agent": "sqlmap/1.6#stable",
            "http_method": "GET",
            "protocol": "HTTP/1.1",
            "status": 200
        }
    }

    os.makedirs(os.path.dirname(eve_file_path), exist_ok=True)
    with open(eve_file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert_record) + "\n")
    print(f"[✔] Appended synthetic Suricata alert -> {eve_file_path}")


def generate_synthetic_zeek_logs(zeek_dir: str):
    os.makedirs(zeek_dir, exist_ok=True)
    ts = time.time()

    # 1. DNS Log
    dns_record = {
        "ts": ts,
        "uid": "CHz6341SZk",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 59124,
        "id.resp_h": "1.1.1.1",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "malicious-c2-beacon.xyz",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
        "answers": ["198.51.100.44"]
    }
    with open(os.path.join(zeek_dir, "dns.log"), "a", encoding="utf-8") as f:
        f.write(json.dumps(dns_record) + "\n")

    # 2. Notice Log
    notice_record = {
        "ts": ts,
        "note": "Scan::Port_Scan",
        "msg": "198.51.100.44 scanned at least 25 unique ports of host 192.168.1.100 in 0m3s",
        "sub": "port scan",
        "id.orig_h": "198.51.100.44",
        "id.resp_h": "192.168.1.100",
        "actions": ["Notice::ACTION_LOG"]
    }
    with open(os.path.join(zeek_dir, "notice.log"), "a", encoding="utf-8") as f:
        f.write(json.dumps(notice_record) + "\n")

    print(f"[✔] Appended synthetic Zeek DNS and Notice logs -> {zeek_dir}")


def main():
    eve_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/pi4_test/eve.json"
    zeek_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp/pi4_test/zeek"

    generate_synthetic_suricata_alert(eve_path)
    generate_synthetic_zeek_logs(zeek_dir)


if __name__ == "__main__":
    main()
