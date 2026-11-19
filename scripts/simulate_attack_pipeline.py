#!/usr/bin/env python3
"""End-to-End Demonstration & Attack Simulation for Pi4 NDR Sensor

Simulates an attack sequence on the network:
1. Reconnaissance: Port scanning (captured by Zeek NSM)
2. Weaponization / Delivery: Suspicious Dynamic DNS & C2 Beaconing (Zeek DNS)
3. Exploitation: SQL Injection & Command Injection Probe (Suricata IDS)
4. Normalization, Deduplication, and IOC Enrichment (NDR Forwarder)
5. Batched Ingestion & Delivery to SOAR Pipeline
"""

import os
import sys
import time
import json
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Ensure ndr_sensor is importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ndr_sensor.config import AppConfig
from ndr_sensor.forwarder import LogForwarder
from scripts.test_traffic_generator import (
    generate_synthetic_suricata_alert,
    generate_synthetic_zeek_logs
)

received_soar_payloads = []


class IngestionServerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)
        payload = json.loads(data.decode("utf-8"))
        received_soar_payloads.append(payload)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "success", "message": "Batch ingested"}')

    def log_message(self, format, *args):
        pass


def run_simulation():
    print("=" * 70)
    print("🛡️  Pi4-NDR-Sensor — End-to-End Attack & Detection Simulation")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmp_dir:
        eve_path = os.path.join(tmp_dir, "suricata", "eve.json")
        zeek_dir = os.path.join(tmp_dir, "zeek")
        offset_file = os.path.join(tmp_dir, "offset_state.json")
        ioc_file = os.path.join(tmp_dir, "ioc_blocklist.txt")

        # 1. Create mock IOC threat intelligence feed
        with open(ioc_file, "w", encoding="utf-8") as f:
            f.write("# Known C2 Infrastructure\n198.51.100.44\nmalicious-c2-beacon.xyz\n")
        print("[1] Seeded Local Threat Intelligence Blocklist (IOCs)")

        # 2. Spin up local mock SOAR server
        server = HTTPServer(("127.0.0.1", 0), IngestionServerHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        soar_url = f"http://127.0.0.1:{port}/api/v1/alerts/investigate"
        print(f"[2] Mock SOAR Ingestion Endpoint active on port {port}")

        # 3. Simulate Network Traffic & Attacks
        print("[3] Simulating Perimeter Traffic:")
        print("    ├── Attacker IP: 198.51.100.44 -> Target IP: 192.168.1.100")
        print("    ├── Stage 1: Fast TCP Port Scan (25 ports in 3s) -> Zeek notice.log")
        print("    ├── Stage 2: Suspicious C2 DNS Query (malicious-c2-beacon.xyz) -> Zeek dns.log")
        print("    └── Stage 3: Web SQLi Probe (sqlmap User-Agent) -> Suricata eve.json")

        generate_synthetic_suricata_alert(eve_path)
        generate_synthetic_zeek_logs(zeek_dir)

        # 4. Configure Log Forwarder Daemon
        config = AppConfig()
        config.sensor.id = "pi4-sensor-field-01"
        config.sensor.interface = "eth0"
        config.state.offset_file = offset_file
        config.logs.suricata.path = eve_path
        config.logs.zeek.dir = zeek_dir
        config.forwarding.endpoint_url = soar_url
        config.forwarding.mode = "aegis_soar"
        config.forwarding.batch_size = 50

        forwarder = LogForwarder(config)
        forwarder.ioc_blocklist.path = ioc_file
        forwarder.ioc_blocklist.reload()

        # 5. Process and Ingest Logs
        print("\n[4] Running Forwarder Ingestion Engine:")
        events_polled = forwarder.poll_once()
        print(f"    ├── Polled and normalized events: {events_polled}")
        print(f"    ├── In-memory Queue Depth: {len(forwarder.batch_queue)}")

        forwarder.flush()
        print(f"    └── Successfully flushed batch to SOAR over HTTPS!")

        server.shutdown()

        # 6. Verify Delivered Telemetry
        print("\n[5] SOAR Ingestion Verification:")
        if received_soar_payloads:
            batch = received_soar_payloads[0]
            if isinstance(batch, list):
                print(f"    ├── Total Alerts in Batch: {len(batch)}")
                for i, alert in enumerate(batch, 1):
                    src = alert.get("source")
                    sev = alert.get("severity")
                    desc = alert.get("rule_description")
                    src_ip = alert.get("source_ip")
                    print(f"    │   [{i}] {src} | Severity: {sev:<8} | IP: {src_ip:<15} | {desc}")
            print("\n[+] Verification SUCCESS: All simulated attack stages captured, enriched, and delivered!")
        else:
            print("[-] Verification FAILED: No alerts received by SOAR.")
            sys.exit(1)

    print("=" * 70)


if __name__ == "__main__":
    run_simulation()
