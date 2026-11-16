# Pi4-NDR-Sensor 🛡️📡

**A Lightweight Network Detection & Response (NDR) Sensor for Raspberry Pi 4 (4GB RAM)**  
*Engineered by [Vasilis Tsiamouras](https://www.linkedin.com/in/vasilis-tsiamouras/)*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Hardware](https://img.shields.io/badge/Hardware-Raspberry%20Pi%204B%20(4GB)-C51A4A.svg)](https://www.raspberrypi.com/)
[![IDS Engine](https://img.shields.io/badge/NIDS-Suricata%20AF__PACKET-orange.svg)](https://suricata.io)
[![NSM Telemetry](https://img.shields.io/badge/NSM-Zeek%20Telemetry-7B1FA2.svg)](https://zeek.org)
[![SOAR Pipeline](https://img.shields.io/badge/SOAR-Aegis--SOAR%20Ready-00A4E4.svg)](https://github.com/Unskilled0ne/aegis-soar)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📌 Executive Summary

**Pi4-NDR-Sensor** is an enterprise-grade, low-overhead passive **Network Detection & Response (NDR)** sensor engineered specifically for the Raspberry Pi 4 (4GB RAM). It delivers continuous network security monitoring (NSM) by combining **Suricata** (signature-based intrusion detection) and **Zeek** (protocol-level metadata logging) with a dedicated, lightweight Python log forwarder.

The sensor passively monitors network traffic via a switch **SPAN / mirror port**, standardizes heterogeneous alert feeds into a unified JSON schema, and ships batched telemetry over HTTPS to an external SOAR pipeline (such as [Aegis-SOAR](https://github.com/Unskilled0ne/aegis-soar)), where alerts can be correlated with honeypot detections from [ShadowPot](https://github.com/Unskilled0ne/shadowpot).

---

## 🏗️ Architecture & Data Flow

```
                     [ Network Traffic (Managed Switch SPAN / Mirror Port) ]
                                                │
                                                ▼ (Passive RX Only, Promiscuous Mode)
                                  ┌───────────────────────────┐
                                  │   Raspberry Pi 4B (4GB)   │
                                  │   Interface: eth0 (promisc│
                                  └─────────────┬─────────────┘
                                                │
                       ┌────────────────────────┴────────────────────────┐
                       ▼                                                 ▼
             ┌───────────────────┐                             ┌───────────────────┐
             │     Suricata      │                             │       Zeek        │
             │ AF_PACKET Engine  │                             │ Protocol Analyzer │
             │ (Pinned Core 1)   │                             │ (Lightweight Site)│
             └─────────┬─────────┘                             └─────────┬─────────┘
                       │                                                 │
                       ▼                                                 ▼
             ┌───────────────────┐                             ┌───────────────────┐
             │     eve.json      │                             │   *.log (JSON)    │
             │  (Suricata Alert) │                             │(dns/ssl/http/notic│
             └─────────┬─────────┘                             └─────────┬─────────┘
                       │                                                 │
                       └────────────────────────┬────────────────────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │  NDR Log Forwarder    │
                                    │  (ndr_sensor daemon)  │
                                    │   - State / Offsets   │
                                    │   - Schema Normalizer │
                                    │   - Adaptive Batching │
                                    └───────────┬───────────┘
                                                │
                                                ▼ HTTPS POST (JSON Batches)
                                    ┌───────────────────────┐
                                    │ Aegis-SOAR Pipeline   │
                                    │ (/alerts/investigate) │
                                    └───────────┬───────────┘
                                                │
                                                ▼ (Correlation Key: src_ip, timestamp window)
                                    ┌───────────────────────┐
                                    │  ShadowPot Honeypot   │
                                    │  Telemetry Feed       │
                                    └───────────────────────┘
```

---

## ⚡ Key Engineering Highlights

- **Hardware-Conscious Memory Budget (< 3.0 GB RAM total):**
  - **Suricata:** Configured with single-worker `AF_PACKET` ring buffers, memory-capped flow/stream reassembly tables, and pinned to CPU Core 1.
  - **Trimmed Ruleset:** Automated rule optimizer (`deploy/rules_pruner.py`) trims the 35,000+ rule ET Open set down to ~3,000 high-priority exploit, malware, scan, and web rules, avoiding multi-gigabyte memory inflation.
  - **Zeek:** Custom `local.zeek` policy disables memory-intensive enterprise protocol analyzers (SMB, Kerberos, DCE-RPC, Radius) and uses JSON output format.
  - **Forwarder Daemon:** Consumes less than **40 MB RAM**, replacing heavyweight forwarders like Filebeat or Logstash.
- **Rotation-Aware State Persistence:**  
  The log tailer automatically detects log rotations (inode changes) and file truncations, maintaining offset markers in `offset_state.json` to guarantee zero duplicate alerts and zero missing logs across reboots.
- **MicroSD Preservation via External Storage:**  
  Includes automated storage provisioning (`deploy/setup_storage.sh`) to route high-write directories (`/var/log/suricata` and `/var/log/zeek`) onto an external USB3 SSD or hard drive with daily compression logrotate scripts.
- **Dual Dispatch Modes:**  
  - `ndr_spec`: Emits the normalized 10-field telemetry schema defined in the architecture specification.
  - `aegis_soar`: Formats events directly into native `SecurityAlert` models for automated triage by [Aegis-SOAR](https://github.com/Unskilled0ne/aegis-soar).

---

## 📊 Normalized Telemetry Schema (§5 Specification)

Every captured alert and protocol event is normalized to the following standard schema:

```json
{
  "sensor_id": "pi4-ndr-01",
  "source": "suricata",
  "event_type": "alert",
  "timestamp": "2026-11-16T10:32:00Z",
  "src_ip": "198.51.100.44",
  "dest_ip": "192.168.1.100",
  "src_port": 54210,
  "dest_port": 80,
  "proto": "tcp",
  "severity": "high",
  "signature": "ET MALWARE Known Malicious User-Agent Detected",
  "raw": {
    "flow_id": 1829384910293,
    "community_id": "1:9J0aBzC9wQe4x4mZ1Pr==",
    "http": {
      "hostname": "internal.apexfin.corp",
      "url": "/login.php?id=1",
      "http_user_agent": "sqlmap/1.6#stable"
    }
  }
}
```

---

## ⚙️ Resource Budget & Tuning (Raspberry Pi 4 4GB)

| Component | RAM Budget (Target) | CPU Allocation | Optimization Applied |
| :--- | :--- | :--- | :--- |
| **Raspberry Pi OS (Lite)** | ~350 MB | Core 0 | Headless 64-bit ARM, unused daemons disabled |
| **Suricata IDS** | ~600 MB – 950 MB | Core 1 | AF_PACKET, flow memcap 128MB, 3,500 active rules |
| **Zeek Telemetry** | ~600 MB – 1.1 GB | Core 2, 3 | Disabled SMB/RPC analyzers, table expire = 30s |
| **NDR Forwarder** | ~35 MB – 50 MB | Dynamic | Async batching queue, zero-copy tailing |
| **System Headroom** | **~1.0 GB+ Free** | — | Prevents Linux OOM-killer invocations |

---

## 🚀 Quickstart & Deployment

### 1. Automated Installation
Clone the repository onto the Raspberry Pi 4 running Raspberry Pi OS Lite (64-bit):

```bash
git clone https://github.com/Unskilled0ne/pi4-ndr-sensor.git /opt/pi4-ndr-sensor
cd /opt/pi4-ndr-sensor
sudo ./deploy/install.sh
```

### 2. Configure SOAR Destination
Edit `/etc/pi4-ndr/forwarder.yaml`:

```yaml
sensor:
  id: "pi4-ndr-01"

forwarding:
  endpoint_url: "http://<SOAR_HOST>:8000/api/v1/alerts/investigate"
  mode: "aegis_soar"
  batch_size: 50
  flush_interval_seconds: 2.0
```

### 3. Mount External Storage (Optional but Recommended)
If an external USB drive or SSD labeled `LOOT` is connected:

```bash
sudo ./deploy/setup_storage.sh LOOT
```

### 4. Start the NDR Pipeline
```bash
sudo systemctl start promiscuous-tap
sudo systemctl start suricata
sudo systemctl start pi4-ndr-forwarder
```

---

## 🧪 Testing & Verification

The repository includes a standalone test harness to validate log parsing, batch dispatch, and SOAR triage:

```bash
# 1. Run full unit and integration test suite
python3 -m pytest tests/ -v

# 2. Test configuration syntax
python3 run_forwarder.py test-config -c config/forwarder.yaml

# 3. Spin up local mock SOAR endpoint
python3 scripts/mock_soar_server.py 8000 &

# 4. Generate synthetic Suricata and Zeek alerts
python3 scripts/test_traffic_generator.py /tmp/test_eve.json /tmp/test_zeek
```

---

## 🛡️ Integration with Aegis-SOAR & ShadowPot

When deployed alongside **ShadowPot** and **Aegis-SOAR**, this sensor completes the perimeter detection and automated response loop:

1. **Passive Detection:** `pi4-ndr-sensor` detects anomalous traffic or exploit attempts on the network perimeter.
2. **Honeypot Correlation:** If the same `src_ip` triggers both an NDR perimeter alert and interacts with an internal `shadowpot` instance within a 1-hour window, `aegis-soar` escalates the investigation confidence to **100% (High-Confidence True Positive)**.
3. **Automated Containment:** `aegis-soar` triggers the firewall block playbook, isolating the attacker before lateral movement occurs.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.  
Copyright (c) 2026 Vasilis Tsiamouras.
