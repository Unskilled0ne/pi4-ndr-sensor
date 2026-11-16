import os
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest

from ndr_sensor.config import AppConfig
from ndr_sensor.forwarder import LogForwarder
from scripts.test_traffic_generator import (
    generate_synthetic_suricata_alert,
    generate_synthetic_zeek_logs
)


class MockServerHandler(BaseHTTPRequestHandler):
    received_requests = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)
        payload = json.loads(data.decode("utf-8"))
        MockServerHandler.received_requests.append(payload)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_server():
    MockServerHandler.received_requests.clear()
    server = HTTPServer(("127.0.0.1", 0), MockServerHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/api/v1/alerts/investigate"
    server.shutdown()


def test_end_to_end_pipeline(tmp_path, mock_server):
    eve_file = tmp_path / "eve.json"
    zeek_dir = tmp_path / "zeek"
    offset_file = tmp_path / "offset.json"

    generate_synthetic_suricata_alert(str(eve_file))
    generate_synthetic_zeek_logs(str(zeek_dir))

    config = AppConfig()
    config.sensor.id = "test-pi4-ndr"
    config.state.offset_file = str(offset_file)
    config.logs.suricata.enabled = True
    config.logs.suricata.path = str(eve_file)
    config.logs.zeek.enabled = True
    config.logs.zeek.dir = str(zeek_dir)
    config.logs.zeek.files = ["dns.log", "notice.log"]
    config.forwarding.endpoint_url = mock_server
    config.forwarding.mode = "aegis_soar"
    config.forwarding.batch_size = 10
    config.filters.zeek_forward_dns = True
    config.filters.zeek_forward_notice = True

    forwarder = LogForwarder(config)

    new_count = forwarder.poll_once()
    assert new_count >= 2

    forwarder.flush()

    assert len(MockServerHandler.received_requests) >= 2
    alert_sources = [r.get("source") for r in MockServerHandler.received_requests]
    assert "ndr-suricata" in alert_sources
    assert "ndr-zeek" in alert_sources

    assert os.path.exists(str(offset_file))
