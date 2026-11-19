import json
import urllib.request
import pytest
from unittest.mock import MagicMock
from ndr_sensor.config import AppConfig
from ndr_sensor.forwarder import LogForwarder
from ndr_sensor.health import start_health_server
from ndr_sensor.top import format_bytes, format_uptime, draw_bar, fetch_health_data, render_dashboard


def test_health_endpoint(tmp_path):
    config = AppConfig()
    config.sensor.id = "health-test-sensor"
    config.state.offset_file = str(tmp_path / "offset.json")
    config.logs.suricata.enabled = False
    config.logs.zeek.enabled = False

    forwarder = LogForwarder(config)
    forwarder.is_running = True

    server = start_health_server(forwarder, host="127.0.0.1", port=0)
    port = server.server_port

    try:
        url = f"http://127.0.0.1:{port}/health"
        with urllib.request.urlopen(url) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["sensor_id"] == "health-test-sensor"
            assert "metrics" in data
            assert "nic_stats" in data
            assert "uptime_seconds" in data
            assert "queue_depth" in data

        # Test 404 for other endpoints
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/invalid"):
                pass
        except urllib.error.HTTPError as e:
            assert e.code == 404

        # Test top dashboard helpers
        fetched = fetch_health_data(url)
        assert fetched["sensor_id"] == "health-test-sensor"
        render_dashboard(fetched, url)

    finally:
        server.shutdown()


def test_top_formatters():
    assert format_bytes(500) == "500.0 B"
    assert "KB" in format_bytes(2048)
    assert "MB" in format_bytes(10485760)
    assert format_bytes(-1) == "N/A"

    assert "s" in format_uptime(45)
    assert "m" in format_uptime(125)
    assert "h" in format_uptime(7200)

    bar = draw_bar(100, 1000)
    assert "[" in bar and "]" in bar
    assert "%" in bar
