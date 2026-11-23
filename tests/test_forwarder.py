import os
import json
import pytest
from unittest.mock import MagicMock, patch
from ndr_sensor.config import AppConfig, ForwardingConfig, AuthConfig
from ndr_sensor.forwarder import LogForwarder
from ndr_sensor.models import NDREvent


def test_forwarder_batching_and_flush(tmp_path):
    config = AppConfig()
    config.state.offset_file = str(tmp_path / "offset.json")
    config.logs.suricata.enabled = False
    config.logs.zeek.enabled = False
    config.forwarding.mode = "ndr_spec"
    config.forwarding.batch_size = 2

    forwarder = LogForwarder(config)

    event1 = NDREvent(
        sensor_id="pi4-01",
        source="suricata",
        event_type="alert",
        severity="medium",
        signature="Test Alert 1"
    )

    with patch.object(forwarder._session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        forwarder.batch_queue.append(event1)
        assert len(forwarder.batch_queue) == 1
        success = forwarder.flush()

        assert success is True
        assert len(forwarder.batch_queue) == 0
        assert forwarder.metrics.batches_sent == 1
        assert forwarder.metrics.events_forwarded == 1
        mock_post.assert_called_once()


def test_forwarder_aegis_soar_mode(tmp_path):
    config = AppConfig()
    config.state.offset_file = str(tmp_path / "offset.json")
    config.logs.suricata.enabled = False
    config.logs.zeek.enabled = False
    config.forwarding.mode = "aegis_soar"

    forwarder = LogForwarder(config)

    event = NDREvent(
        sensor_id="pi4-01",
        source="suricata",
        event_type="alert",
        src_ip="1.2.3.4",
        dest_ip="5.6.7.8",
        severity="critical",
        signature="ET EXPLOIT Critical RCE Probe"
    )

    with patch.object(forwarder._session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        forwarder.batch_queue.append(event)
        success = forwarder.flush()

        assert success is True
        assert forwarder.metrics.events_forwarded == 1
        _, kwargs = mock_post.call_args
        payload = kwargs["json"]
        assert isinstance(payload, list)
        assert len(payload) == 1
        assert payload[0]["source"] == "ndr-suricata"
        assert payload[0]["severity"] == "CRITICAL"
        assert payload[0]["source_ip"] == "1.2.3.4"
        assert payload[0]["destination_ip"] == "5.6.7.8"


def test_forwarder_queue_bounding(tmp_path):
    config = AppConfig()
    config.state.offset_file = str(tmp_path / "offset.json")
    config.logs.suricata.enabled = False
    config.logs.zeek.enabled = False
    config.forwarding.max_queue_size = 3

    forwarder = LogForwarder(config)

    for i in range(5):
        ev = NDREvent(
            sensor_id="pi4-01",
            source="suricata",
            event_type="alert",
            severity="low" if i < 3 else "high",
            signature=f"Alert {i}"
        )
        forwarder._enqueue_event(ev)

    assert len(forwarder.batch_queue) == 3
    assert forwarder.metrics.events_dropped == 2


def test_should_forward_suricata_filtering(tmp_path):
    config = AppConfig()
    config.state.offset_file = str(tmp_path / "offset.json")
    config.logs.suricata.enabled = False
    config.logs.zeek.enabled = False
    config.filters.suricata_forward_flow = False
    config.filters.suricata_forward_dns = False

    forwarder = LogForwarder(config)

    alert_event = NDREvent(source="suricata", event_type="alert", severity="high")
    assert forwarder._should_forward(alert_event) is True

    flow_event = NDREvent(source="suricata", event_type="flow")
    assert forwarder._should_forward(flow_event) is False

    dns_event = NDREvent(source="suricata", event_type="dns")
    assert forwarder._should_forward(dns_event) is False

    http_event = NDREvent(source="suricata", event_type="http")
    assert forwarder._should_forward(http_event) is True


def test_auth_token_env_resolution(monkeypatch):
    monkeypatch.setenv("NDR_AUTH_TOKEN", "s3cret-t0ken-123")
    auth = AuthConfig(type="bearer", token="${NDR_AUTH_TOKEN}")
    assert auth.token == "s3cret-t0ken-123"


def test_auth_token_plain_passthrough():
    auth = AuthConfig(type="bearer", token="plain-token")
    assert auth.token == "plain-token"


def test_alert_deduplication(tmp_path):
    config = AppConfig()
    config.state.offset_file = str(tmp_path / "offset.json")
    config.filters.dedup_window_seconds = 10.0

    forwarder = LogForwarder(config)
    assert forwarder.dedup.is_duplicate("SIG-1", "1.1.1.1", "2.2.2.2") is False
    assert forwarder.dedup.is_duplicate("SIG-1", "1.1.1.1", "2.2.2.2") is True
    assert forwarder.dedup.is_duplicate("SIG-2", "1.1.1.1", "2.2.2.2") is False


def test_dead_letter_dropping_on_max_retries(tmp_path):
    config = AppConfig()
    config.state.offset_file = str(tmp_path / "offset.json")
    config.forwarding.max_retries = 2

    forwarder = LogForwarder(config)
    event = NDREvent(source="suricata", event_type="alert", severity="high")
    forwarder.batch_queue.append(event)

    with patch.object(forwarder._session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp

        # First failure
        assert forwarder.flush() is False
        assert len(forwarder.batch_queue) == 1
        assert forwarder.metrics.events_dropped == 0

        # Second failure (reaches max_retries = 2) -> dropped from queue
        assert forwarder.flush() is False
        assert len(forwarder.batch_queue) == 0
        assert forwarder.metrics.events_dropped == 1


def test_ioc_enrichment(tmp_path):
    ioc_file = tmp_path / "ioc.txt"
    ioc_file.write_text("198.51.100.99\nbad-c2.com\n", encoding="utf-8")

    config = AppConfig()
    config.state.offset_file = str(tmp_path / "offset.json")
    forwarder = LogForwarder(config)
    forwarder.ioc_blocklist.path = str(ioc_file)
    forwarder.ioc_blocklist.reload()

    clean_event = NDREvent(source="suricata", event_type="conn", src_ip="10.0.0.1", severity="low")
    forwarder._enrich_event(clean_event)
    assert clean_event.severity == "low"

    bad_event = NDREvent(source="suricata", event_type="conn", src_ip="198.51.100.99", severity="low")
    forwarder._enrich_event(bad_event)
    assert bad_event.severity == "high"
    assert "[IOC-MATCH]" in (bad_event.signature or "")


def test_endpoint_url_env_override(monkeypatch):
    monkeypatch.setenv("NDR_ENDPOINT_URL", "http://10.42.0.1:8000/api/v1/alerts/investigate")
    cfg = AppConfig.load()
    assert cfg.forwarding.endpoint_url == "http://10.42.0.1:8000/api/v1/alerts/investigate"


def test_endpoint_url_template_resolution(monkeypatch):
    from ndr_sensor.config import ForwardingConfig
    monkeypatch.setenv("CUSTOM_SOAR", "http://192.168.1.50:9000/alerts")
    cfg = ForwardingConfig(endpoint_url="${CUSTOM_SOAR}")
    assert cfg.endpoint_url == "http://192.168.1.50:9000/alerts"

