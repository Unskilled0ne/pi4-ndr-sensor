import os
import json
import pytest
from unittest.mock import MagicMock, patch
from ndr_sensor.config import AppConfig, ForwardingConfig
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
        assert payload["source"] == "ndr-suricata"
        assert payload["severity"] == "CRITICAL"
        assert payload["source_ip"] == "1.2.3.4"
        assert payload["destination_ip"] == "5.6.7.8"


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
