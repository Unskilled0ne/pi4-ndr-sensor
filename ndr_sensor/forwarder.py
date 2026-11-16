import os
import time
import json
import logging
from typing import List, Dict, Any, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ndr_sensor.config import AppConfig
from ndr_sensor.models import NDREvent
from ndr_sensor.normalizer import normalize_suricata, normalize_zeek
from ndr_sensor.tailer import StateTracker, FileTailer

logger = logging.getLogger("ndr_sensor.forwarder")


class TelemetryMetrics:
    def __init__(self):
        self.events_read: int = 0
        self.events_normalized: int = 0
        self.events_forwarded: int = 0
        self.events_dropped: int = 0
        self.batches_sent: int = 0
        self.dispatch_errors: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "events_read": self.events_read,
            "events_normalized": self.events_normalized,
            "events_forwarded": self.events_forwarded,
            "events_dropped": self.events_dropped,
            "batches_sent": self.batches_sent,
            "dispatch_errors": self.dispatch_errors
        }


class LogForwarder:
    """
    Core daemon engine: coordinates log tailers, schema normalization,
    in-memory batching, and resilient HTTP dispatch to the SOAR pipeline.
    """

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig.load()
        self.metrics = TelemetryMetrics()
        self.state_tracker = StateTracker(self.config.state.offset_file)
        self.tailers: Dict[str, FileTailer] = {}
        self.batch_queue: List[NDREvent] = []
        self.last_flush_time: float = time.time()
        self.is_running: bool = False

        self._session = self._create_http_session()
        self._init_tailers()

    def _create_http_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=self.config.forwarding.max_retries,
            backoff_factor=self.config.forwarding.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _init_tailers(self) -> None:
        # 1. Suricata tailer
        if self.config.logs.suricata.enabled:
            s_path = self.config.logs.suricata.path
            self.tailers["suricata"] = FileTailer(s_path, self.state_tracker)

        # 2. Zeek tailers
        if self.config.logs.zeek.enabled:
            z_dir = self.config.logs.zeek.dir
            for z_file in self.config.logs.zeek.files:
                full_path = os.path.join(z_dir, z_file)
                key = f"zeek:{z_file}"
                self.tailers[key] = FileTailer(full_path, self.state_tracker)

    def _should_forward(self, event: NDREvent) -> bool:
        filters = self.config.filters
        if event.source == "suricata":
            if event.event_type == "alert" and filters.always_forward_alerts:
                return True
            return True

        if event.source == "zeek":
            if event.event_type == "conn":
                return filters.zeek_forward_conn
            if event.event_type == "dns":
                return filters.zeek_forward_dns
            if event.event_type == "http":
                return filters.zeek_forward_http
            if event.event_type == "ssl":
                return filters.zeek_forward_ssl
            if event.event_type == "notice":
                return filters.zeek_forward_notice

        return True

    def poll_once(self) -> int:
        """Polls all active log tailers, normalizes events, and queues them."""
        new_events_count = 0

        # Poll Suricata
        if "suricata" in self.tailers:
            for line in self.tailers["suricata"].read_new_lines():
                self.metrics.events_read += 1
                event = normalize_suricata(
                    line,
                    sensor_id=self.config.sensor.id,
                    allowed_types=self.config.logs.suricata.types
                )
                if event:
                    self.metrics.events_normalized += 1
                    if self._should_forward(event):
                        self.batch_queue.append(event)
                        new_events_count += 1
                    else:
                        self.metrics.events_dropped += 1

        # Poll Zeek files
        for key, tailer in self.tailers.items():
            if not key.startswith("zeek:"):
                continue
            log_name = key.split(":", 1)[1]
            for line in tailer.read_new_lines():
                self.metrics.events_read += 1
                event = normalize_zeek(
                    log_name,
                    line,
                    sensor_id=self.config.sensor.id
                )
                if event:
                    self.metrics.events_normalized += 1
                    if self._should_forward(event):
                        self.batch_queue.append(event)
                        new_events_count += 1
                    else:
                        self.metrics.events_dropped += 1

        # Check flush conditions
        elapsed = time.time() - self.last_flush_time
        if len(self.batch_queue) >= self.config.forwarding.batch_size or (self.batch_queue and elapsed >= self.config.forwarding.flush_interval_seconds):
            self.flush()

        return new_events_count

    def flush(self) -> bool:
        """Flushes the queued batch to the configured SOAR endpoint."""
        if not self.batch_queue:
            return True

        to_send = list(self.batch_queue)
        mode = self.config.forwarding.mode
        endpoint = self.config.forwarding.endpoint_url
        headers = {"Content-Type": "application/json"}

        # Configure Auth Header
        auth = self.config.forwarding.auth
        if auth.token:
            if auth.type == "bearer":
                headers[auth.header_name] = f"Bearer {auth.token}"
            elif auth.type == "api_key":
                headers[auth.header_name] = auth.token

        success = True
        try:
            if mode == "aegis_soar":
                # Aegis-SOAR's /api/v1/alerts/investigate processes individual alerts
                for event in to_send:
                    payload = event.to_aegis_alert()
                    resp = self._session.post(
                        endpoint,
                        json=payload,
                        headers=headers,
                        timeout=self.config.forwarding.timeout_seconds
                    )
                    if resp.status_code not in (200, 201, 202):
                        logger.warning("Endpoint rejected alert: HTTP %d %s", resp.status_code, resp.text[:120])
                        success = False
            else:
                # Standard §5 NDR spec schema batch
                payload = [event.model_dump() for event in to_send]
                resp = self._session.post(
                    endpoint,
                    json=payload,
                    headers=headers,
                    timeout=self.config.forwarding.timeout_seconds
                )
                if resp.status_code not in (200, 201, 202):
                    logger.warning("Batch dispatch rejected: HTTP %d %s", resp.status_code, resp.text[:120])
                    success = False

            if success:
                self.metrics.batches_sent += 1
                self.metrics.events_forwarded += len(to_send)
                self.batch_queue = self.batch_queue[len(to_send):]
                self.last_flush_time = time.time()
                self.state_tracker.save()
                return True
            else:
                self.metrics.dispatch_errors += 1
                return False

        except Exception as e:
            logger.error("HTTP dispatch exception to %s: %s", endpoint, e)
            self.metrics.dispatch_errors += 1
            return False

    def run_loop(self, poll_interval: float = 0.5) -> None:
        """Starts main daemon loop."""
        self.is_running = True
        logger.info("Starting Pi4 NDR Sensor Forwarder [Sensor: %s, Mode: %s]", self.config.sensor.id, self.config.forwarding.mode)
        try:
            while self.is_running:
                self.poll_once()
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Shutdown requested. Flushing remaining telemetry...")
            self.stop()

    def stop(self) -> None:
        self.is_running = False
        self.flush()
        self.state_tracker.save()
        self._session.close()
        logger.info("Forwarder stopped. Metrics: %s", self.metrics.as_dict())
