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
        if self.config.logs.suricata.enabled:
            s_path = self.config.logs.suricata.path
            self.tailers["suricata"] = FileTailer(s_path, self.state_tracker)

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

    def _enqueue_event(self, event: NDREvent) -> None:
        max_q = self.config.forwarding.max_queue_size
        if len(self.batch_queue) >= max_q:
            # Drop lowest severity event to protect memory
            for i, queued in enumerate(self.batch_queue):
                if queued.severity == "low":
                    self.batch_queue.pop(i)
                    self.metrics.events_dropped += 1
                    break
            else:
                self.batch_queue.pop(0)
                self.metrics.events_dropped += 1

        self.batch_queue.append(event)

    def poll_once(self) -> int:
        new_events_count = 0

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
                        self._enqueue_event(event)
                        new_events_count += 1
                    else:
                        self.metrics.events_dropped += 1

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
                        self._enqueue_event(event)
                        new_events_count += 1
                    else:
                        self.metrics.events_dropped += 1

        elapsed = time.time() - self.last_flush_time
        if len(self.batch_queue) >= self.config.forwarding.batch_size or (self.batch_queue and elapsed >= self.config.forwarding.flush_interval_seconds):
            self.flush()

        return new_events_count

    def flush(self) -> bool:
        if not self.batch_queue:
            return True

        to_send = list(self.batch_queue[:self.config.forwarding.batch_size])
        mode = self.config.forwarding.mode
        endpoint = self.config.forwarding.endpoint_url
        headers = {"Content-Type": "application/json"}

        auth = self.config.forwarding.auth
        if auth.token:
            safe_token = auth.token.replace("\r", "").replace("\n", "").strip()
            safe_header = auth.header_name.replace("\r", "").replace("\n", "").strip()
            if auth.type == "bearer":
                headers[safe_header] = f"Bearer {safe_token}"
            elif auth.type == "api_key":
                headers[safe_header] = safe_token

        success = True
        timeout = (3.05, self.config.forwarding.timeout_seconds)

        try:
            if mode == "aegis_soar":
                for event in to_send:
                    payload = event.to_aegis_alert()
                    resp = self._session.post(
                        endpoint,
                        json=payload,
                        headers=headers,
                        timeout=timeout
                    )
                    if resp.status_code not in (200, 201, 202):
                        logger.warning("Endpoint returned status %d", resp.status_code)
                        success = False
            else:
                payload = [event.model_dump() for event in to_send]
                resp = self._session.post(
                    endpoint,
                    json=payload,
                    headers=headers,
                    timeout=timeout
                )
                if resp.status_code not in (200, 201, 202):
                    logger.warning("Endpoint returned status %d", resp.status_code)
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
            logger.error("HTTP dispatch failure: %s", type(e).__name__)
            self.metrics.dispatch_errors += 1
            return False

    def run_loop(self, poll_interval: float = 0.5) -> None:
        self.is_running = True
        logger.info("Forwarder started: sensor=%s mode=%s", self.config.sensor.id, self.config.forwarding.mode)
        try:
            while self.is_running:
                self.poll_once()
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        self.is_running = False
        self.flush()
        self.state_tracker.save()
        self._session.close()
