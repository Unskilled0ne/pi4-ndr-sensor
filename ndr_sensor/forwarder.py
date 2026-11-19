import os
import time
import json
import signal
import logging
from typing import List, Dict, Any, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ndr_sensor.config import AppConfig
from ndr_sensor.models import NDREvent
from ndr_sensor.normalizer import normalize_suricata, normalize_zeek
from ndr_sensor.tailer import StateTracker, FileTailer
from ndr_sensor.dedup import AlertDeduplicator
from ndr_sensor.ioc_lookup import IOCBlocklist

logger = logging.getLogger("ndr_sensor.forwarder")


def _notify_systemd(state: str) -> None:
    """Send notification to systemd if running under a watchdog."""
    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return
    try:
        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if notify_socket.startswith("@"):
            notify_socket = "\0" + notify_socket[1:]
        sock.sendto(state.encode("utf-8"), notify_socket)
        sock.close()
    except Exception:
        pass


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

    def write_prometheus(self, path: str = "/var/lib/pi4-ndr/metrics.prom") -> None:
        """Write metrics in Prometheus textfile collector format."""
        try:
            lines = [
                "# HELP ndr_events_read Total events read from log files",
                "# TYPE ndr_events_read counter",
                f"ndr_events_read {self.events_read}",
                "# HELP ndr_events_normalized Total events successfully normalized",
                "# TYPE ndr_events_normalized counter",
                f"ndr_events_normalized {self.events_normalized}",
                "# HELP ndr_events_forwarded Total events forwarded to SOAR",
                "# TYPE ndr_events_forwarded counter",
                f"ndr_events_forwarded {self.events_forwarded}",
                "# HELP ndr_events_dropped Total events dropped",
                "# TYPE ndr_events_dropped counter",
                f"ndr_events_dropped {self.events_dropped}",
                "# HELP ndr_batches_sent Total batches sent",
                "# TYPE ndr_batches_sent counter",
                f"ndr_batches_sent {self.batches_sent}",
                "# HELP ndr_dispatch_errors Total dispatch errors",
                "# TYPE ndr_dispatch_errors counter",
                f"ndr_dispatch_errors {self.dispatch_errors}",
            ]
            temp_path = f"{path}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            os.replace(temp_path, path)
        except Exception:
            pass


class LogForwarder:
    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig.load()
        self.metrics = TelemetryMetrics()
        self.state_tracker = StateTracker(self.config.state.offset_file)
        self.tailers: Dict[str, FileTailer] = {}
        self.batch_queue: List[NDREvent] = []
        self.last_flush_time: float = time.time()
        self.is_running: bool = False
        self._start_time: float = time.time()
        self._consecutive_failures: int = 0
        self._last_metrics_write: float = 0.0
        self.dedup = AlertDeduplicator(
            window_seconds=self.config.filters.dedup_window_seconds
        )
        self.ioc_blocklist = IOCBlocklist()
        self._last_ioc_check: float = time.time()

        self._session = self._create_http_session()
        self._init_tailers()

    def _enrich_event(self, event: NDREvent) -> None:
        if self.ioc_blocklist.check(event.src_ip) or self.ioc_blocklist.check(event.dest_ip):
            if event.severity not in ("high", "critical"):
                event.severity = "high"
            if not event.signature:
                event.signature = f"[IOC-MATCH] Known malicious indicator: {event.src_ip or event.dest_ip}"
            elif "[IOC-MATCH]" not in event.signature:
                event.signature = f"[IOC-MATCH] {event.signature}"

    def _create_http_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=self.config.forwarding.max_retries,
            backoff_factor=self.config.forwarding.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=1, pool_maxsize=2)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if self.config.forwarding.tls_ca_bundle:
            session.verify = self.config.forwarding.tls_ca_bundle
        else:
            session.verify = self.config.forwarding.tls_verify

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
            if event.event_type == "alert":
                return filters.always_forward_alerts
            if event.event_type == "flow":
                return filters.suricata_forward_flow
            if event.event_type == "dns":
                return filters.suricata_forward_dns
            if event.event_type == "http":
                return filters.suricata_forward_http
            if event.event_type in ("tls", "ssl"):
                return filters.suricata_forward_tls
            return False

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
            return False

        return False

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

        # Periodic IOC blocklist reload
        if time.time() - self._last_ioc_check >= 300.0:
            self.ioc_blocklist.reload()
            self._last_ioc_check = time.time()

        if "suricata" in self.tailers:
            for line in self.tailers["suricata"].read_new_lines():
                self.metrics.events_read += 1
                event = normalize_suricata(
                    line,
                    sensor_id=self.config.sensor.id,
                    allowed_types=self.config.logs.suricata.types
                )
                if event:
                    self._enrich_event(event)
                    self.metrics.events_normalized += 1
                    if self._should_forward(event):
                        if event.event_type == "alert" and self.dedup.is_duplicate(event.signature, event.src_ip, event.dest_ip):
                            self.metrics.events_dropped += 1
                        else:
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
                    self._enrich_event(event)
                    self.metrics.events_normalized += 1
                    if self._should_forward(event):
                        if event.event_type in ("alert", "notice") and self.dedup.is_duplicate(event.signature, event.src_ip, event.dest_ip):
                            self.metrics.events_dropped += 1
                        else:
                            self._enqueue_event(event)
                            new_events_count += 1
                    else:
                        self.metrics.events_dropped += 1

        elapsed = time.time() - self.last_flush_time
        if len(self.batch_queue) >= self.config.forwarding.batch_size or (self.batch_queue and elapsed >= self.config.forwarding.flush_interval_seconds):
            self.flush()

        # Periodic Prometheus metrics export
        if time.time() - self._last_metrics_write >= 60.0:
            self.metrics.write_prometheus()
            self._last_metrics_write = time.time()

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

        timeout = (3.05, self.config.forwarding.timeout_seconds)

        try:
            if mode == "aegis_soar":
                payload = [event.to_aegis_alert() for event in to_send]
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
                self.metrics.dispatch_errors += 1
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.config.forwarding.max_retries:
                    dropped_count = len(to_send)
                    logger.error(
                        "Dropping %d events after %d consecutive failures",
                        dropped_count, self._consecutive_failures
                    )
                    self.batch_queue = self.batch_queue[len(to_send):]
                    self.metrics.events_dropped += dropped_count
                    self._consecutive_failures = 0
                return False

            self.metrics.batches_sent += 1
            self.metrics.events_forwarded += len(to_send)
            self.batch_queue = self.batch_queue[len(to_send):]
            self.last_flush_time = time.time()
            self._consecutive_failures = 0
            self.state_tracker.save()
            return True

        except Exception as e:
            logger.error("HTTP dispatch failure: %s", type(e).__name__)
            self.metrics.dispatch_errors += 1
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.config.forwarding.max_retries:
                dropped_count = len(to_send)
                logger.error(
                    "Dropping %d events after %d consecutive failures",
                    dropped_count, self._consecutive_failures
                )
                self.batch_queue = self.batch_queue[len(to_send):]
                self.metrics.events_dropped += dropped_count
                self._consecutive_failures = 0
            return False

    def run_loop(self, poll_interval: float = 0.5) -> None:
        self.is_running = True
        logger.info("Forwarder started: sensor=%s mode=%s", self.config.sensor.id, self.config.forwarding.mode)

        def _handle_shutdown(signum, frame):
            logger.info("Received signal %d, shutting down gracefully...", signum)
            self.is_running = False

        def _handle_reload(signum, frame):
            logger.info("Received SIGHUP, reloading configuration...")
            try:
                new_config = AppConfig.load()
                self.config = new_config
                logger.info("Configuration reloaded successfully.")
            except Exception as e:
                logger.error("Config reload failed: %s", e)

        signal.signal(signal.SIGTERM, _handle_shutdown)
        signal.signal(signal.SIGINT, _handle_shutdown)
        signal.signal(signal.SIGHUP, _handle_reload)

        _notify_systemd("READY=1")

        try:
            while self.is_running:
                self.poll_once()
                _notify_systemd("WATCHDOG=1")
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        if not self.is_running and not self.batch_queue:
            self._session.close()
            return
        self.is_running = False
        logger.info("Flushing remaining %d events...", len(self.batch_queue))
        self.flush()
        self.state_tracker.save()
        self._session.close()
        _notify_systemd("STOPPING=1")
        logger.info("Forwarder stopped cleanly.")
