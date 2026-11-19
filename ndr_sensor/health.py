import os
import json
import time
import threading
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ndr_sensor.forwarder import LogForwarder

logger = logging.getLogger("ndr_sensor.health")

_forwarder_ref = None


def _get_nic_stats(interface: str = "eth0") -> dict:
    """Read NIC counters from sysfs."""
    stats = {}
    stats_dir = f"/sys/class/net/{interface}/statistics"
    for counter in ["rx_bytes", "rx_packets", "rx_dropped", "rx_errors", "tx_bytes", "tx_packets"]:
        path = os.path.join(stats_dir, counter)
        try:
            with open(path, "r") as f:
                stats[counter] = int(f.read().strip())
        except (OSError, ValueError):
            stats[counter] = -1
    return stats


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return

        forwarder = _forwarder_ref
        if forwarder is None:
            self.send_response(503)
            self.end_headers()
            return

        interface = getattr(forwarder.config.sensor, "interface", "eth0")

        health = {
            "status": "ok" if forwarder.is_running else "stopped",
            "sensor_id": forwarder.config.sensor.id,
            "uptime_seconds": round(time.time() - forwarder._start_time, 1),
            "queue_depth": len(forwarder.batch_queue),
            "consecutive_failures": forwarder._consecutive_failures,
            "metrics": forwarder.metrics.as_dict(),
            "nic_stats": _get_nic_stats(interface)
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(health, indent=2).encode("utf-8"))

    def log_message(self, format, *args):
        pass


def start_health_server(forwarder: "LogForwarder", host: str = "127.0.0.1", port: int = 9100):
    """Start a background health check HTTP server."""
    global _forwarder_ref
    _forwarder_ref = forwarder
    server = HTTPServer((host, port), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Health endpoint listening on http://%s:%d/health", host, port)
    return server
