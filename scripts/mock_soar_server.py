#!/usr/bin/env python3
"""
Mock SOAR Ingestion Server
Listens for alerts dispatched by the Pi 4 NDR Sensor Forwarder.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

PORT = 8000
received_alerts = []


class MockSOARHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            payload = json.loads(post_data.decode("utf-8"))
            received_alerts.append(payload)
            print(f"\n[✔] Received Alert ({self.path}):")
            print(json.dumps(payload, indent=2))

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"status": "success", "alert_id": payload.get("alert_id", "TEST-01"), "action": "queued_for_investigation"}
            self.wfile.write(json.dumps(response).encode("utf-8"))
        except Exception as e:
            print(f"[!] Error processing payload: {e}")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "invalid json"}')

    def log_message(self, format, *args):
        # Suppress default noisy log lines
        pass


def run(port=PORT):
    server_address = ("", port)
    httpd = HTTPServer(server_address, MockSOARHandler)
    print(f"[*] Mock SOAR Server listening on http://0.0.0.0:{port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run(p)
