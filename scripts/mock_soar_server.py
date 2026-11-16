#!/usr/bin/env python3
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
MAX_PAYLOAD_BYTES = 10485760
received_alerts = []


class MockSOARHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_PAYLOAD_BYTES:
            self.send_response(413)
            self.end_headers()
            return

        post_data = self.rfile.read(content_length)

        try:
            payload = json.loads(post_data.decode("utf-8"))
            received_alerts.append(payload)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"status": "success", "alert_id": payload.get("alert_id", "TEST-01")}
            self.wfile.write(json.dumps(response).encode("utf-8"))
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "invalid json"}')

    def log_message(self, format, *args):
        pass


def run(host=DEFAULT_HOST, port=DEFAULT_PORT):
    server_address = (host, port)
    httpd = HTTPServer(server_address, MockSOARHandler)
    print(f"[+] Listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    run(port=p)
