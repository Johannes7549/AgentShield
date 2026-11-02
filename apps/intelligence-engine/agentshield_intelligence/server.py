import json
import secrets
import signal
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from agentshield_intelligence.config import Config
from agentshield_intelligence.health import dispatch


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._respond()

    def do_POST(self) -> None:
        self._respond()

    def _respond(self) -> None:
        started = time.time()
        path = urlsplit(self.path).path
        status, body = dispatch(self.command, path)
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)
        sys.stdout.write(
            json.dumps(
                {
                    "level": "info",
                    "service": "intelligence-engine",
                    "msg": "otel",
                    "trace_id": secrets.token_hex(16),
                    "span_id": secrets.token_hex(8),
                    "name": f"{self.command} {path}",
                    "status": status,
                    "duration_ms": int((time.time() - started) * 1000),
                }
            )
            + "\n"
        )

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


def serve(config: Config) -> None:
    server = ThreadingHTTPServer((config.host, config.port), Handler)

    def shutdown(signum: int, frame: object) -> None:
        del signum, frame
        server.shutdown()

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    sys.stdout.write(
        json.dumps(
            {
                "level": "info",
                "msg": "listening",
                "service": "intelligence-engine",
                "addr": f"{config.host}:{config.port}",
            }
        )
        + "\n"
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
