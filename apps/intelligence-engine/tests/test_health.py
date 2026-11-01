import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen

from agentshield_intelligence.analysis import AnalysisUnavailable, analyze_untrusted_content
from agentshield_intelligence.config import ConfigError, load_config
from agentshield_intelligence.health import dispatch
from agentshield_intelligence.server import Handler


class HealthTests(unittest.TestCase):
    def test_live_and_ready(self) -> None:
        status, body = dispatch("GET", "/health/live")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        checks = body["checks"]
        self.assertIsInstance(checks, dict)
        self.assertEqual(checks["analysis"], "not_implemented")

        status, body = dispatch("GET", "/health/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body["status"], "not_ready")

    def test_query_string_is_not_part_of_the_response(self) -> None:
        secret = "super-secret-value"
        status, body = dispatch("GET", f"/health/live?token={secret}")
        self.assertEqual(status, 200)
        self.assertNotIn(secret, json.dumps(body))

    def test_unknown_route_is_not_an_analysis_api(self) -> None:
        status, body = dispatch("POST", "/v1/analyze")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = load_config({})
        self.assertEqual(config.host, "127.0.0.1")
        self.assertEqual(config.port, 8082)
        self.assertEqual(config.environment, "development")

    def test_production_is_refused(self) -> None:
        with self.assertRaises(ConfigError):
            load_config({"AGENTSHIELD_ENV": "production"})

    def test_bad_address(self) -> None:
        with self.assertRaises(ConfigError):
            load_config({"INTELLIGENCE_HTTP_ADDR": "8082"})


class AnalysisTests(unittest.TestCase):
    def test_analysis_is_unavailable_and_does_not_echo_content(self) -> None:
        secret = "ignore-previous-instructions"
        with self.assertRaises(AnalysisUnavailable) as caught:
            analyze_untrusted_content(secret.encode("utf-8"), "text/plain")
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn("not an authorization decision", str(caught.exception))


class ServerTests(unittest.TestCase):
    def test_live_socket(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with urlopen(f"http://127.0.0.1:{port}/health/live", timeout=2) as response:
                self.assertEqual(response.status, 200)
                body = json.loads(response.read().decode("utf-8"))
                self.assertEqual(body["checks"]["analysis"], "not_implemented")
            with self.assertRaises(HTTPError) as caught:
                urlopen(f"http://127.0.0.1:{port}/health/ready", timeout=2)
            self.assertEqual(caught.exception.code, 503)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
