import hashlib
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "examples" / "sample-agent" / "agent.py"


def load_agent():
    spec = importlib.util.spec_from_file_location("sample_agent", AGENT)
    if spec is None or spec.loader is None:
        raise AssertionError("sample agent module is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SampleAgentSigningTests(unittest.TestCase):
    def test_signing_input_matches_the_gateway_format(self) -> None:
        agent = load_agent()
        body = b'{"tool":"tickets.read"}'
        digest = hashlib.sha256(body).hexdigest()
        self.assertEqual(
            agent.signing_input(1_700_000_000, "nonce-value-123456", body),
            f"1700000000.nonce-value-123456.{digest}",
        )


if __name__ == "__main__":
    unittest.main()
