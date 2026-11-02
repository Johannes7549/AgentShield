import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from agentshield_sdk.client import Client  # noqa: E402
from agentshield_sdk.errors import ApprovalRequired, Denied  # noqa: E402
from agentshield_sdk.jsonenc import encode_json  # noqa: E402
from agentshield_sdk.signing import public_key, sign, signing_input  # noqa: E402

SEED = bytes([0x42]) * 32
AGENT = "11111111-1111-4111-8111-111111111111"
ORG = "22222222-2222-4222-8222-222222222222"
EXECUTION = "33333333-3333-4333-8333-333333333333"
DECISION = "44444444-4444-4444-8444-444444444444"
BODY = (
    '{"agent_id":"11111111-1111-4111-8111-111111111111",'
    '"arguments":{"a":"x","b":1},'
    '"execution_id":"33333333-3333-4333-8333-333333333333",'
    '"idempotency_key":"idem-fixed-key-123",'
    '"operation":"sample.echo",'
    '"organization_id":"22222222-2222-4222-8222-222222222222",'
    '"requested_at":"2023-11-14T22:13:20Z",'
    '"resource":"demo",'
    '"tool_name":"sample.echo"}'
)


class JsonTests(unittest.TestCase):
    def test_encode_matches_the_typescript_byte_string(self) -> None:
        encoded = encode_json({"q": 'a"b', "z": [1, True, None], "n": "é", "e": "😀"})
        self.assertEqual(
            encoded.decode("ascii"),
            '{"e":"\\ud83d\\ude00","n":"\\u00e9","q":"a\\"b","z":[1,true,null]}',
        )


class SigningTests(unittest.TestCase):
    def test_signature_matches_the_go_vector(self) -> None:
        body = b'{"tool":"tickets.read"}'
        self.assertEqual(
            signing_input(1_700_000_000, "nonce-value-123456", body),
            "1700000000.nonce-value-123456.c64754e077ed2605c1a851045e3a42681df935f7482c6819446c8744f857cc28",
        )
        self.assertEqual(
            sign(SEED, 1_700_000_000, "nonce-value-123456", body),
            "fuxPrL6xKqaUrNI4eHSNfcIoPltHnPttEXvZdJL_tG2kYJ8L1Sy90OJNWpWczTkYrN9-y_oP9sCeloHIF2zoBA",
        )
        self.assertEqual(public_key(SEED), "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI")

    def test_short_nonce_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sign(SEED, 1, "short", b"body")


class ClientTests(unittest.TestCase):
    def _client(self, transport):
        return Client(
            gateway="http://127.0.0.1:8081",
            agent_id=AGENT,
            organization_id=ORG,
            seed=SEED,
            transport=transport,
            clock=lambda: 1_700_000_000,
            nonce=lambda: "nonce-value-123456",
            execution_id=lambda: EXECUTION,
            idempotency_key=lambda: "idem-fixed-key-123",
        )

    def test_authorize_signs_the_exact_body_it_sends(self) -> None:
        seen = []

        def transport(url, body, headers):
            seen.append((url, body, headers))
            payload = {
                "decision_id": DECISION,
                "outcome": "allow",
                "explanation": {"reason": "allowed"},
            }
            return 200, json.dumps(payload).encode("utf-8")

        decision = self._client(transport).authorize(
            tool_name="sample.echo",
            operation="sample.echo",
            resource="demo",
            arguments={"b": 1, "a": "x"},
        )
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][1].decode("utf-8"), BODY)
        self.assertEqual(
            seen[0][2]["X-AgentShield-Signature"],
            sign(SEED, 1_700_000_000, "nonce-value-123456", seen[0][1]),
        )
        self.assertEqual(decision.outcome, "allow")
        self.assertNotIn(SEED.hex(), repr(self._client(transport)))

    def test_call_tool_stops_before_execute(self) -> None:
        for outcome, error in (("deny", Denied), ("require_approval", ApprovalRequired)):
            paths = []

            def transport(url, body, headers, outcome=outcome):
                paths.append(url)
                payload = {
                    "decision_id": DECISION,
                    "outcome": outcome,
                    "explanation": {"reason": outcome},
                }
                if outcome == "require_approval":
                    payload["approval_id"] = "55555555-5555-4555-8555-555555555555"
                status = 403 if outcome == "deny" else 200
                return status, json.dumps(payload).encode("utf-8")

            with self.assertRaises(error):
                self._client(transport).call_tool(
                    tool_name="sample.echo",
                    operation="sample.echo",
                    resource="demo",
                    arguments={},
                )
            self.assertEqual(paths, ["http://127.0.0.1:8081/api/v1/runtime/authorize"])

    def test_call_tool_executes_only_after_allow(self) -> None:
        paths = []

        def transport(url, body, headers):
            paths.append(url)
            if url.endswith("/authorize"):
                payload = {
                    "decision_id": DECISION,
                    "outcome": "allow",
                    "explanation": {"reason": "allowed"},
                }
            else:
                payload = {
                    "decision_id": DECISION,
                    "outcome": "allow",
                    "adapter": "sample.echo",
                    "result": {"label": "sample adapter with no external side effect"},
                }
            return 200, json.dumps(payload).encode("utf-8")

        result = self._client(transport).call_tool(
            tool_name="sample.echo",
            operation="sample.echo",
            resource="demo",
            arguments={},
        )
        self.assertEqual(result.adapter, "sample.echo")
        self.assertEqual(
            paths,
            [
                "http://127.0.0.1:8081/api/v1/runtime/authorize",
                "http://127.0.0.1:8081/api/v1/runtime/execute",
            ],
        )

    def test_execute_sends_an_approval_id_only_when_asked(self) -> None:
        seen = []

        def transport(url, body, headers):
            seen.append(body)
            payload = {
                "decision_id": DECISION,
                "outcome": "allow",
                "adapter": "sample.echo",
                "result": {},
            }
            return 200, json.dumps(payload).encode("utf-8")

        client = self._client(transport)
        client.execute(DECISION, "idem-fixed-key-123")
        self.assertNotIn(b"approval_id", seen[0])
        client.execute(DECISION, "idem-fixed-key-123", "55555555-5555-4555-8555-555555555555")
        self.assertIn(b"approval_id", seen[1])


if __name__ == "__main__":
    unittest.main()
