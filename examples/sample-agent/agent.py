"""Sample Python agent for the Phase 1 gateway.

This is a demonstration script, not an SDK and not a framework integration.
The private seed never leaves this process. AgentShield stores only the public key.
The only tool the gateway will execute is sample.echo.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def signing_input(timestamp: int, nonce: str, body: bytes) -> str:
    digest = hashlib.sha256(body).hexdigest()
    return f"{timestamp}.{nonce}.{digest}"


def load_or_create_seed(path: Path) -> bytes:
    if path.exists():
        seed = path.read_bytes()
        if len(seed) != 32:
            raise SystemExit("seed file must be 32 bytes")
        return seed
    seed = secrets.token_bytes(32)
    path.write_bytes(seed)
    return seed


def public_key(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization

    private = signing_key(seed)
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sign(seed: bytes, timestamp: int, nonce: str, body: bytes) -> str:
    signature = signing_key(seed).sign(signing_input(timestamp, nonce, body).encode("ascii"))
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def signing_key(seed: bytes):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise SystemExit("install examples/sample-agent/requirements.txt before signing") from exc
    return Ed25519PrivateKey.from_private_bytes(seed)


def main() -> None:
    parser = argparse.ArgumentParser(description="Call the AgentShield gateway as a sample agent.")
    parser.add_argument("--seed-file", type=Path, required=True)
    parser.add_argument("--gateway", default="http://127.0.0.1:8081")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--operation", default="sample.echo")
    parser.add_argument("--resource", default="demo")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    seed = load_or_create_seed(args.seed_file)
    if not args.agent_id:
        raise SystemExit("agent id is required")
    print(f"public_key {public_key(seed)}")
    body = {
        "agent_id": args.agent_id,
        "organization_id": args.organization_id,
        "execution_id": str(uuid.uuid4()),
        "tool_name": "sample.echo",
        "operation": args.operation,
        "resource": args.resource,
        "arguments": {},
        "requested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "idempotency_key": "sample-idempotency-" + secrets.token_hex(8),
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    decision = post(args.gateway + "/api/v1/runtime/authorize", seed, args.agent_id, raw)
    print(json.dumps(decision, indent=2))
    if not args.execute:
        return
    if decision.get("outcome") != "allow":
        raise SystemExit("execute was not attempted because the decision is not allow")
    execute_body = json.dumps(
        {"decision_id": decision["decision_id"], "idempotency_key": body["idempotency_key"]},
        separators=(",", ":"),
    ).encode("utf-8")
    result = post(args.gateway + "/api/v1/runtime/execute", seed, args.agent_id, execute_body)
    print(json.dumps(result, indent=2))


def post(url: str, seed: bytes, agent_id: str, body: bytes) -> dict:
    timestamp = int(time.time())
    nonce = secrets.token_urlsafe(16)
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-AgentShield-Agent-Id": agent_id,
            "X-AgentShield-Timestamp": str(timestamp),
            "X-AgentShield-Nonce": nonce,
            "X-AgentShield-Signature": sign(seed, timestamp, nonce, body),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        print(payload, file=sys.stderr)
        raise SystemExit(exc.code) from exc


if __name__ == "__main__":
    main()
