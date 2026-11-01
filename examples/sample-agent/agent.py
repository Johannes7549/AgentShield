"""Sample Python agent for the gateway.

This script is a demonstration of sdk/python. It is not a framework integration.
The private seed never leaves this process. AgentShield stores only the public key.
The only tool the gateway will execute is sample.echo.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk" / "python"
if str(SDK) not in sys.path:
    sys.path.insert(0, str(SDK))

from agentshield_sdk import Client, GatewayError, public_key, sign, signing_input  # noqa: E402

__all__ = ["load_or_create_seed", "main", "public_key", "sign", "signing_input"]


def load_or_create_seed(path: Path) -> bytes:
    if path.exists():
        seed = path.read_bytes()
        if len(seed) != 32:
            raise SystemExit("seed file must be 32 bytes")
        return seed
    seed = secrets.token_bytes(32)
    path.write_bytes(seed)
    return seed


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
    print(f"public_key {public_key(seed)}")
    client = Client(
        gateway=args.gateway,
        agent_id=args.agent_id,
        organization_id=args.organization_id,
        seed=seed,
    )
    try:
        decision = client.authorize(
            tool_name="sample.echo",
            operation=args.operation,
            resource=args.resource,
            arguments={},
            execution_id=str(uuid.uuid4()),
            idempotency_key="sample-idempotency-" + secrets.token_hex(8),
        )
    except GatewayError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        raise SystemExit(exc.status) from exc
    print(json.dumps(decision.as_dict(), indent=2))
    if not args.execute:
        return
    if decision.outcome != "allow":
        raise SystemExit("execute was not attempted because the decision is not allow")
    try:
        result = client.execute(decision.decision_id, decision.idempotency_key)
    except GatewayError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        raise SystemExit(exc.status) from exc
    print(json.dumps(result.as_dict(), indent=2))


if __name__ == "__main__":
    main()
