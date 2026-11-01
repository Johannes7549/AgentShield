"""stdio entry point. The seed file is read and then kept in the client."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from agentshield_sdk.client import Client

from agentshield_mcp.server import GatewayMCPServer, read_message, write_message


def main() -> None:
    missing = [
        name
        for name in (
            "AGENTSHIELD_GATEWAY",
            "AGENTSHIELD_AGENT_ID",
            "AGENTSHIELD_ORGANIZATION_ID",
            "AGENTSHIELD_SEED_FILE",
        )
        if not os.environ.get(name)
    ]
    if missing:
        raise SystemExit("missing " + ", ".join(missing))
    seed_path = Path(os.environ["AGENTSHIELD_SEED_FILE"])
    seed = seed_path.read_bytes()
    tools = [part for part in os.environ.get("AGENTSHIELD_TOOLS", "sample.echo").split(",") if part]
    client = Client(
        gateway=os.environ["AGENTSHIELD_GATEWAY"],
        agent_id=os.environ["AGENTSHIELD_AGENT_ID"],
        organization_id=os.environ["AGENTSHIELD_ORGANIZATION_ID"],
        seed=seed,
    )
    server = GatewayMCPServer(client, tools)
    while True:
        message = read_message(sys.stdin.buffer)
        if message is None:
            return
        response = server.handle(message)
        if response is not None:
            write_message(sys.stdout.buffer, response)


if __name__ == "__main__":
    main()
