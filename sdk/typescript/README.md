# TypeScript SDK

Status: implemented.

`@agentshield/sdk` signs the exact bytes it sends to the gateway. The signing input matches `runtime/identity` and the Python SDK, including the locked test vector. The seed stays in the caller process.

`callTool` calls `execute` only when the outcome is `allow`. `deny` and `require_approval` throw. `execute` accepts an approval id after a human has approved that decision. The client has no local tool runner.

The gateway still executes only `sample.echo`.
