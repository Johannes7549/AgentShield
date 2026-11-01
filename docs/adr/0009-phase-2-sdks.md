# ADR 0009: Phase 2 SDKs and gateway-only integrations

- Status: Accepted
- Date: 2026-11-01

## Context

Phase 1 authenticates a signed tool call and executes only `sample.echo`. A sample script signed that call by hand. Phase 2 needs a Python client and a TypeScript client that reproduce the signing input from ADR 0003, plus LangGraph and MCP entry points. Those entry points must not grow a second executor. LangChain and CrewAI stay unsupported until the gateway path is the only path those frameworks can take.

The gateway OpenAPI document does not change. ADR 0007 is not involved.

## Decision

`sdk/python` and `sdk/typescript` serialize a request, sign those exact bytes, and POST them. `call_tool` / `callTool` calls execute only after the gateway returns `allow`. `deny` and `require_approval` stop in the client. The clients do not accept an `approval_id`, do not store the seed, and do not expose a function that runs a tool locally.

`GatewayToolNode` is a LangGraph node. Its constructor takes the Python client and rejects any attempt to pass local tools. `GatewayMCPServer` lists tool names and forwards `tools/call` through the same client. A name that was not listed is a protocol error. Neither integration imports a tool callable, and neither calls a method other than `call_tool`.

LangChain and CrewAI directories stay documentation. They do not wrap tools.

## Consequences

An agent can point LangGraph or MCP at the gateway. The gateway still executes only `sample.echo`. A policy allow for any other tool returns HTTP 501, and the integration reports that error instead of running the tool itself. ADR 0008's statement that LangGraph cannot be pointed at the gateway is superseded by this record. Credential rotation and human approval consumption remain unimplemented.

## Alternatives

Wrapping a local Python function and calling it after allow was rejected. That would execute a tool the gateway has no adapter for, which is the bypass Phase 2 exists to prevent. Installing LangChain and intercepting every tool in that process was rejected because the roadmap keeps LangChain unsupported until the gateway path is real, and a process-wide patch is easy to skip.
