# ADR 0008: Phase 1 enforcement path

- Status: Accepted
- Date: 2026-11-01

## Context

The Phase 0 contracts described authorize, execute, agent registration, and policy versions, and marked them unimplemented. Phase 1 needs those operations. Human registration, credential rotation, and approval decisions are still later work. The health documents said readiness was always 503, which would be false once the dependencies can be checked.

ADR 0007 allows an unreleased contract to move when an ADR explains the move.

## Decision

The control plane issues a bearer session for an existing user. `scripts` are not a registration API. `npm run bootstrap --workspace @agentshield/control-plane` inserts one organization, one owner, and an Argon2id password hash. `POST /api/v1/sessions` checks that password and stores only the SHA-256 of the token. The session's organization is the user's single active membership. A client-supplied organization id is not accepted.

Agent registration stores the 32-byte Ed25519 public key. Policy creation inserts an immutable version and, for an agent-scoped policy, a display projection. The gateway still evaluates `policy_versions`.

The gateway verifies the raw-body signature, reserves the nonce in Redis for 130 seconds, and persists the invocation, decision, redacted event, and audit link in one transaction. `require_approval` also inserts a pending approval bound to the raw-body hash, with a 15-minute expiry. Nothing in this phase approves or consumes it.

`execute` runs only `sample.echo`. That adapter returns the operation and resource and performs no external call. Every other tool returns 501 and leaves the allow unused. A second execute of the same completed sample call returns the stored result and does not append another audit link.

Readiness returns 200 only after the process can reach the dependencies it needs. Production mode stays refused until a non-owner database role and row level security exist.

## Consequences

Operators can demonstrate a signed tool call. They cannot yet rotate a key or approve a request. The OpenAPI descriptions for the implemented routes no longer say "Not implemented". Routes that are still absent keep that sentence and still return 404. ADR 0009 supersedes the earlier limit that LangGraph could not be pointed at the gateway.

## Alternatives

A stub authorize route that returned allow was rejected in Phase 0 and is still rejected. Issuing a long-lived token from the bootstrap command was rejected because the password column would stay unused and the token would have no expiry check.
