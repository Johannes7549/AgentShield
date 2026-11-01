# ADR 0007: Versioned HTTP contracts, two origins

- Status: Accepted
- Date: 2026-11-01

## Context

Operators and agents are different callers. Putting both behind one process in the first milestone would force the gateway to host user management, or the control plane to sit on the tool-call path.

The external paths are already written down: `/api/v1/...` for management and `/api/v1/runtime/...` for enforcement. Health probes are easier to operate at `/health/live` and `/health/ready` on every process.

## Decision

The control plane and the gateway publish separate OpenAPI documents under `docs/api/`. Both use JSON. Errors use the same object: `error.code`, `error.message`, and `error.request_id`.

Locally they are different origins, ports 8080 and 8081. A future ingress may present one host. It must not merge their authentication. Agent signatures are rejected on control-plane routes. Human sessions are rejected on `authorize` and `execute`.

An operation listed in OpenAPI and marked "Not implemented" is not registered. The current servers return 404 for those paths. Implementations have to match the contract rather than the other way around. Breaking changes require a new `/api/vN` or an ADR that explains why an unreleased contract can still move.

## Consequences

Clients generate against the document, then have to read `docs/api/README.md` before calling anything except health. That split is deliberate.

The dashboard talks to the control plane only. It does not receive agent signing keys and it does not call the gateway's enforcement routes on behalf of an agent.

## Alternatives

One OpenAPI file with `servers` switched by tag was rejected because it hides which process must enforce which authentication. GraphQL was rejected because the enforcement API is a small command set, not a graph, and authorization errors need stable HTTP statuses.
