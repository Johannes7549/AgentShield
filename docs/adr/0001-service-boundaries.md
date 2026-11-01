# ADR 0001: Service boundaries in one repository

- Status: Accepted
- Date: 2026-11-01

## Context

AgentShield has a low-latency enforcement path and a slower management path. They change for different reasons. Putting them in one process would make a dashboard deploy affect authorization, and putting every library in its own network service would make policy evaluation depend on a remote call.

## Decision

Keep one repository. Run the control plane, gateway, intelligence service, and dashboard as separate processes. Keep policy evaluation and signature verification as Go libraries linked into the gateway.

The control plane is the only writer of users, organizations, memberships, agents, credentials, and policy documents. The gateway is the writer of invocations, authorization decisions, and audit links. Approval rows are created by the gateway and decided by the control plane.

Services share OpenAPI files and the signature specification. They do not share a database module or an ORM model.

## Consequences

A change to the decision contract updates `runtime/policy-engine` and the gateway OpenAPI together. Cross-language SDKs reimplement the signing input from ADR 0003 and must match its tests.

Operationally there are four processes. Compose starts only the data services. Application processes run on the host until their images exist.

## Alternatives

One deployable monolith was rejected because the gateway's availability and dependency set should stay smaller than the control plane's. A separate policy network service was rejected for the hot path. An external policy engine can still replace the library later if it implements the same decision contract.
