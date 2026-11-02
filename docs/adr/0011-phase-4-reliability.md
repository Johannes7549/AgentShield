# ADR 0011: Phase 4 reliability limits and behavioral incidents

- Status: Accepted
- Date: 2026-11-02

## Context

Phase 1 persists a decision and stops. Redis already stores nonces. The schema already has `security_incidents`. The gateway error enum already includes `rate_limited`. Phase 4 is the point where a signed caller can be slowed down, an adapter can be stopped after repeated failure, and a deterministic rule can open an incident. A model score must not become an authorization decision.

## Decision

After a signature and nonce succeed, the gateway charges three Redis counters for 60 seconds: 60 requests per agent, 30 calls per agent and tool, and 100,000 tokens per agent. A token is four bytes of the raw body, rounded up, with a minimum of one. Crossing a counter returns HTTP 429 `rate_limited` and does not record a decision. Redis errors fail closed.

Execute calls `sample.echo` with a two-second deadline. The deadline does not commit the execution, so one later retry can still run it. Five adapter failures in 60 seconds open that tool's circuit for 30 seconds. An open circuit returns HTTP 503 `circuit_open` and does not call the adapter. A completed execution still returns its stored result and does not call the adapter again. An unknown tool stays HTTP 501 and does not trip the circuit.

Two rules write `security_incidents` in the same transaction as the decision and do not change allow, deny, or require_approval. Canonical arguments larger than 4096 bytes open a low incident, `oversized_arguments`. The fifth deny for that agent inside ten minutes opens one medium incident, `deny_burst`. Later denies in that same run of five-or-more do not open another row. Owner, admin, and auditor sessions can list incidents. Operator and approver cannot. No scoring model is called.

## Consequences

A signed agent can be rejected before policy runs when it is over budget. Policy remains the only source of allow, deny, and require_approval. The dashboard still does not list incidents. Production mode stays refused. `POST /api/v1/events` and `GET /api/v1/audit` stay unregistered.

## Alternatives

Using a model tokenizer was rejected because the budget would then depend on a component that is not allowed to authorize. Counting a rate-limited call as a deny was rejected because that would invent a policy decision the documents did not make. Opening the circuit on HTTP 501 was rejected because a missing adapter is not a failing dependency.
