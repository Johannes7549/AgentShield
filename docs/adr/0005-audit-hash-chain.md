# ADR 0005: Per-organization hash chain

- Status: Accepted
- Date: 2026-11-01

## Context

Security events have to be append-only, and a silent edit has to be detectable. A single global chain couples unrelated tenants and makes verification heavier than the isolation model. A database constraint can stop ordinary updates. It cannot stop a table owner who disables the trigger.

## Decision

Each organization has its own chain.

The previous hash of the first event is 64 lowercase zero hex characters. The event hash is SHA-256 of a canonical header. The header is JSON with keys sorted lexicographically, no insignificant whitespace, and string escaping compatible with Go's `encoding/json` (including `\u003c`, `\u003e`, and `\u0026`). The header fields are `event_id`, `event_type`, `occurred_at`, `organization_id`, `payload_hash`, and `prev_hash`. `occurred_at` is UTC with nine fractional digits. `payload_hash` is SHA-256 of the canonical redacted payload. Duplicate JSON keys are rejected before hashing.

PostgreSQL assigns the sequence, requires `prev_hash` to equal the current head, and rejects updates and deletes of `security_events`, `audit_chain`, `policy_versions`, and `authorization_decisions`. `agentshield_append_audit_link` is the supported insert path. Concurrent appends that lose the head race retry.

The Go implementation lives in `runtime/gateway/internal/auditchain` and is the canonical hasher. The migration contains the same genesis constant.

## Consequences

Append throughput for one organization is serialized. That is inherent to a hash chain and is acceptable for an audit log. Verification needs the events and the links, and a stored copy of a past head if the threat includes the database owner.

Phase 1 writes the event and the link in the same transaction as the authorization decision.

## Alternatives

A signed event without a chain was rejected because it detects a forged event from an attacker who lacks the signing key, not removal of an event by someone who can delete rows. An external transparency log is a possible later witness for the head hash. It is not required to define the hash.
