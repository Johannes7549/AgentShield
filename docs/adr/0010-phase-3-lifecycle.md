# ADR 0010: Phase 3 credential lifecycle and approval consumption

- Status: Accepted
- Date: 2026-11-02

## Context

Phase 1 stores a pending approval and stops. It does not rotate a key, and execute rejects every `approval_id`. Phase 3 is the human decision and the single use of that decision. The OpenAPI shapes for revoke, suspend, rotate, list, approve, and reject already existed. `POST /api/v1/approvals` was reserved for a gateway service identity. The gateway already inserts the row, so opening that route to a human would let a caller mint an approval the gateway did not bind.

## Decision

Owner and admin sessions can suspend, revoke, and rotate an agent in their own organization. Suspend changes the agent status and leaves the active key in place. The gateway then denies the agent because the agent is not active. Revoke sets the agent and every credential to revoked and records `revoked_at`. Rotate requires one active credential, marks it rotated, and inserts the new public key. A suspended or revoked agent cannot be rotated. This revision does not resume a suspended agent.

Owner, admin, and approver sessions can list, approve, and reject pending approvals in their organization. Operator and auditor cannot. The gateway remains the only writer of a new approval row, so `POST /api/v1/approvals` stays unregistered. Approve and reject append an audit link. An expired pending row becomes `expired` and cannot be approved.

Execute accepts `approval_id` only for a `require_approval` decision. The approval must be `approved`, unexpired, bound to that decision, and its `payload_hash` must equal the hash stored on the execution when the gateway authorized the original body. The deciding user must not have the same id as the agent. Consumption and the adapter run in one transaction. A completed execution returns the stored result and does not consume a second approval. `call_tool` still does not send an approval id.

## Consequences

A human can release one `sample.echo` call that policy marked `require_approval`. Any other tool still returns 501, and that response does not consume the approval. Production mode stays refused. ADR 0008's statement that operators cannot approve a request is superseded by this record.

## Alternatives

Letting the agent approve its own pending row was rejected. Letting execute trust a payload hash supplied in the execute body was rejected, because that hash would no longer be the one stored at authorization. Adding a resume route was left out because the contract has no such operation.
