# Security model

AgentShield treats the agent as a principal that can be wrong, compromised, or misleading. Safety is a property of the gateway and the policy store, not of the model.

This document describes the model this repository is built toward and the controls that exist now. Where a control is only specified, it says so.

## Decisions

Every tool call ends in exactly one of:

- `allow` — the gateway may hand the call to a registered adapter
- `deny` — the gateway does not call the tool
- `require_approval` — the gateway stores a bound approval and does not call the tool

Evaluation order, including default deny and explicit deny precedence, is normative in [ADR 0004](adr/0004-authorization-decisions.md). An error is not an allow. A 404 from an unimplemented route is not an allow.

Prompt-injection and anomaly scores never change that outcome. They may create an incident. They are not proof that a compromise succeeded, and they are not proof that it failed.

## Identities

Humans and agents are different principals.

Humans belong to organizations through `memberships`. Roles are `owner`, `admin`, `operator`, `auditor`, and `approver`. Approval routes accept `approver`, `admin`, and `owner` only. The control plane derives the organization from that membership.

Agents have an Ed25519 key pair. AgentShield stores the 32-byte public key and the lowercase SHA-256 fingerprint of those bytes. It does not have a column for secret key material. The gateway verifies `runtime/identity` signatures and reserves each nonce in Redis for 130 seconds. A second use inside that window is rejected. A signature that arrives after Redis has expired is still rejected when its timestamp is outside the 60-second skew.

Password hashes for humans are Argon2id strings in `password_hash`. The bootstrap command creates one owner. `POST /api/v1/sessions` checks the password and stores the SHA-256 of the bearer token. There is no public registration route.

## Organization isolation

Composite foreign keys tie agent-scoped rows to `(agent_id, organization_id)`. An agent cannot be moved between organizations. Nullable agent references are checked by trigger.

Client-supplied organization ids are claims. Later request handlers must ignore them as authority and deny the request when the claim disagrees with the authenticated agent or membership.

Row level security is enabled on tenant tables. The Compose owner role bypasses RLS for migrations and bootstrap. Shared deployments must connect as `agentshield_app` and set `app.organization_id` for the transaction after authentication. Production mode requires that app role.

## Approval binding

An approval stores the SHA-256 of the exact raw request body. The gateway inserts a pending row when the decision is `require_approval`, with a 15-minute expiry. An owner, admin, or approver can approve or reject that row. The approving user's id cannot equal the agent id, and an agent credential cannot call the approval routes. Execute consumes an approved, unexpired row once, and only when its hash matches the hash stored with the execution. A second execution of the completed call returns the stored result and does not consume another approval.

## Audit

Security events are append-only. The per-organization hash chain is enforced in PostgreSQL: the next link must carry the current head hash, the sequence is assigned by the trigger, and updates and deletes of chain rows are rejected.

`runtime/gateway/internal/auditchain` computes the canonical hash. The genesis previous hash is 64 zero hex characters, shared with the migration. A verifier recomputes the hash from the event. Linkage alone does not prove the payload is original if a database owner rewrites the event and the link together. A copied head hash, stored outside the database, is what makes that rewrite detectable. That export is not built yet.

The chain does not protect against a database superuser. The Compose database user owns the tables.

## Redaction

`runtime/gateway/internal/redact` replaces values whose keys look like credentials before a payload is stored or logged. Invalid JSON is an error, and the error does not include the input. Redaction is for records. Approval and signatures bind the raw body, not the redacted document.

The matcher is aggressive. A key containing `token`, `secret`, `password`, or similar is removed even when the value is not a credential. That is the preferred failure direction.

## Request limits and exposure

Local data services publish ports on `127.0.0.1` only. Development passwords in `docker-compose.yml` and `.env.example` are known defaults. They are not credentials for any other environment.

The gateway body limit defaults to 1 MiB and cannot be configured higher, matching the JSON parser used for redaction and hashing. The control plane JSON parser limit is 256 KiB. Both processes bind `127.0.0.1` by default.

After a signature and nonce succeed, Redis counts 60 requests per agent, 30 calls per agent and tool, and a token budget of 100,000 for 60 seconds. A token is four bytes of the raw body, rounded up. Crossing a counter returns 429 and stores no decision. Five adapter failures in that window open the tool circuit for 30 seconds. An open circuit does not call the adapter. `sample.echo` has a two-second deadline. A completed execution returns the stored result instead of running again.

Canonical arguments larger than 4096 bytes, and the fifth deny for an agent inside ten minutes, open a `security_incidents` row in the same transaction as the decision. Those rules do not change allow, deny, or require_approval. No model score is consulted. Owner, admin, and auditor sessions can list the rows.

`AGENTSHIELD_ENV=production` is allowed for the control plane and gateway when `DATABASE_URL` uses `agentshield_app`. The intelligence process still refuses production.

The chaos harness runs the catalog against the gateway and stores failed when the expected defense is not observed. A missing observation is failed. The probes are fixtures. They do not change an authorization outcome and they do not carry attack payloads.

## What this revision does not claim

- It does not stop prompt injection. No detector is implemented, and a future detector will not be an authorization oracle. Behavioral incidents are not that detector.
- It does not resume a suspended agent. Revocation is permanent in this revision.
- It does not execute any tool except `sample.echo`. That adapter does not call a network, database, or shell.
- It isolates `agentshield_app` by organization RLS. The schema owner still bypasses RLS.
- It does not provide a tamper-proof log against someone who can rewrite the database and every external copy of the head.
- It does not scan dependencies in this repository's CI yet. That job belongs with the first release process, not with an empty lockfile story. Node lockfiles are generated locally and CI uses `npm ci` once they exist.

The Python and TypeScript clients sign the body they send. `execute` can present an approval id after a human approves. `call_tool` still stops on deny and require_approval. LangGraph and MCP forward tool calls through those clients and have no local tool function. LangChain and CrewAI still do not wrap tools. The clients do not stop prompt injection.
