# Development roadmap

Status reflects this repository, not the intended product. An item is done only when the code and tests exist.

## Phase 0 — Foundation

Done in this revision:

- Monorepo layout and service boundaries.
- Architecture, security model, and ADRs.
- PostgreSQL schema, including composite organization foreign keys and the audit-chain triggers.
- OpenAPI contracts, with implementation status recorded separately.
- Docker Compose for PostgreSQL, Redis, NATS, and MinIO, loopback ports, private evidence bucket.
- Go gateway, NestJS control plane, Python intelligence process, and Next.js shell.
- Liveness, and readiness that returns 503 where the security function is absent.
- Signature, redaction, and audit-hash primitives with unit tests.
- Lint and test entry points, plus a CI workflow.

Still open before calling the foundation finished in a shared environment:

- Pin container images by digest before anyone other than a single developer uses Compose.
- Add a non-owner database role. The published Compose user owns the schema.
- Confirm MinIO after a fresh clone if `cgr.dev` is unreachable. On the machine that finished this revision, `cgr.dev/chainguard/minio` started and `minio-init` created `agentshield-evidence`. PostgreSQL, Redis, and NATS are healthy, and `0001_init` applied. Upstream no longer publishes `minio/minio` anonymously.

## Phase 1 — Minimum viable enforcement

Done in this revision:

- Bootstrap of one organization, one owner, and an Argon2id password hash. There is still no public registration route.
- Human session tokens. Only the SHA-256 is stored.
- Agent registration of an Ed25519 public key.
- Immutable policy versions, loaded by the gateway.
- Signature checks, Redis nonce reservation, and `allow` / `deny` / `require_approval`.
- Invocation, decision, redacted event, and audit link in one transaction.
- `sample.echo`, labeled as having no external side effect. Other tools return 501.
- A sample Python caller in `examples/sample-agent/`.
- Security tests for default deny, explicit deny, organization mismatch, bad signatures, replay, and a PostgreSQL rollback of the audit insert.

Deferred items from this phase are covered by Phase 3 and Phase 4.

## Phase 2 — SDKs and integrations

Done in this revision:

- Python and TypeScript clients that sign the raw body bytes they send. Both match the Go signature vector in `runtime/identity`.
- `call_tool` executes only after the gateway returns allow. Deny and require_approval stop before execute.
- A LangGraph node and an MCP server that forward tool calls through that client. Neither accepts a local function.
- LangChain and CrewAI stay unsupported. No wrapper is installed for them.

Still out of scope:

- Any gateway adapter other than `sample.echo`.

## Phase 3 — Approval and credential lifecycle

Done in this revision:

- Rotation replaces the active public key and marks the previous key rotated. Revocation retires the agent and its keys. Suspension blocks the agent and leaves the key in place.
- A human owner, admin, or approver can approve or reject the pending row the gateway already inserted. The row keeps the raw-body hash, expires, and can be consumed once.
- The approving user cannot have the same id as the agent. An agent credential cannot call the approval routes. Execute refuses a pending, expired, rejected, or self-approved row.

Still out of scope:

- Resuming a suspended agent.
- Any gateway adapter other than `sample.echo`.

## Phase 4 — Reliability and behavior

Done in this revision:

- Redis request, tool-call, and token budgets. A breach returns 429 and does not store a decision.
- A two-second adapter deadline, and a circuit that opens for 30 seconds after five adapter failures. A completed execution still returns its stored result.
- Deterministic incidents for oversized arguments and a burst of denies. The policy outcome does not change. Owner, admin, and auditor can list incidents.

Still out of scope:

- Model scoring. It stays non-authoritative and is not called.
- Any gateway adapter other than `sample.echo`.

## Phase 5 — Chaos harness

- Executable scenarios from `chaos-engine/scenarios/CATALOG.md`.
- A result is a failure when the harness does not observe the expected defensive behavior. A missing result is not a pass.

## Phase 6 — Console and operations

- Dashboard views on live data, WebSocket updates, React Query, and charts.
- OpenTelemetry across the three processes.
- External head-hash export, a non-owner database role, row level security, image digest pins, and a measured decision about analytical storage.

ClickHouse is not scheduled until an event stream is committing and a query needs it.
