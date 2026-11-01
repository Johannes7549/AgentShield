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

Still out of scope:

- Credential rotation, revocation, and suspension.
- Human approval, rejection, and single-use consumption.
- Rate limits, circuit breakers, and framework SDKs.

## Phase 2 — SDKs and integrations

- Python and TypeScript SDKs that implement the same signing input.
- LangGraph and MCP integrations that cannot bypass the gateway.
- LangChain and CrewAI stay unsupported until those two are real.

## Phase 3 — Approval and credential lifecycle

- Rotation, revocation, and suspension.
- Human approval bound to the raw payload hash, with expiry, single use, and a prohibition on self-approval.

## Phase 4 — Reliability and behavior

- Timeouts, tool-call limits, token budgets, rate limits, circuit breakers, and idempotent side effects.
- Deterministic behavioral rules and incidents. Model scoring stays optional and non-authoritative.

## Phase 5 — Chaos harness

- Executable scenarios from `chaos-engine/scenarios/CATALOG.md`.
- A result is a failure when the harness does not observe the expected defensive behavior. A missing result is not a pass.

## Phase 6 — Console and operations

- Dashboard views on live data, WebSocket updates, React Query, and charts.
- OpenTelemetry across the three processes.
- External head-hash export, a non-owner database role, row level security, image digest pins, and a measured decision about analytical storage.

ClickHouse is not scheduled until an event stream is committing and a query needs it.
