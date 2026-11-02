# ADR 0013: Phase 6 console, isolation, and analytical storage

- Status: Accepted
- Date: 2026-11-02

## Context

Phases 0–5 enforce and test tool calls. Operators still had no live console, no external copy of the audit head, and no non-owner database role. Production mode stayed refused for that reason. ClickHouse has been listed in sketches without a writer or a query that needs it.

## Decision

The control plane lists redacted events and audit links for the caller's organization. Owner, admin, and auditor can export the current audit head to `audit_head_exports`. That row is the external copy operators compare against a later rewrite of the chain.

Migration `0004_app_role_rls` creates `agentshield_app`, enables RLS on tenant tables, and adds SECURITY DEFINER helpers for login, session resolve, and agent lookup. Production mode is allowed only when `DATABASE_URL` uses `agentshield_app`. Development may keep the owner role, which bypasses RLS. Processes set `app.organization_id` for the transaction after authentication.

The dashboard signs in through a local BFF, loads agents, incidents, events, and audit links with React Query, refreshes on an interval, and can request a head export. Control-plane requests emit structured OpenTelemetry-style spans to process logs. The gateway and intelligence process emit the same shape on HTTP handling.

Compose pins PostgreSQL, Redis, NATS, and Busybox by digest. Chainguard MinIO images stay on floating tags until a digest can be recorded from a reachable registry.

ClickHouse is not deployed. PostgreSQL remains the transactional store. An analytical store waits until an event stream is committing and a query needs a scan PostgreSQL cannot serve.

## Consequences

Shared deployments can point the control plane and gateway at `agentshield_app`. The dashboard no longer invents counts. Intelligence still has no analysis route and still refuses production. Event stream publishing to NATS is still absent.

## Alternatives

Leaving production refused after the app role existed was rejected. Shipping ClickHouse with no reader was rejected. Letting the browser hold a long-lived control-plane token without a BFF cookie was rejected for the local console.
