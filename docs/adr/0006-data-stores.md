# ADR 0006: PostgreSQL first, analytical storage later

- Status: Accepted
- Date: 2026-11-01

## Context

The product sketch lists PostgreSQL, Redis, NATS, ClickHouse, MinIO, and a metrics stack. Starting all of them makes the first migration harder to understand and adds systems with no writer and no reader.

## Decision

Compose starts PostgreSQL, Redis, NATS with JetStream, and MinIO. Ports bind to loopback. Credentials in the Compose file are development defaults.

PostgreSQL holds the schema in `infrastructure/docker/postgres/migrations`. Migrations are SQL files applied by the database image on first volume creation. The control plane must not auto-sync a schema from structs.

Redis, NATS, and MinIO are present so Phase 1 has a nonce store, a commit-then-publish broker, and a private bucket. No application code depends on them yet. The evidence bucket is created private.

The upstream MinIO project no longer publishes `minio/minio` or `minio/mc` for anonymous pulls. Compose uses Chainguard's publicly pullable MinIO server and client images instead of building an unmaintained binary. The bucket and the S3 API are still MinIO.

ClickHouse, Prometheus, and Grafana are not deployed. OpenTelemetry is a Phase 6 wiring task, after there are real spans to export. Kubernetes manifests are not included until a process is ready to run in a cluster.

## Consequences

Local setup is one Compose command plus the application processes. A contributor cannot accidentally point a dashboard chart at an empty analytical database and treat it as telemetry.

When event volume makes PostgreSQL the wrong place for wide scans, a later ADR can add an analytical store fed from NATS. That store will not become the source of authorization.

## Alternatives

Adding ClickHouse now was rejected because an unused database becomes a place people write events without a retention or integrity story. Using SQLite for the first schema was rejected because the foreign keys, triggers, and JSON constraints we need are the PostgreSQL behavior Phase 1 will run against.
