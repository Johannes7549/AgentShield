# Local infrastructure

`docker compose up -d` from the repository root starts PostgreSQL 16, Redis 7, NATS with JetStream, and MinIO. Ports are published on `127.0.0.1`.

The Postgres image runs every SQL file in `postgres/migrations` on first volume creation only. `docker compose down -v` deletes that volume. Apply a later file with `psql` when the volume already exists. `0002_user_sessions.sql` adds human session storage.

MinIO's own images are no longer published for anonymous download. Compose uses `cgr.dev/chainguard/minio` and `cgr.dev/chainguard/minio-client`. The server runs as uid 65532, and `minio-perms` gives that user the data volume. The client image has no shell, so bucket creation is one `mc mb --ignore-existing` command that Compose restarts until MinIO answers.

Images are floating tags. Pin them by digest before any shared environment.

Kubernetes manifests are not in this revision. See `../kubernetes/README.md`.
