# AgentShield

AgentShield is a security and reliability layer for autonomous agents. Tool calls are authenticated, authorized, and recorded outside the agent that requested them. This repository implements that path for one registered agent and the `sample.echo` adapter. Python and TypeScript clients sign the request. LangGraph and MCP forward tool calls through those clients and cannot run a tool locally. The repository does not approve requests or rotate keys. LangChain and CrewAI are not integrated.

The control plane and gateway answer liveness. Readiness is 200 only when their databases answer. The dashboard is still a shell and does not show live counts. `AGENTSHIELD_ENV=production` is refused.

## Layout

```text
apps/control-plane          NestJS management API
apps/dashboard              Next.js console shell
apps/intelligence-engine    Python analysis process, not implemented
runtime/gateway             Go enforcement process
runtime/policy-engine       Deterministic allow, deny, and require_approval
runtime/identity            Ed25519 request signatures
sdk/python                  Python client. Signs the raw body it sends
sdk/typescript              TypeScript client. Same signing input
integrations/langgraph      LangGraph node that calls the Python client
integrations/mcp            MCP server that calls the Python client
examples/sample-agent       Demonstration that uses the Python client
docs                        Architecture, security model, ADRs, OpenAPI
infrastructure/docker       Compose and the PostgreSQL migration
```

LangChain, CrewAI, and the chaos harness do not intercept tool calls.

## Decisions

The policy evaluator is an in-process Go library, not an OPA sidecar. Agent requests are signed with Ed25519 over the raw body. Missing policy is deny. PostgreSQL is the transactional store. ClickHouse is not deployed. The records are in `docs/adr/`.

## Local data services

Docker Desktop has to be running.

```powershell
docker compose up -d
docker compose ps
```

Published ports bind to `127.0.0.1`. The database user, Redis, NATS, and MinIO use the development defaults in `.env.example`. Those values are not for any other environment. Postgres applies every file in `infrastructure/docker/postgres/migrations/` in lexical order when the data volume is created. An existing volume does not pick up a new file. Apply `0002_user_sessions.sql` with `psql` if `schema_migrations` does not list it. Reset the volume with `docker compose down -v` only when you can lose the local data.

MinIO's evidence bucket is `agentshield-evidence`. The server image is `cgr.dev/chainguard/minio` because the upstream `minio/minio` image is no longer published for anonymous pulls. After Compose starts that image, the console is at `http://127.0.0.1:9001`.

## Application processes

```powershell
npm install
npm run build --workspace @agentshield/control-plane
npm start --workspace @agentshield/control-plane
```

The control plane listens on `127.0.0.1:8080`. `GET /health/ready` returns 200 when `DATABASE_URL` points at a database that answers, and 503 otherwise.

Create the first organization before registering an agent. The command refuses `AGENTSHIELD_ENV=production`.

```powershell
$env:DATABASE_URL = "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield?sslmode=disable"
$env:AGENTSHIELD_BOOTSTRAP_EMAIL = "owner@example.com"
$env:AGENTSHIELD_BOOTSTRAP_PASSWORD = "change-me-local-only"
$env:AGENTSHIELD_BOOTSTRAP_DISPLAY_NAME = "Local Owner"
$env:AGENTSHIELD_BOOTSTRAP_ORG_NAME = "Local"
$env:AGENTSHIELD_BOOTSTRAP_ORG_SLUG = "local"
npm run build --workspace @agentshield/control-plane
npm run bootstrap --workspace @agentshield/control-plane
```

Then `POST /api/v1/sessions` with that email and password. The token is shown once.

```powershell
$env:Path = "$pwd\.tools\go\bin;$env:Path"   # only if go is not already installed
go run ./runtime/gateway/cmd/gateway
```

The gateway listens on `127.0.0.1:8081`. It authorizes requests when `DATABASE_URL` and `REDIS_URL` are set and those services answer. Without them, readiness stays 503 and authorize does not return allow.

```powershell
$env:DATABASE_URL = "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield?sslmode=disable"
$env:REDIS_URL = "redis://127.0.0.1:6379/0"
go run ./runtime/gateway/cmd/gateway
```

`examples/sample-agent/` uses the Python SDK to call `sample.echo`. `integrations/langgraph` and `integrations/mcp` are the framework entry points. Both call the SDK and refuse a local tool function.

```powershell
$env:PYTHONPATH = "apps/intelligence-engine"
python -m agentshield_intelligence
```

The intelligence process listens on `127.0.0.1:8082`. It has no analysis route.

```powershell
npm run dev --workspace @agentshield/dashboard
```

The console is at `http://127.0.0.1:3000`.

`AGENTSHIELD_ENV=production` is refused by the three backend processes.

## Tests

```powershell
powershell -File scripts/test.ps1
powershell -File scripts/lint.ps1
```

Go tests cover signatures, policy precedence, redaction, the audit hash, gateway decisions, and a PostgreSQL rollback of the audit insert. Python tests cover the intelligence process, the sample signing input, and the repository contracts. The control plane tests cover configuration, policy documents, health, and a local registration flow when PostgreSQL is reachable. The dashboard test checks that the shell does not describe the gateway as ready.

## Contracts

`docs/api/control-plane.openapi.yaml` and `docs/api/gateway.openapi.yaml` are the target API. `docs/api/README.md` says which operations exist. Unimplemented routes are not stubbed as successful empty responses.

## License

Apache License 2.0. See `LICENSE`.
