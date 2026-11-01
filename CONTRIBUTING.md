# Contributing

AgentShield is a security control. A change that makes a failure look like an allow is a defect even when the tests are green for the happy path.

## Before you open a change

- Read `docs/ARCHITECTURE.md` and `docs/SECURITY_MODEL.md`.
- If you move a service boundary, a decision rule, or a storage choice, add or update an ADR in `docs/adr/`.
- Keep OpenAPI and the implementation together. If a route is not finished, leave it unregistered and update `docs/api/README.md`. Do not return an empty success body for an unimplemented operation.
- Schema changes are new SQL files under `infrastructure/docker/postgres/migrations`. Do not add a framework setting that creates tables from classes.

## Checks

On Windows:

```powershell
powershell -File scripts/test.ps1
powershell -File scripts/lint.ps1
```

On a Unix shell, `make test` and `make lint` run the same suites. Go 1.23 or newer, Node.js 20 or newer, and Python 3.11 or newer are required. Ruff is required for the Python lint.

## Security reports

Do not open a public issue for a vulnerability. Report it privately to the maintainers. A public contact address will be added before the first release. Until then, there is no supported production deployment.

## Scope of a pull request

Prefer one phase item from `docs/DEVELOPMENT_ROADMAP.md`. Include the tests that fail if the security behavior regresses. Say which checks you ran.
