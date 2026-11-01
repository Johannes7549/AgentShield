# Runtime gateway

Go process that will authenticate agents and authorize tool calls. This revision does not register `/api/v1/runtime/authorize` or `/api/v1/runtime/execute`.

- `GET /health/live` returns 200 and reports `authorization: not_implemented`.
- `GET /health/ready` returns 503.

Request signatures, JSON redaction, and audit hashing live beside this process and have unit tests. They are not wired to an HTTP authorization route.

```powershell
go run ./runtime/gateway/cmd/gateway
```

Default address is `127.0.0.1:8081`. The body limit defaults to 1 MiB and cannot be raised above that. Production mode is refused.
