# Control plane

NestJS process for users, organizations, agents, policies, and human approvals.

This revision serves health probes only.

- `GET /health/live` returns 200.
- `GET /health/ready` returns 503.
- `/api/v1/*` is not registered.

```powershell
npm run build --workspace @agentshield/control-plane
npm start --workspace @agentshield/control-plane
```

The process listens on `127.0.0.1:8080` and refuses `AGENTSHIELD_ENV=production`. It does not open a database connection. SQL migrations are the schema source of truth. Do not enable an ORM schema sync.
