# Dashboard

Next.js shell for the security console. Tailwind is configured, and `components.json` is the shadcn/ui setup. No shadcn component is installed yet because no view needs one.

The page lists the ten console sections and the readiness of each process. It does not query an API and it does not render zeroed metrics.

React Query, Recharts, and a WebSocket client are intentionally not dependencies yet. They land with the first view that has data to show, in Phase 6.

```powershell
npm run dev --workspace @agentshield/dashboard
```

`GET /api/health` returns the shell status.
