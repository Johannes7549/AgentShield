# API contracts

These OpenAPI documents are the target contract. Implementation status is separate from the contract so a generated client cannot be mistaken for a working server.

| Operation | Service | Status |
| --- | --- | --- |
| `GET /health/live` | control plane, gateway, intelligence | Implemented |
| `GET /health/ready` | control plane, gateway | Implemented. 200 when dependencies answer, otherwise 503 |
| `GET /health/ready` | intelligence | Implemented, returns 503 |
| `GET /api/health` | dashboard | Implemented, shell status |
| `POST /api/v1/sessions` | control plane | Implemented for a bootstrapped user |
| `GET/POST /api/v1/agents`, `GET /api/v1/agents/{agentId}` | control plane | Implemented |
| `GET/POST /api/v1/policies`, `PUT /api/v1/policies/{policyId}` | control plane | Implemented |
| Agent revoke, suspend, and rotate | control plane | Not implemented |
| Approval, event, incident, and audit routes | control plane | Not implemented |
| `POST /api/v1/runtime/authorize` | gateway | Implemented |
| `POST /api/v1/runtime/execute` | gateway | Implemented for `sample.echo` only. Other tools return 501 |
| Chaos experiment routes | control plane | Not implemented |

The intelligence service publishes no analysis route. `analyze_untrusted_content` raises `AnalysisUnavailable`.

Request and response errors use `error.code`, `error.message`, and `error.request_id`. Messages must not include stack traces, SQL text, or secret values.
