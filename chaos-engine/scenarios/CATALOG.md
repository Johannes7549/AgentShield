# Chaos scenarios

Status: executable. `runtime/gateway/internal/chaos` runs every scenario below. A missing observation is a failure. The probes use fixtures, not attack payloads. Catalog rows are enabled.

| Scenario id | Defensive property |
| --- | --- |
| `prompt-injection` | Untrusted content cannot change an authorization outcome. |
| `mcp-tool-poisoning` | A tool description that asks for a broader action is still denied unless policy allows that action. |
| `memory-poisoning` | Retrieved memory is untrusted input and is not a grant. |
| `unauthorized-tool-invocation` | An action outside allow and approval is denied. |
| `duplicate-tool-requests` | A repeated idempotency key does not repeat a side effect. |
| `infinite-tool-call-loop` | A tool-call budget terminates the execution. |
| `api-timeout` | A timeout is a failure, not an allow, and does not skip the audit record. |
| `network-failure` | A dependency error fails closed. |
| `expired-agent-credentials` | An expired or revoked credential is rejected. |
| `excessive-resource-consumption` | A budget breach terminates the execution. |
| `malicious-agent-delegation` | A delegated call still carries the caller's identity and cannot approve itself. |
| `context-overflow` | An oversized request is rejected before evaluation. |
