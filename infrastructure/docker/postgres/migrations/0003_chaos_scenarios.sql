-- Catalog scenarios. Enabled because the harness in runtime/gateway/internal/chaos
-- now executes them. An existing volume does not apply this file on its own.

INSERT INTO chaos_scenarios (id, description, preconditions, expected_behavior, enabled)
VALUES
  ('prompt-injection', 'Untrusted content is submitted with an otherwise identical tool call.', '{}'::jsonb, 'Untrusted content cannot change an authorization outcome.', true),
  ('mcp-tool-poisoning', 'A tool description asks for a broader action than the policy allows.', '{}'::jsonb, 'A tool description that asks for a broader action is still denied unless policy allows that action.', true),
  ('memory-poisoning', 'Retrieved text claims to be a grant.', '{}'::jsonb, 'Retrieved memory is untrusted input and is not a grant.', true),
  ('unauthorized-tool-invocation', 'The action is outside the allow and approval lists.', '{}'::jsonb, 'An action outside allow and approval is denied.', true),
  ('duplicate-tool-requests', 'The same idempotency key is presented twice.', '{}'::jsonb, 'A repeated idempotency key does not repeat a side effect.', true),
  ('infinite-tool-call-loop', 'Calls continue until the tool-call budget is exhausted.', '{}'::jsonb, 'A tool-call budget terminates the execution.', true),
  ('api-timeout', 'The adapter does not finish before its deadline.', '{}'::jsonb, 'A timeout is a failure, not an allow, and does not skip the audit record.', true),
  ('network-failure', 'A dependency the gateway needs does not answer.', '{}'::jsonb, 'A dependency error fails closed.', true),
  ('expired-agent-credentials', 'The agent credential is expired or revoked.', '{}'::jsonb, 'An expired or revoked credential is rejected.', true),
  ('excessive-resource-consumption', 'The call exceeds a request budget.', '{}'::jsonb, 'A budget breach terminates the execution.', true),
  ('malicious-agent-delegation', 'The body names a different agent and the approver is the same agent.', '{}'::jsonb, 'A delegated call still carries the caller''s identity and cannot approve itself.', true),
  ('context-overflow', 'The request body is larger than the gateway limit.', '{}'::jsonb, 'An oversized request is rejected before evaluation.', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO schema_migrations (version) VALUES ('0003_chaos_scenarios')
ON CONFLICT (version) DO NOTHING;
