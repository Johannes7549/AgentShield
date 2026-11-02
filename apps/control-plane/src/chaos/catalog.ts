export interface CatalogScenario {
  id: string;
  description: string;
  expected_behavior: string;
}

export const CATALOG: CatalogScenario[] = [
  {
    id: "prompt-injection",
    description: "Untrusted content is submitted with an otherwise identical tool call.",
    expected_behavior: "Untrusted content cannot change an authorization outcome.",
  },
  {
    id: "mcp-tool-poisoning",
    description: "A tool description asks for a broader action than the policy allows.",
    expected_behavior: "A tool description that asks for a broader action is still denied unless policy allows that action.",
  },
  {
    id: "memory-poisoning",
    description: "Retrieved text claims to be a grant.",
    expected_behavior: "Retrieved memory is untrusted input and is not a grant.",
  },
  {
    id: "unauthorized-tool-invocation",
    description: "The action is outside the allow and approval lists.",
    expected_behavior: "An action outside allow and approval is denied.",
  },
  {
    id: "duplicate-tool-requests",
    description: "The same idempotency key is presented twice.",
    expected_behavior: "A repeated idempotency key does not repeat a side effect.",
  },
  {
    id: "infinite-tool-call-loop",
    description: "Calls continue until the tool-call budget is exhausted.",
    expected_behavior: "A tool-call budget terminates the execution.",
  },
  {
    id: "api-timeout",
    description: "The adapter does not finish before its deadline.",
    expected_behavior: "A timeout is a failure, not an allow, and does not skip the audit record.",
  },
  {
    id: "network-failure",
    description: "A dependency the gateway needs does not answer.",
    expected_behavior: "A dependency error fails closed.",
  },
  {
    id: "expired-agent-credentials",
    description: "The agent credential is expired or revoked.",
    expected_behavior: "An expired or revoked credential is rejected.",
  },
  {
    id: "excessive-resource-consumption",
    description: "The call exceeds a request budget.",
    expected_behavior: "A budget breach terminates the execution.",
  },
  {
    id: "malicious-agent-delegation",
    description: "The body names a different agent and the approver is the same agent.",
    expected_behavior: "A delegated call still carries the caller's identity and cannot approve itself.",
  },
  {
    id: "context-overflow",
    description: "The request body is larger than the gateway limit.",
    expected_behavior: "An oversized request is rejected before evaluation.",
  },
];
