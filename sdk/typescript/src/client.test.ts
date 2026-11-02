import assert from "node:assert/strict";
import test from "node:test";

import { ApprovalRequired, Client, Denied, type Transport } from "./client.js";
import { sign } from "./signing.js";

const SEED = Buffer.alloc(32, 0x42);
const AGENT = "11111111-1111-4111-8111-111111111111";
const ORG = "22222222-2222-4222-8222-222222222222";
const EXECUTION = "33333333-3333-4333-8333-333333333333";
const DECISION = "44444444-4444-4444-8444-444444444444";
const BODY =
  '{"agent_id":"11111111-1111-4111-8111-111111111111","arguments":{"a":"x","b":1},"execution_id":"33333333-3333-4333-8333-333333333333","idempotency_key":"idem-fixed-key-123","operation":"sample.echo","organization_id":"22222222-2222-4222-8222-222222222222","requested_at":"2023-11-14T22:13:20Z","resource":"demo","tool_name":"sample.echo"}';

function client(transport: Transport): Client {
  return new Client({
    gateway: "http://127.0.0.1:8081",
    agentId: AGENT,
    organizationId: ORG,
    seed: SEED,
    transport,
    clock: () => 1_700_000_000,
    nonce: () => "nonce-value-123456",
    executionId: () => EXECUTION,
    idempotencyKey: () => "idem-fixed-key-123",
  });
}

test("authorize signs the exact body it sends", async () => {
  const seen: { url: string; body: Buffer; headers: Record<string, string> }[] = [];
  const transport: Transport = async (url, body, headers) => {
    seen.push({ url, body, headers });
    return {
      status: 200,
      body: Buffer.from(
        JSON.stringify({
          decision_id: DECISION,
          outcome: "allow",
          explanation: { reason: "allowed" },
        }),
      ),
    };
  };
  const decision = await client(transport).authorize({
    toolName: "sample.echo",
    operation: "sample.echo",
    resource: "demo",
    arguments: { b: 1, a: "x" },
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0]?.body.toString("utf8"), BODY);
  assert.equal(seen[0]?.headers["X-AgentShield-Signature"], sign(SEED, 1_700_000_000, "nonce-value-123456", seen[0].body));
  assert.equal(decision.outcome, "allow");
  assert.equal(decision.idempotencyKey, "idem-fixed-key-123");
  assert.equal(client(transport).toString().includes(SEED.toString("hex")), false);
});

test("callTool stops before execute on deny and require_approval", async () => {
  for (const outcome of ["deny", "require_approval"] as const) {
    const paths: string[] = [];
    const transport: Transport = async (url) => {
      paths.push(url);
      const payload: Record<string, unknown> = {
        decision_id: DECISION,
        outcome,
        explanation: { reason: outcome },
      };
      if (outcome === "require_approval") {
        payload.approval_id = "55555555-5555-4555-8555-555555555555";
      }
      return { status: outcome === "deny" ? 403 : 200, body: Buffer.from(JSON.stringify(payload)) };
    };
    const call = client(transport).callTool({
      toolName: "sample.echo",
      operation: "sample.echo",
      resource: "demo",
      arguments: {},
    });
    await assert.rejects(call, outcome === "deny" ? Denied : ApprovalRequired);
    assert.deepEqual(paths, ["http://127.0.0.1:8081/api/v1/runtime/authorize"]);
  }
});

test("callTool executes only after allow", async () => {
  const paths: string[] = [];
  const transport: Transport = async (url) => {
    paths.push(url);
    if (url.endsWith("/authorize")) {
      return {
        status: 200,
        body: Buffer.from(
          JSON.stringify({
            decision_id: DECISION,
            outcome: "allow",
            explanation: { reason: "allowed" },
          }),
        ),
      };
    }
    return {
      status: 200,
      body: Buffer.from(
        JSON.stringify({
          decision_id: DECISION,
          outcome: "allow",
          adapter: "sample.echo",
          result: { label: "sample adapter with no external side effect" },
        }),
      ),
    };
  };
  const result = await client(transport).callTool({
    toolName: "sample.echo",
    operation: "sample.echo",
    resource: "demo",
    arguments: {},
  });
  assert.equal(result.adapter, "sample.echo");
  assert.deepEqual(paths, [
    "http://127.0.0.1:8081/api/v1/runtime/authorize",
    "http://127.0.0.1:8081/api/v1/runtime/execute",
  ]);
});

test("execute sends an approval id only when asked", async () => {
  const seen: string[] = [];
  const transport: Transport = async (_url, body) => {
    seen.push(body.toString("utf8"));
    return {
      status: 200,
      body: Buffer.from(
        JSON.stringify({
          decision_id: DECISION,
          outcome: "allow",
          adapter: "sample.echo",
          result: {},
        }),
      ),
    };
  };
  const caller = client(transport);
  await caller.execute(DECISION, "idem-fixed-key-123");
  await caller.execute(DECISION, "idem-fixed-key-123", "55555555-5555-4555-8555-555555555555");
  assert.equal(seen[0]?.includes("approval_id"), false);
  assert.equal(seen[1]?.includes("approval_id"), true);
});
