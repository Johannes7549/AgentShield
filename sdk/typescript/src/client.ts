/** Gateway client. Tool execution happens only after an allow decision. */

import { randomBytes, randomUUID } from "node:crypto";

import { encodeJson } from "./json.js";
import { sign } from "./signing.js";

export interface Decision {
  decisionId: string;
  outcome: string;
  explanation: Record<string, unknown>;
  idempotencyKey: string;
  approvalId?: string;
  approvalExpiresAt?: string;
}

export interface ExecuteResult {
  decisionId: string;
  outcome: "allow";
  adapter: string;
  result: Record<string, unknown>;
}

export class GatewayError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "GatewayError";
  }
}

export class Denied extends Error {
  constructor(readonly decision: Decision) {
    super(String(decision.explanation.reason ?? "denied"));
    this.name = "Denied";
  }
}

export class ApprovalRequired extends Error {
  constructor(readonly decision: Decision) {
    super(String(decision.explanation.reason ?? "approval required"));
    this.name = "ApprovalRequired";
  }
}

export type Transport = (
  url: string,
  body: Buffer,
  headers: Record<string, string>,
) => Promise<{ status: number; body: Buffer }>;

export interface ClientOptions {
  gateway: string;
  agentId: string;
  organizationId: string;
  seed: Buffer;
  transport?: Transport;
  clock?: () => number;
  nonce?: () => string;
  executionId?: () => string;
  idempotencyKey?: () => string;
}

export class Client {
  readonly gateway: string;
  readonly agentId: string;
  private readonly organizationId: string;
  private readonly seed: Buffer;
  private readonly transport: Transport;
  private readonly clock: () => number;
  private readonly nonce: () => string;
  private readonly executionId: () => string;
  private readonly idempotencyKey: () => string;

  constructor(options: ClientOptions) {
    if (options.seed.length !== 32) {
      throw new Error("seed must be 32 bytes");
    }
    this.gateway = options.gateway.replace(/\/$/, "");
    this.agentId = options.agentId;
    this.organizationId = options.organizationId;
    this.seed = options.seed;
    this.transport = options.transport ?? fetchTransport;
    this.clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
    this.nonce = options.nonce ?? (() => randomBytes(16).toString("base64url"));
    this.executionId = options.executionId ?? (() => randomUUID());
    this.idempotencyKey = options.idempotencyKey ?? (() => `idem-${randomBytes(16).toString("hex")}`);
  }

  toString(): string {
    return `Client(gateway=${this.gateway}, agentId=${this.agentId})`;
  }

  async authorize(input: {
    toolName: string;
    operation: string;
    resource: string;
    arguments: Record<string, unknown>;
    executionId?: string;
    idempotencyKey?: string;
  }): Promise<Decision> {
    const idempotencyKey = input.idempotencyKey ?? this.idempotencyKey();
    const timestamp = this.clock();
    const body = encodeJson({
      agent_id: this.agentId,
      arguments: input.arguments,
      execution_id: input.executionId ?? this.executionId(),
      idempotency_key: idempotencyKey,
      operation: input.operation,
      organization_id: this.organizationId,
      requested_at: new Date(timestamp * 1000).toISOString().replace(".000Z", "Z"),
      resource: input.resource,
      tool_name: input.toolName,
    });
    const payload = await this.post("/api/v1/runtime/authorize", body, timestamp);
    return decisionFrom(payload, idempotencyKey);
  }

  async execute(decisionId: string, idempotencyKey: string, approvalId?: string): Promise<ExecuteResult> {
    const requestBody: Record<string, string> = {
      decision_id: decisionId,
      idempotency_key: idempotencyKey,
    };
    if (approvalId !== undefined) {
      requestBody.approval_id = approvalId;
    }
    const body = encodeJson(requestBody);
    const payload = await this.post("/api/v1/runtime/execute", body, this.clock());
    if (payload.outcome !== "allow" || typeof payload.adapter !== "string") {
      throw errorFrom(payload, 200);
    }
    const result = payload.result ?? {};
    if (typeof result !== "object" || result === null || Array.isArray(result)) {
      throw new GatewayError(200, "invalid_response", "gateway response was not an object");
    }
    return {
      decisionId: String(payload.decision_id),
      outcome: "allow",
      adapter: payload.adapter,
      result: result as Record<string, unknown>,
    };
  }

  async callTool(input: {
    toolName: string;
    operation: string;
    resource: string;
    arguments: Record<string, unknown>;
  }): Promise<ExecuteResult> {
    const decision = await this.authorize(input);
    if (decision.outcome === "allow") {
      return this.execute(decision.decisionId, decision.idempotencyKey);
    }
    if (decision.outcome === "deny") {
      throw new Denied(decision);
    }
    if (decision.outcome === "require_approval") {
      throw new ApprovalRequired(decision);
    }
    throw new GatewayError(0, "invalid_decision", "gateway returned an unknown outcome");
  }

  private async post(path: string, body: Buffer, timestamp: number): Promise<Record<string, unknown>> {
    const nonce = this.nonce();
    const response = await this.transport(`${this.gateway}${path}`, body, {
      "Content-Type": "application/json",
      "X-AgentShield-Agent-Id": this.agentId,
      "X-AgentShield-Timestamp": String(timestamp),
      "X-AgentShield-Nonce": nonce,
      "X-AgentShield-Signature": sign(this.seed, timestamp, nonce, body),
    });
    return readResponse(response.status, response.body);
  }
}

const fetchTransport: Transport = async (url, body, headers) => {
  const response = await fetch(url, { method: "POST", body, headers, redirect: "error" });
  return { status: response.status, body: Buffer.from(await response.arrayBuffer()) };
};

function readResponse(status: number, raw: Buffer): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new GatewayError(status, "invalid_response", "gateway response was not JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new GatewayError(status, "invalid_response", "gateway response was not an object");
  }
  const payload = parsed as Record<string, unknown>;
  if ("outcome" in payload && "decision_id" in payload) {
    if (status !== 200 && status !== 403) {
      throw new GatewayError(status, "invalid_response", "gateway decision used an unexpected status");
    }
    return payload;
  }
  throw errorFrom(payload, status);
}

function decisionFrom(payload: Record<string, unknown>, idempotencyKey: string): Decision {
  const explanation = payload.explanation ?? {};
  if (typeof explanation !== "object" || explanation === null || Array.isArray(explanation)) {
    throw new GatewayError(200, "invalid_response", "gateway response was not an object");
  }
  return {
    decisionId: String(payload.decision_id),
    outcome: String(payload.outcome),
    explanation: explanation as Record<string, unknown>,
    idempotencyKey,
    approvalId: typeof payload.approval_id === "string" ? payload.approval_id : undefined,
    approvalExpiresAt:
      typeof payload.approval_expires_at === "string" ? payload.approval_expires_at : undefined,
  };
}

function errorFrom(payload: Record<string, unknown>, status: number): GatewayError {
  const error = payload.error;
  if (typeof error === "object" && error !== null && !Array.isArray(error)) {
    const body = error as Record<string, unknown>;
    return new GatewayError(status, String(body.code ?? "error"), String(body.message ?? "gateway error"));
  }
  return new GatewayError(status, "invalid_response", "gateway response was not a decision");
}
