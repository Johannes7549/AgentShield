import { createHash } from "crypto";

const ACTION = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

export interface ResourceRule {
  effect: "allow" | "deny" | "require_approval";
  action: string;
  resource: string;
}

export interface PolicyDocument {
  agent?: { id: string };
  permissions: {
    allowed: string[];
    denied: string[];
    approval_required: string[];
  };
  resource_rules?: ResourceRule[];
}

export function validatePolicyDocument(value: unknown): PolicyDocument {
  const record = object(value, "document");
  const keys = Object.keys(record);
  for (const key of keys) {
    if (key !== "agent" && key !== "permissions" && key !== "resource_rules") {
      throw new Error("policy document contains an unknown field");
    }
  }
  const permissions = object(record.permissions, "permissions");
  for (const key of Object.keys(permissions)) {
    if (key !== "allowed" && key !== "denied" && key !== "approval_required") {
      throw new Error("policy permissions contain an unknown field");
    }
  }
  const allowed = actionList(permissions.allowed, "allowed");
  const denied = actionList(permissions.denied, "denied");
  const approval = actionList(permissions.approval_required, "approval_required");
  const seen = new Map<string, string>();
  remember(seen, allowed, "allowed");
  remember(seen, denied, "denied");
  remember(seen, approval, "approval_required");

  let agent: { id: string } | undefined;
  if ("agent" in record && record.agent !== undefined) {
    const agentRecord = object(record.agent, "agent");
    if (Object.keys(agentRecord).some((key) => key !== "id") || typeof agentRecord.id !== "string") {
      throw new Error("policy agent id is invalid");
    }
    if (agentRecord.id.length < 1 || agentRecord.id.length > 128) {
      throw new Error("policy agent id is invalid");
    }
    agent = { id: agentRecord.id };
  }

  let resourceRules: ResourceRule[] | undefined;
  if ("resource_rules" in record && record.resource_rules !== undefined) {
    if (!Array.isArray(record.resource_rules)) {
      throw new Error("resource rules are invalid");
    }
    resourceRules = record.resource_rules.map((rule) => {
      const item = object(rule, "resource rule");
      if (Object.keys(item).some((key) => key !== "effect" && key !== "action" && key !== "resource")) {
        throw new Error("resource rule contains an unknown field");
      }
      if (item.effect !== "allow" && item.effect !== "deny" && item.effect !== "require_approval") {
        throw new Error("resource rule effect is invalid");
      }
      if (typeof item.action !== "string" || !ACTION.test(item.action) || seen.get(item.action) !== "allowed") {
        throw new Error("resource rule does not narrow an allow");
      }
      if (typeof item.resource !== "string" || item.resource.length < 1 || item.resource.length > 512) {
        throw new Error("resource rule resource is invalid");
      }
      return { effect: item.effect, action: item.action, resource: item.resource };
    });
  }

  const document: PolicyDocument = {
    permissions: { allowed, denied, approval_required: approval },
  };
  if (agent) {
    document.agent = agent;
  }
  if (resourceRules) {
    document.resource_rules = resourceRules;
  }
  return document;
}

export function canonicalJson(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "string") {
    return escapeJson(value);
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("invalid number");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${escapeJson(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new Error("invalid json value");
}

export function documentHash(document: PolicyDocument): string {
  return createHash("sha256").update(canonicalJson(document), "utf8").digest("hex");
}

function remember(seen: Map<string, string>, actions: string[], list: string): void {
  for (const action of actions) {
    const previous = seen.get(action);
    if (previous) {
      throw new Error(`action is in both ${previous} and ${list}`);
    }
    seen.set(action, list);
  }
}

function actionList(value: unknown, name: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${name} must be an array`);
  }
  return value.map((item) => {
    if (typeof item !== "string" || item.length > 128 || !ACTION.test(item)) {
      throw new Error(`${name} contains an invalid action`);
    }
    return item;
  });
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value as Record<string, unknown>;
}

function escapeJson(value: string): string {
  return JSON.stringify(value).replace(/[<>&]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
