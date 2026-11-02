import { createHash } from "crypto";
import { canonicalJson } from "../policies/document";

const GENESIS = "0".repeat(64);

export function auditEventHash(input: {
  prevHash: string;
  eventId: string;
  organizationId: string;
  eventType: string;
  occurredAt: string;
  payload: Record<string, string>;
}): { eventHash: string; payload: string } {
  if (!/^[0-9a-f]{64}$/.test(input.prevHash)) {
    throw new Error("prev hash is invalid");
  }
  const payload = canonicalJson(input.payload);
  const payloadHash = createHash("sha256").update(payload, "utf8").digest("hex");
  const header = canonicalJson({
    event_id: input.eventId,
    event_type: input.eventType,
    occurred_at: input.occurredAt,
    organization_id: input.organizationId,
    payload_hash: payloadHash,
    prev_hash: input.prevHash,
  });
  return {
    eventHash: createHash("sha256").update(header, "utf8").digest("hex"),
    payload,
  };
}

export function occurredAt(now = new Date()): string {
  return now.toISOString().replace(/\.(\d{3})Z$/, (_match, milliseconds: string) => `.${milliseconds}000000Z`);
}

export const auditGenesis = GENESIS;
