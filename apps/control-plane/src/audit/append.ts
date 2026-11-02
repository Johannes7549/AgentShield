import { randomUUID } from "crypto";
import type { PoolClient } from "pg";
import { auditEventHash, auditGenesis, occurredAt } from "./chain";

export async function appendAudit(
  client: PoolClient,
  input: {
    organizationId: string;
    agentId: string | null;
    executionId: string | null;
    eventType: string;
    payload: Record<string, string>;
  },
): Promise<void> {
  const occurred = occurredAt();
  const eventId = randomUUID();
  const head = await client.query<{ last_hash: string }>(
    `SELECT last_hash FROM audit_chain_heads WHERE organization_id = $1 FOR UPDATE`,
    [input.organizationId],
  );
  const prevHash = head.rows[0]?.last_hash ?? auditGenesis;
  const link = auditEventHash({
    prevHash,
    eventId,
    organizationId: input.organizationId,
    eventType: input.eventType,
    occurredAt: occurred,
    payload: input.payload,
  });
  await client.query(
    `INSERT INTO security_events (
       id, organization_id, agent_id, execution_id, event_type, payload_redacted, occurred_at
     ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
    [eventId, input.organizationId, input.agentId, input.executionId, input.eventType, link.payload, occurred],
  );
  await client.query(`SELECT agentshield_append_audit_link($1, $2, $3, $4)`, [
    input.organizationId,
    eventId,
    prevHash,
    link.eventHash,
  ]);
}
