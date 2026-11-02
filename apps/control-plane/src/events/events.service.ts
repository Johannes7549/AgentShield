import { Inject, Injectable } from "@nestjs/common";
import type { Pool } from "pg";
import { DATABASE_POOL } from "../db/database";
import { withOrganization } from "../db/organization";
import { apiError } from "../http/errors";

export interface SecurityEventRecord {
  id: string;
  organization_id: string;
  agent_id: string | null;
  execution_id: string | null;
  event_type: string;
  occurred_at: string;
  payload_redacted: Record<string, unknown>;
}

@Injectable()
export class EventsService {
  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async list(
    organizationId: string,
    limit: number,
    cursor: string | undefined,
  ): Promise<{ items: SecurityEventRecord[]; next_cursor: string | null }> {
    const pool = this.requirePool();
    const cursorParts = decodeCursor(cursor);
    return withOrganization(pool, organizationId, async (client) => {
      const result = await client.query<EventRow>(
        `SELECT id::text, organization_id::text, agent_id::text, execution_id::text,
                event_type, occurred_at, payload_redacted
         FROM security_events
         WHERE organization_id = $1
           AND ($2::timestamptz IS NULL OR (occurred_at, id) < ($2::timestamptz, $3::uuid))
         ORDER BY occurred_at DESC, id DESC
         LIMIT $4`,
        [organizationId, cursorParts?.at ?? null, cursorParts?.id ?? null, limit + 1],
      );
      const page = result.rows.slice(0, limit).map(toEvent);
      const next = result.rows.length > limit ? encodeCursor(page[page.length - 1]) : null;
      return { items: page, next_cursor: next };
    });
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    return this.pool;
  }
}

interface EventRow {
  id: string;
  organization_id: string;
  agent_id: string | null;
  execution_id: string | null;
  event_type: string;
  occurred_at: Date;
  payload_redacted: Record<string, unknown>;
}

function toEvent(row: EventRow): SecurityEventRecord {
  return {
    id: row.id,
    organization_id: row.organization_id,
    agent_id: row.agent_id,
    execution_id: row.execution_id,
    event_type: row.event_type,
    occurred_at: row.occurred_at.toISOString(),
    payload_redacted: row.payload_redacted ?? {},
  };
}

function encodeCursor(event: SecurityEventRecord): string {
  return Buffer.from(JSON.stringify({ at: event.occurred_at, id: event.id }), "utf8").toString("base64url");
}

function decodeCursor(cursor: string | undefined): { at: string; id: string } | undefined {
  if (!cursor) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { at?: string; id?: string };
    if (typeof parsed.at === "string" && typeof parsed.id === "string") {
      return { at: parsed.at, id: parsed.id };
    }
  } catch {
    throw apiError(400, "validation_failed", "cursor is invalid");
  }
  throw apiError(400, "validation_failed", "cursor is invalid");
}
