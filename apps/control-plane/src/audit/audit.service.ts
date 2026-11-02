import { Inject, Injectable } from "@nestjs/common";
import type { Pool } from "pg";
import { DATABASE_POOL } from "../db/database";
import { withOrganization } from "../db/organization";
import { apiError } from "../http/errors";

export interface AuditLinkRecord {
  sequence: number;
  event_id: string;
  prev_hash: string;
  event_hash: string;
}

export interface AuditHeadExport {
  id: string;
  sequence: number;
  head_hash: string;
  exported_at: string;
  destination: string;
}

@Injectable()
export class AuditService {
  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async list(organizationId: string): Promise<{ items: AuditLinkRecord[] }> {
    const pool = this.requirePool();
    return withOrganization(pool, organizationId, async (client) => {
      const result = await client.query<AuditLinkRecord>(
        `SELECT sequence, event_id::text, prev_hash, event_hash
         FROM audit_chain
         WHERE organization_id = $1
         ORDER BY sequence DESC
         LIMIT 200`,
        [organizationId],
      );
      return { items: result.rows };
    });
  }

  async exportHead(organizationId: string, destination: string): Promise<AuditHeadExport> {
    const pool = this.requirePool();
    return withOrganization(pool, organizationId, async (client) => {
      const head = await client.query<{ last_sequence: string; last_hash: string }>(
        `SELECT last_sequence::text, last_hash FROM audit_chain_heads WHERE organization_id = $1 FOR UPDATE`,
        [organizationId],
      );
      if (head.rowCount !== 1) {
        throw apiError(404, "not_found", "audit head not found");
      }
      const inserted = await client.query<{
        id: string;
        sequence: string;
        head_hash: string;
        exported_at: Date;
        destination: string;
      }>(
        `INSERT INTO audit_head_exports (organization_id, sequence, head_hash, destination)
         VALUES ($1, $2, $3, $4)
         RETURNING id::text, sequence::text, head_hash, exported_at, destination`,
        [organizationId, head.rows[0].last_sequence, head.rows[0].last_hash, destination],
      );
      const row = inserted.rows[0];
      return {
        id: row.id,
        sequence: Number(row.sequence),
        head_hash: row.head_hash,
        exported_at: row.exported_at.toISOString(),
        destination: row.destination,
      };
    });
  }

  async listExports(organizationId: string): Promise<{ items: AuditHeadExport[] }> {
    const pool = this.requirePool();
    return withOrganization(pool, organizationId, async (client) => {
      const result = await client.query<{
        id: string;
        sequence: string;
        head_hash: string;
        exported_at: Date;
        destination: string;
      }>(
        `SELECT id::text, sequence::text, head_hash, exported_at, destination
         FROM audit_head_exports
         WHERE organization_id = $1
         ORDER BY exported_at DESC, id DESC
         LIMIT 50`,
        [organizationId],
      );
      return {
        items: result.rows.map((row) => ({
          id: row.id,
          sequence: Number(row.sequence),
          head_hash: row.head_hash,
          exported_at: row.exported_at.toISOString(),
          destination: row.destination,
        })),
      };
    });
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    return this.pool;
  }
}
