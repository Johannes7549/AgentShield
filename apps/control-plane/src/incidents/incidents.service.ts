import { Inject, Injectable } from "@nestjs/common";
import type { Pool } from "pg";
import { DATABASE_POOL } from "../db/database";
import { withOrganization } from "../db/organization";
import { apiError } from "../http/errors";

export interface IncidentRecord {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "investigating" | "resolved" | "false_positive";
  title: string;
  detection_reason: string;
}

@Injectable()
export class IncidentsService {
  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async list(organizationId: string): Promise<{ items: IncidentRecord[] }> {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    return withOrganization(this.pool, organizationId, async (client) => {
      const result = await client.query<IncidentRecord>(
        `SELECT id::text, severity, status, title, detection_reason
         FROM security_incidents
         WHERE organization_id = $1
         ORDER BY opened_at DESC, id DESC
         LIMIT 200`,
        [organizationId],
      );
      return { items: result.rows };
    });
  }
}
