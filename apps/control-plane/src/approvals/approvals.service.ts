import { Inject, Injectable } from "@nestjs/common";
import type { Pool, PoolClient } from "pg";
import { appendAudit } from "../audit/append";
import { DATABASE_POOL } from "../db/database";
import { setOrganization } from "../db/organization";
import { apiError } from "../http/errors";
import { rejectsSelfApproval } from "./self-approval";

export interface ApprovalRecord {
  id: string;
  organization_id: string;
  agent_id: string;
  status: "pending" | "approved" | "rejected" | "expired" | "consumed";
  payload_hash: string;
  expires_at: string;
}

@Injectable()
export class ApprovalsService {
  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async list(organizationId: string): Promise<{ items: ApprovalRecord[] }> {
    const pool = this.requirePool();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await setOrganization(client, organizationId);
      await expirePending(client, organizationId);
      const result = await client.query<ApprovalRow>(
        `${approvalSelect()}
         WHERE organization_id = $1
         ORDER BY created_at DESC, id DESC
         LIMIT 200`,
        [organizationId],
      );
      await client.query("COMMIT");
      return { items: result.rows.map(toApproval) };
    } catch (error) {
      await client.query("ROLLBACK");
      if (isHttp(error)) {
        throw error;
      }
      throw apiError(500, "internal_error", "internal error");
    } finally {
      client.release();
    }
  }

  async decide(
    organizationId: string,
    userId: string,
    approvalId: string,
    decision: "approved" | "rejected",
  ): Promise<ApprovalRecord> {
    const pool = this.requirePool();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await setOrganization(client, organizationId);
      await expirePending(client, organizationId);
      const locked = await client.query<ApprovalRow>(
        `${approvalSelect()} WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
        [approvalId, organizationId],
      );
      const row = locked.rows[0];
      if (!row) {
        throw apiError(404, "not_found", "approval not found");
      }
      if (rejectsSelfApproval(row.agent_id, userId)) {
        throw apiError(403, "self_approval", "an agent cannot approve its own action");
      }
      if (row.status === "expired") {
        throw apiError(409, "approval_expired", "approval has expired");
      }
      if (row.status !== "pending") {
        throw apiError(409, "conflict", "approval is not pending");
      }
      await client.query(
        `UPDATE approval_requests
         SET status = $3, decided_by = $4, decided_at = now()
         WHERE id = $1 AND organization_id = $2 AND status = 'pending'`,
        [approvalId, organizationId, decision, userId],
      );
      await appendAudit(client, {
        organizationId,
        agentId: row.agent_id,
        executionId: row.execution_id,
        eventType: "approval.decided",
        payload: { approval_id: row.id, decision, payload_hash: row.payload_hash },
      });
      await client.query("COMMIT");
      return toApproval({ ...row, status: decision });
    } catch (error) {
      await client.query("ROLLBACK");
      if (isHttp(error)) {
        throw error;
      }
      throw apiError(500, "internal_error", "internal error");
    } finally {
      client.release();
    }
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    return this.pool;
  }
}

interface ApprovalRow {
  id: string;
  organization_id: string;
  agent_id: string;
  execution_id: string;
  status: ApprovalRecord["status"];
  payload_hash: string;
  expires_at: Date;
}

function approvalSelect(): string {
  return `SELECT id::text, organization_id::text, agent_id::text,
            (
              SELECT ti.execution_id::text
              FROM tool_invocations ti
              WHERE ti.id = approval_requests.tool_invocation_id
                AND ti.organization_id = approval_requests.organization_id
            ) AS execution_id,
            status, payload_hash, expires_at
     FROM approval_requests`;
}

async function expirePending(client: PoolClient, organizationId: string): Promise<void> {
  await client.query(
    `UPDATE approval_requests
     SET status = 'expired'
     WHERE organization_id = $1 AND status = 'pending' AND expires_at <= now()`,
    [organizationId],
  );
}

function toApproval(row: ApprovalRow): ApprovalRecord {
  return {
    id: row.id,
    organization_id: row.organization_id,
    agent_id: row.agent_id,
    status: row.status,
    payload_hash: row.payload_hash,
    expires_at: row.expires_at.toISOString(),
  };
}

function isHttp(error: unknown): boolean {
  return typeof error === "object" && error !== null && "getStatus" in error;
}
