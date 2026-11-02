import { Inject, Injectable } from "@nestjs/common";
import { createHash } from "crypto";
import type { Pool, PoolClient } from "pg";
import { appendAudit } from "../audit/append";
import { DATABASE_POOL } from "../db/database";
import { setOrganization } from "../db/organization";
import { apiError } from "../http/errors";

export interface AgentRecord {
  id: string;
  organization_id: string;
  name: string;
  framework: string;
  status: "active" | "suspended" | "revoked";
  credential_status: "active" | "rotated" | "revoked" | "none";
  registered_at: string;
  last_activity_at: string | null;
}

@Injectable()
export class AgentsService {
  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async create(
    organizationId: string,
    input: { name: string; framework: string; publicKey: Buffer },
  ): Promise<AgentRecord> {
    const pool = this.requirePool();
    const fingerprint = createHash("sha256").update(input.publicKey).digest("hex");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await setOrganization(client, organizationId);
      const agent = await client.query<{ id: string }>(
        `INSERT INTO agents (organization_id, name, framework)
         VALUES ($1, $2, $3)
         RETURNING id::text`,
        [organizationId, input.name, input.framework],
      );
      await client.query(
        `INSERT INTO agent_credentials (agent_id, organization_id, public_key, public_key_fingerprint)
         VALUES ($1, $2, $3, $4)`,
        [agent.rows[0].id, organizationId, input.publicKey, fingerprint],
      );
      await client.query("COMMIT");
      const created = await this.get(organizationId, agent.rows[0].id);
      if (!created) {
        throw apiError(500, "internal_error", "internal error");
      }
      return created;
    } catch (error) {
      await client.query("ROLLBACK");
      if (constraint(error, "agents_org_name_uq")) {
        throw apiError(409, "conflict", "an agent with that name already exists");
      }
      if (constraint(error, "agent_credentials_public_key_fingerprint_key")) {
        throw apiError(409, "conflict", "public key is already registered");
      }
      if (isHttp(error)) {
        throw error;
      }
      throw apiError(500, "internal_error", "internal error");
    } finally {
      client.release();
    }
  }

  async list(organizationId: string, limit: number, cursor: string | undefined): Promise<{ items: AgentRecord[]; next_cursor: string | null }> {
    const pool = this.requirePool();
    const cursorParts = decodeCursor(cursor);
    const result = await pool.query<AgentRow>(
      `${agentSelect()}
       WHERE a.organization_id = $1
         AND ($2::timestamptz IS NULL OR (a.registered_at, a.id) < ($2::timestamptz, $3::uuid))
       ORDER BY a.registered_at DESC, a.id DESC
       LIMIT $4`,
      [organizationId, cursorParts?.at ?? null, cursorParts?.id ?? null, limit + 1],
    );
    const page = result.rows.slice(0, limit).map(toAgent);
    const next = result.rows.length > limit ? encodeCursor(page[page.length - 1]) : null;
    return { items: page, next_cursor: next };
  }

  async suspend(organizationId: string, agentId: string): Promise<AgentRecord> {
    return this.changeStatus(organizationId, agentId, "suspended");
  }

  async revoke(organizationId: string, agentId: string): Promise<AgentRecord> {
    return this.changeStatus(organizationId, agentId, "revoked");
  }

  async rotate(
    organizationId: string,
    agentId: string,
    publicKey: Buffer,
  ): Promise<{ id: string; agent_id: string; algorithm: "ed25519"; fingerprint: string; status: "active" }> {
    const fingerprint = createHash("sha256").update(publicKey).digest("hex");
    return this.transaction(organizationId, async (client) => {
      const status = await lockAgent(client, organizationId, agentId);
      if (status !== "active") {
        throw apiError(409, "conflict", "agent is not active");
      }
      const rotated = await client.query(
        `UPDATE agent_credentials
         SET status = 'rotated'
         WHERE agent_id = $1 AND organization_id = $2 AND status = 'active'`,
        [agentId, organizationId],
      );
      if (rotated.rowCount !== 1) {
        throw apiError(409, "conflict", "agent does not have one active credential");
      }
      let created: { id: string };
      try {
        const inserted = await client.query<{ id: string }>(
          `INSERT INTO agent_credentials (agent_id, organization_id, public_key, public_key_fingerprint)
           VALUES ($1, $2, $3, $4)
           RETURNING id::text`,
          [agentId, organizationId, publicKey, fingerprint],
        );
        created = inserted.rows[0];
      } catch (error) {
        if (constraint(error, "agent_credentials_public_key_fingerprint_key")) {
          throw apiError(409, "conflict", "public key is already registered");
        }
        throw error;
      }
      await appendAudit(client, {
        organizationId,
        agentId,
        executionId: null,
        eventType: "credential.rotated",
        payload: { credential_id: created.id, fingerprint, status: "active" },
      });
      return { id: created.id, agent_id: agentId, algorithm: "ed25519", fingerprint, status: "active" };
    });
  }

  async get(organizationId: string, agentId: string): Promise<AgentRecord | undefined> {
    const pool = this.requirePool();
    const result = await pool.query<AgentRow>(
      `${agentSelect()} WHERE a.organization_id = $1 AND a.id = $2`,
      [organizationId, agentId],
    );
    return result.rows[0] ? toAgent(result.rows[0]) : undefined;
  }

  private async changeStatus(
    organizationId: string,
    agentId: string,
    next: "suspended" | "revoked",
  ): Promise<AgentRecord> {
    await this.transaction(organizationId, async (client) => {
      const status = await lockAgent(client, organizationId, agentId);
      if (status === next) {
        return;
      }
      if (status === "revoked") {
        throw apiError(409, "conflict", "agent is revoked");
      }
      await client.query(`UPDATE agents SET status = $3 WHERE id = $1 AND organization_id = $2`, [
        agentId,
        organizationId,
        next,
      ]);
      if (next === "revoked") {
        await client.query(
          `UPDATE agent_credentials
           SET status = 'revoked', revoked_at = now()
           WHERE agent_id = $1 AND organization_id = $2 AND status <> 'revoked'`,
          [agentId, organizationId],
        );
      }
      await appendAudit(client, {
        organizationId,
        agentId,
        executionId: null,
        eventType: next === "revoked" ? "agent.revoked" : "agent.suspended",
        payload: { status: next },
      });
    });
    const agent = await this.get(organizationId, agentId);
    if (!agent) {
      throw apiError(500, "internal_error", "internal error");
    }
    return agent;
  }

  private async transaction<T>(organizationId: string, work: (client: PoolClient) => Promise<T>): Promise<T> {
    const pool = this.requirePool();
    let last: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await setOrganization(client, organizationId);
        const result = await work(client);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK");
        if (isSerialization(error)) {
          last = error;
          continue;
        }
        if (isHttp(error)) {
          throw error;
        }
        throw apiError(500, "internal_error", "internal error");
      } finally {
        client.release();
      }
    }
    if (last) {
      throw apiError(500, "internal_error", "internal error");
    }
    throw apiError(500, "internal_error", "internal error");
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    return this.pool;
  }
}

interface AgentRow {
  id: string;
  organization_id: string;
  name: string;
  framework: string;
  status: AgentRecord["status"];
  credential_status: AgentRecord["credential_status"];
  registered_at: Date;
  last_activity_at: Date | null;
}

function agentSelect(): string {
  return `SELECT a.id::text, a.organization_id::text, a.name, a.framework, a.status,
            COALESCE((
              SELECT c.status FROM agent_credentials c
              WHERE c.agent_id = a.id AND c.organization_id = a.organization_id
              ORDER BY CASE c.status WHEN 'active' THEN 0 WHEN 'rotated' THEN 1 ELSE 2 END, c.created_at DESC
              LIMIT 1
            ), 'none') AS credential_status,
            a.registered_at, a.last_activity_at
     FROM agents a`;
}

function toAgent(row: AgentRow): AgentRecord {
  return {
    id: row.id,
    organization_id: row.organization_id,
    name: row.name,
    framework: row.framework,
    status: row.status,
    credential_status: row.credential_status,
    registered_at: row.registered_at.toISOString(),
    last_activity_at: row.last_activity_at ? row.last_activity_at.toISOString() : null,
  };
}

function encodeCursor(agent: AgentRecord): string {
  return Buffer.from(`${agent.registered_at}|${agent.id}`, "utf8").toString("base64url");
}

function decodeCursor(cursor: string | undefined): { at: string; id: string } | undefined {
  if (!cursor) {
    return undefined;
  }
  const decoded = Buffer.from(cursor, "base64url").toString("utf8");
  const split = decoded.lastIndexOf("|");
  if (split <= 0) {
    throw apiError(400, "validation_failed", "cursor is invalid");
  }
  const at = decoded.slice(0, split);
  const id = decoded.slice(split + 1);
  if (Number.isNaN(Date.parse(at)) || !/^[0-9a-f-]{36}$/i.test(id)) {
    throw apiError(400, "validation_failed", "cursor is invalid");
  }
  return { at, id };
}

async function lockAgent(client: PoolClient, organizationId: string, agentId: string): Promise<AgentRecord["status"]> {
  const result = await client.query<{ status: AgentRecord["status"] }>(
    `SELECT status FROM agents WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
    [agentId, organizationId],
  );
  if (!result.rows[0]) {
    throw apiError(404, "not_found", "agent not found");
  }
  return result.rows[0].status;
}

function isSerialization(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && (error as { code?: string }).code === "40001";
}

function constraint(error: unknown, name: string): boolean {
  return typeof error === "object" && error !== null && "constraint" in error && (error as { constraint?: string }).constraint === name;
}

function isHttp(error: unknown): boolean {
  return typeof error === "object" && error !== null && "getStatus" in error;
}
