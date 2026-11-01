import { Inject, Injectable } from "@nestjs/common";
import type { Pool, PoolClient } from "pg";
import { DATABASE_POOL } from "../db/database";
import { apiError } from "../http/errors";
import { documentHash, validatePolicyDocument, canonicalJson, type PolicyDocument } from "./document";

export interface PolicyRecord {
  id: string;
  organization_id: string;
  name: string;
  scope: "organization" | "agent";
  agent_id: string | null;
  status: "draft" | "active" | "archived";
  current_version: number;
}

@Injectable()
export class PoliciesService {
  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async create(
    organizationId: string,
    userId: string,
    input: { name: string; scope: "organization" | "agent"; agentId?: string; document: unknown },
  ): Promise<PolicyRecord> {
    const document = this.document(input.document);
    if (input.scope === "organization" && input.agentId) {
      throw apiError(400, "validation_failed", "organization policies do not take an agent");
    }
    if (input.scope === "agent" && !input.agentId) {
      throw apiError(400, "validation_failed", "agent policies require an agent");
    }
    const pool = this.requirePool();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      if (input.scope === "agent") {
        const agent = await client.query(`SELECT 1 FROM agents WHERE id = $1 AND organization_id = $2`, [
          input.agentId,
          organizationId,
        ]);
        if (agent.rowCount !== 1) {
          throw apiError(404, "not_found", "agent not found");
        }
        const existing = await client.query(
          `SELECT 1 FROM security_policies
           WHERE organization_id = $1 AND agent_id = $2 AND scope = 'agent' AND status = 'active'`,
          [organizationId, input.agentId],
        );
        if ((existing.rowCount ?? 0) > 0) {
          throw apiError(409, "conflict", "this agent already has an active policy");
        }
      } else {
        const existing = await client.query(
          `SELECT 1 FROM security_policies
           WHERE organization_id = $1 AND scope = 'organization' AND status = 'active'`,
          [organizationId],
        );
        if ((existing.rowCount ?? 0) > 0) {
          throw apiError(409, "conflict", "this organization already has an active policy");
        }
      }
      const policy = await client.query<{ id: string }>(
        `INSERT INTO security_policies (organization_id, name, scope, agent_id, status)
         VALUES ($1, $2, $3, $4, 'active')
         RETURNING id::text`,
        [organizationId, input.name, input.scope, input.agentId ?? null],
      );
      const versionId = await insertVersion(client, policy.rows[0].id, organizationId, userId, 1, document);
      await client.query(`UPDATE security_policies SET current_version_id = $1 WHERE id = $2`, [
        versionId,
        policy.rows[0].id,
      ]);
      if (input.scope === "agent" && input.agentId) {
        await project(client, organizationId, input.agentId, versionId, document);
      }
      await client.query("COMMIT");
      const created = await this.get(organizationId, policy.rows[0].id);
      if (!created) {
        throw apiError(500, "internal_error", "internal error");
      }
      return created;
    } catch (error) {
      await client.query("ROLLBACK");
      if (constraint(error, "security_policies_org_name_uq")) {
        throw apiError(409, "conflict", "a policy with that name already exists");
      }
      if (isHttp(error)) {
        throw error;
      }
      throw apiError(500, "internal_error", "internal error");
    } finally {
      client.release();
    }
  }

  async replace(organizationId: string, userId: string, policyId: string, documentValue: unknown): Promise<PolicyRecord> {
    const document = this.document(documentValue);
    const pool = this.requirePool();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const current = await client.query<{ scope: "organization" | "agent"; agent_id: string | null; version: number }>(
        `SELECT p.scope, p.agent_id::text, v.version
         FROM security_policies p
         JOIN policy_versions v ON v.id = p.current_version_id AND v.organization_id = p.organization_id
         WHERE p.id = $1 AND p.organization_id = $2
         FOR UPDATE OF p`,
        [policyId, organizationId],
      );
      if (current.rowCount !== 1) {
        throw apiError(404, "not_found", "policy not found");
      }
      const row = current.rows[0];
      const versionId = await insertVersion(client, policyId, organizationId, userId, row.version + 1, document);
      await client.query(`UPDATE security_policies SET current_version_id = $1, status = 'active' WHERE id = $2`, [
        versionId,
        policyId,
      ]);
      if (row.scope === "agent" && row.agent_id) {
        await client.query(
          `DELETE FROM agent_permissions
           WHERE organization_id = $1
             AND policy_version_id IN (
               SELECT id FROM policy_versions WHERE policy_id = $2 AND organization_id = $1
             )`,
          [organizationId, policyId],
        );
        await project(client, organizationId, row.agent_id, versionId, document);
      }
      await client.query("COMMIT");
      const updated = await this.get(organizationId, policyId);
      if (!updated) {
        throw apiError(500, "internal_error", "internal error");
      }
      return updated;
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

  async list(organizationId: string): Promise<{ items: PolicyRecord[] }> {
    const pool = this.requirePool();
    const result = await pool.query<PolicyRow>(
      `${policySelect()} WHERE p.organization_id = $1 ORDER BY p.created_at DESC, p.id DESC`,
      [organizationId],
    );
    return { items: result.rows.map(toPolicy) };
  }

  async get(organizationId: string, policyId: string): Promise<PolicyRecord | undefined> {
    const pool = this.requirePool();
    const result = await pool.query<PolicyRow>(`${policySelect()} WHERE p.organization_id = $1 AND p.id = $2`, [
      organizationId,
      policyId,
    ]);
    return result.rows[0] ? toPolicy(result.rows[0]) : undefined;
  }

  private document(value: unknown): PolicyDocument {
    try {
      return validatePolicyDocument(value);
    } catch {
      throw apiError(400, "validation_failed", "policy document is invalid");
    }
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    return this.pool;
  }
}

async function insertVersion(
  client: PoolClient,
  policyId: string,
  organizationId: string,
  userId: string,
  version: number,
  document: PolicyDocument,
): Promise<string> {
  const canonical = canonicalJson(document);
  const hash = documentHash(document);
  const result = await client.query<{ id: string }>(
    `INSERT INTO policy_versions (policy_id, organization_id, version, document, document_hash, created_by)
     VALUES ($1, $2, $3, $4::jsonb, $5, $6)
     RETURNING id::text`,
    [policyId, organizationId, version, canonical, hash, userId],
  );
  return result.rows[0].id;
}

async function project(
  client: PoolClient,
  organizationId: string,
  agentId: string,
  versionId: string,
  document: PolicyDocument,
): Promise<void> {
  const lists: [string, string[]][] = [
    ["allow", document.permissions.allowed],
    ["deny", document.permissions.denied],
    ["require_approval", document.permissions.approval_required],
  ];
  for (const [effect, actions] of lists) {
    for (const action of actions) {
      await client.query(
        `INSERT INTO agent_permissions (agent_id, organization_id, action, effect, policy_version_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [agentId, organizationId, action, effect, versionId],
      );
    }
  }
  for (const rule of document.resource_rules ?? []) {
    await client.query(
      `INSERT INTO agent_permissions (agent_id, organization_id, action, effect, resource_pattern, policy_version_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [agentId, organizationId, rule.action, rule.effect, rule.resource, versionId],
    );
  }
}

interface PolicyRow {
  id: string;
  organization_id: string;
  name: string;
  scope: PolicyRecord["scope"];
  agent_id: string | null;
  status: PolicyRecord["status"];
  current_version: number;
}

function policySelect(): string {
  return `SELECT p.id::text, p.organization_id::text, p.name, p.scope, p.agent_id::text, p.status, v.version AS current_version
          FROM security_policies p
          JOIN policy_versions v ON v.id = p.current_version_id AND v.organization_id = p.organization_id`;
}

function toPolicy(row: PolicyRow): PolicyRecord {
  return {
    id: row.id,
    organization_id: row.organization_id,
    name: row.name,
    scope: row.scope,
    agent_id: row.agent_id,
    status: row.status,
    current_version: Number(row.current_version),
  };
}

function constraint(error: unknown, name: string): boolean {
  return typeof error === "object" && error !== null && "constraint" in error && (error as { constraint?: string }).constraint === name;
}

function isHttp(error: unknown): boolean {
  return typeof error === "object" && error !== null && "getStatus" in error;
}
