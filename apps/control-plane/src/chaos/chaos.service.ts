import { Inject, Injectable } from "@nestjs/common";
import type { Pool } from "pg";
import { DATABASE_POOL } from "../db/database";
import { setOrganization } from "../db/organization";
import { apiError } from "../http/errors";
import { CATALOG } from "./catalog";
import { CHAOS_RUNNER, type ChaosRun, type ChaosRunner } from "./runner";

export interface ExperimentRecord {
  id: string;
  scenario_id: string;
  agent_id: string;
  status: "pending" | "running" | "passed" | "failed" | "error";
  actual_result?: { reason: string };
}

@Injectable()
export class ChaosService {
  constructor(
    @Inject(DATABASE_POOL) private readonly pool: Pool | null,
    @Inject(CHAOS_RUNNER) private readonly runner: ChaosRunner,
  ) {}

  async create(organizationId: string, agentId: string, scenarioId: string): Promise<ExperimentRecord> {
    const pool = this.requirePool();
    await this.ensureCatalog(pool);
    const client = await pool.connect();
    let experimentId = "";
    try {
      await client.query("BEGIN");
      await setOrganization(client, organizationId);
      const scenario = await client.query<{ enabled: boolean }>(
        `SELECT enabled FROM chaos_scenarios WHERE id = $1`,
        [scenarioId],
      );
      if (scenario.rowCount !== 1) {
        throw apiError(404, "not_found", "scenario not found");
      }
      if (!scenario.rows[0].enabled) {
        throw apiError(409, "conflict", "scenario is disabled");
      }
      const agent = await client.query(`SELECT id FROM agents WHERE id = $1 AND organization_id = $2`, [
        agentId,
        organizationId,
      ]);
      if (agent.rowCount !== 1) {
        throw apiError(404, "not_found", "agent not found");
      }
      const inserted = await client.query<{ id: string }>(
        `INSERT INTO chaos_executions (
           organization_id, scenario_id, agent_id, status, payload, started_at
         ) VALUES ($1, $2, $3, 'running', '{"catalog":"chaos-engine/scenarios/CATALOG.md"}'::jsonb, now())
         RETURNING id::text`,
        [organizationId, scenarioId, agentId],
      );
      experimentId = inserted.rows[0].id;
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      if (isHttp(error)) {
        throw error;
      }
      throw apiError(500, "internal_error", "internal error");
    } finally {
      client.release();
    }

    let outcome: ChaosRun = { status: "error", reason: "runner unavailable" };
    try {
      const ran = await this.runner.run(scenarioId);
      if (ran.status === "passed" || ran.status === "failed" || ran.status === "error") {
        outcome = { status: ran.status, reason: ran.reason || "missing result" };
      }
    } catch {
      outcome = { status: "error", reason: "runner unavailable" };
    }
    await pool.query(
      `UPDATE chaos_executions
       SET status = $3, actual_result = $4::jsonb, finished_at = now()
       WHERE id = $1 AND organization_id = $2`,
      [experimentId, organizationId, outcome.status, JSON.stringify({ reason: outcome.reason })],
    );
    return this.get(organizationId, experimentId);
  }

  async get(organizationId: string, experimentId: string): Promise<ExperimentRecord> {
    const pool = this.requirePool();
    const result = await pool.query<ExperimentRow>(
      `SELECT id::text, scenario_id, agent_id::text, status, actual_result
       FROM chaos_executions
       WHERE id = $1 AND organization_id = $2`,
      [experimentId, organizationId],
    );
    if (result.rowCount !== 1) {
      throw apiError(404, "not_found", "experiment not found");
    }
    return toRecord(result.rows[0]);
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    return this.pool;
  }

  private async ensureCatalog(pool: Pool): Promise<void> {
    for (const scenario of CATALOG) {
      await pool.query(
        `INSERT INTO chaos_scenarios (id, description, preconditions, expected_behavior, enabled)
         VALUES ($1, $2, '{}'::jsonb, $3, true)
         ON CONFLICT (id) DO NOTHING`,
        [scenario.id, scenario.description, scenario.expected_behavior],
      );
    }
  }
}

interface ExperimentRow {
  id: string;
  scenario_id: string;
  agent_id: string;
  status: ExperimentRecord["status"];
  actual_result: { reason?: string } | null;
}

function toRecord(row: ExperimentRow): ExperimentRecord {
  const record: ExperimentRecord = {
    id: row.id,
    scenario_id: row.scenario_id,
    agent_id: row.agent_id,
    status: row.status,
  };
  if (row.actual_result && typeof row.actual_result.reason === "string") {
    record.actual_result = { reason: row.actual_result.reason };
  }
  return record;
}

function isHttp(error: unknown): boolean {
  return typeof error === "object" && error !== null && "getStatus" in error;
}
