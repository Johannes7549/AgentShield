import { randomUUID } from "crypto";
import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { Pool } from "pg";
import request from "supertest";
import { hashPassword } from "./auth/passwords";
import { AppModule } from "./app.module";
import { CHAOS_RUNNER, type ChaosRun } from "./chaos/runner";
import { applicationOptions, configureApp } from "./http/configure-app";

const databaseUrl =
  process.env.AGENTSHIELD_TEST_DATABASE_URL ??
  "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield?sslmode=disable";

const scripted = {
  async run(scenarioId: string): Promise<ChaosRun> {
    if (scenarioId === "network-failure") {
      return { status: "failed", reason: "missing result: a dependency error fails closed" };
    }
    return { status: "passed", reason: "an action outside allow and approval is denied" };
  },
};

describe("phase 5 chaos experiments", () => {
  let app: INestApplication | undefined;
  let pool: Pool | undefined;
  let organizationId = "";
  let ownerToken = "";
  let operatorToken = "";
  let agentId = "";

  beforeAll(async () => {
    if (!databaseUrl.includes("127.0.0.1") && !databaseUrl.includes("localhost")) {
      return;
    }
    const probe = new Pool({ connectionString: databaseUrl, connectionTimeoutMillis: 1000 });
    try {
      await probe.query("SELECT 1");
    } catch {
      return;
    } finally {
      await probe.end();
    }
    process.env.AGENTSHIELD_ENV = "test";
    process.env.DATABASE_URL = databaseUrl;
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(CHAOS_RUNNER)
      .useValue(scripted)
      .compile();
    app = moduleRef.createNestApplication(applicationOptions);
    configureApp(app);
    await app.init();
    pool = new Pool({ connectionString: databaseUrl });

    const slug = `p5-${randomUUID().slice(0, 8)}`;
    const passwordHash = await hashPassword("local-test-password");
    organizationId = (
      await pool.query<{ id: string }>(`INSERT INTO organizations (name, slug) VALUES ('Phase 5', $1) RETURNING id::text`, [
        slug,
      ])
    ).rows[0].id;
    await insertMember(pool, organizationId, `${slug}-owner@example.com`, passwordHash, "owner");
    await insertMember(pool, organizationId, `${slug}-operator@example.com`, passwordHash, "operator");
    ownerToken = await login(app, `${slug}-owner@example.com`);
    operatorToken = await login(app, `${slug}-operator@example.com`);
    agentId = (
      await pool.query<{ id: string }>(
        `INSERT INTO agents (organization_id, name, framework) VALUES ($1, 'phase5-agent', 'python') RETURNING id::text`,
        [organizationId],
      )
    ).rows[0].id;
    await pool.query(
      `INSERT INTO chaos_scenarios (id, description, preconditions, expected_behavior, enabled)
       VALUES ('phase5-disabled', 'Disabled probe', '{}'::jsonb, 'This scenario stays disabled.', false)
       ON CONFLICT (id) DO UPDATE SET enabled = false`,
    );
  });

  afterAll(async () => {
    await app?.close();
    if (pool && organizationId) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(`DELETE FROM chaos_executions WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM chaos_scenarios WHERE id = 'phase5-disabled'`);
        await client.query(`DELETE FROM user_sessions WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM agents WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM memberships WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM users WHERE email LIKE 'p5-%@example.com'`);
        await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
        await pool.end();
      }
    }
  });

  it("stores a pass and a missing result as a failure", async () => {
    if (!app) {
      return;
    }
    const refused = await request(app.getHttpServer())
      .post("/api/v1/chaos/experiments")
      .set("Authorization", `Bearer ${operatorToken}`)
      .send({ agent_id: agentId, scenario_id: "unauthorized-tool-invocation" });
    expect(refused.status).toBe(403);

    const unknown = await request(app.getHttpServer())
      .post("/api/v1/chaos/experiments")
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ agent_id: agentId, scenario_id: "not-a-scenario" });
    expect(unknown.status).toBe(404);

    const disabled = await request(app.getHttpServer())
      .post("/api/v1/chaos/experiments")
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ agent_id: agentId, scenario_id: "phase5-disabled" });
    expect(disabled.status).toBe(409);

    const passed = await request(app.getHttpServer())
      .post("/api/v1/chaos/experiments")
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ agent_id: agentId, scenario_id: "unauthorized-tool-invocation" });
    expect(passed.status).toBe(201);
    expect(passed.body.status).toBe("passed");
    expect(passed.body.actual_result.reason).toBe("an action outside allow and approval is denied");

    const loaded = await request(app.getHttpServer())
      .get(`/api/v1/chaos/experiments/${passed.body.id}`)
      .set("Authorization", `Bearer ${ownerToken}`);
    expect(loaded.status).toBe(200);
    expect(loaded.body.id).toBe(passed.body.id);

    const missing = await request(app.getHttpServer())
      .post("/api/v1/chaos/experiments")
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ agent_id: agentId, scenario_id: "network-failure" });
    expect(missing.status).toBe(201);
    expect(missing.body.status).toBe("failed");
    expect(missing.body.actual_result.reason).toContain("missing result");
  });
});

async function insertMember(
  pool: Pool,
  organizationId: string,
  email: string,
  passwordHash: string,
  role: string,
): Promise<void> {
  const user = await pool.query<{ id: string }>(
    `INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id::text`,
    [email, passwordHash, role],
  );
  await pool.query(`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, $3)`, [
    organizationId,
    user.rows[0].id,
    role,
  ]);
}

async function login(app: INestApplication, email: string): Promise<string> {
  const response = await request(app.getHttpServer())
    .post("/api/v1/sessions")
    .send({ email, password: "local-test-password" });
  if (response.status !== 201) {
    throw new Error(`login failed with ${response.status}`);
  }
  return response.body.token as string;
}
