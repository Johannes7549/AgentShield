import { randomUUID } from "crypto";
import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { Pool } from "pg";
import request from "supertest";
import { hashPassword } from "./auth/passwords";
import { AppModule } from "./app.module";
import { applicationOptions, configureApp } from "./http/configure-app";

const databaseUrl =
  process.env.AGENTSHIELD_TEST_DATABASE_URL ??
  "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield?sslmode=disable";

describe("phase 4 incident list", () => {
  let app: INestApplication | undefined;
  let pool: Pool | undefined;
  let organizationId = "";
  let ownerToken = "";
  let operatorToken = "";
  let auditorToken = "";
  let incidentId = "";

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
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication(applicationOptions);
    configureApp(app);
    await app.init();
    pool = new Pool({ connectionString: databaseUrl });

    const slug = `p4-${randomUUID().slice(0, 8)}`;
    const passwordHash = await hashPassword("local-test-password");
    organizationId = (
      await pool.query<{ id: string }>(`INSERT INTO organizations (name, slug) VALUES ('Phase 4', $1) RETURNING id::text`, [
        slug,
      ])
    ).rows[0].id;
    await insertMember(pool, organizationId, `${slug}-owner@example.com`, passwordHash, "owner");
    await insertMember(pool, organizationId, `${slug}-operator@example.com`, passwordHash, "operator");
    await insertMember(pool, organizationId, `${slug}-auditor@example.com`, passwordHash, "auditor");
    ownerToken = await login(app, `${slug}-owner@example.com`);
    operatorToken = await login(app, `${slug}-operator@example.com`);
    auditorToken = await login(app, `${slug}-auditor@example.com`);
    incidentId = (
      await pool.query<{ id: string }>(
        `INSERT INTO security_incidents (
           organization_id, severity, status, title, detection_reason, evidence
         ) VALUES ($1, 'medium', 'open', 'repeated denies', 'deny_burst', '{"rule":"deny_burst"}'::jsonb)
         RETURNING id::text`,
        [organizationId],
      )
    ).rows[0].id;
  });

  afterAll(async () => {
    await app?.close();
    if (pool && organizationId) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(`DELETE FROM security_incidents WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM user_sessions WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM memberships WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM users WHERE email LIKE 'p4-%@example.com'`);
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

  it("lets an auditor read incidents and refuses an operator", async () => {
    if (!app) {
      return;
    }
    const hidden = await request(app.getHttpServer())
      .get("/api/v1/incidents")
      .set("Authorization", `Bearer ${operatorToken}`);
    expect(hidden.status).toBe(403);

    const listed = await request(app.getHttpServer())
      .get("/api/v1/incidents")
      .set("Authorization", `Bearer ${auditorToken}`);
    expect(listed.status).toBe(200);
    expect(listed.body.items).toEqual([
      {
        id: incidentId,
        severity: "medium",
        status: "open",
        title: "repeated denies",
        detection_reason: "deny_burst",
      },
    ]);

    const owner = await request(app.getHttpServer())
      .get("/api/v1/incidents")
      .set("Authorization", `Bearer ${ownerToken}`);
    expect(owner.status).toBe(200);
    expect(owner.body.items).toHaveLength(1);
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
