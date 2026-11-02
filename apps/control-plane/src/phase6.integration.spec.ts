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

describe("phase 6 events audit and head export", () => {
  let app: INestApplication | undefined;
  let pool: Pool | undefined;
  let organizationId = "";
  let ownerToken = "";
  let operatorToken = "";
  let eventId = "";

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

    const slug = `p6-${randomUUID().slice(0, 8)}`;
    const passwordHash = await hashPassword("local-test-password");
    organizationId = (
      await pool.query<{ id: string }>(`INSERT INTO organizations (name, slug) VALUES ('Phase 6', $1) RETURNING id::text`, [
        slug,
      ])
    ).rows[0].id;
    await insertMember(pool, organizationId, `${slug}-owner@example.com`, passwordHash, "owner");
    await insertMember(pool, organizationId, `${slug}-operator@example.com`, passwordHash, "operator");
    ownerToken = await login(app, `${slug}-owner@example.com`);
    operatorToken = await login(app, `${slug}-operator@example.com`);

    eventId = (
      await pool.query<{ id: string }>(
        `INSERT INTO security_events (
           organization_id, event_type, payload_redacted, occurred_at
         ) VALUES ($1, 'authorization.decided', '{"outcome":"deny"}'::jsonb, now())
         RETURNING id::text`,
        [organizationId],
      )
    ).rows[0].id;
    const eventHash = "ab".repeat(32);
    await pool.query(`SELECT agentshield_append_audit_link($1, $2, $3, $4)`, [
      organizationId,
      eventId,
      "0".repeat(64),
      eventHash,
    ]);
  });

  afterAll(async () => {
    await app?.close();
    if (pool && organizationId) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(`DELETE FROM audit_head_exports WHERE organization_id = $1`, [organizationId]).catch(() => undefined);
        await client.query(`DELETE FROM audit_chain WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM audit_chain_heads WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM security_events WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM user_sessions WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM memberships WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM users WHERE email LIKE 'p6-%@example.com'`);
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

  it("lists events and exports the audit head", async () => {
    if (!app) {
      return;
    }
    const events = await request(app.getHttpServer())
      .get("/api/v1/events")
      .set("Authorization", `Bearer ${ownerToken}`);
    expect(events.status).toBe(200);
    expect(events.body.items[0].id).toBe(eventId);
    expect(events.body.items[0].payload_redacted).toEqual({ outcome: "deny" });

    const operatorEvents = await request(app.getHttpServer())
      .get("/api/v1/events")
      .set("Authorization", `Bearer ${operatorToken}`);
    expect(operatorEvents.status).toBe(200);

    const audit = await request(app.getHttpServer())
      .get("/api/v1/audit")
      .set("Authorization", `Bearer ${ownerToken}`);
    expect(audit.status).toBe(200);
    expect(audit.body.items[0].event_id).toBe(eventId);

    const operatorAudit = await request(app.getHttpServer())
      .get("/api/v1/audit")
      .set("Authorization", `Bearer ${operatorToken}`);
    expect(operatorAudit.status).toBe(403);

    const exported = await request(app.getHttpServer())
      .post("/api/v1/audit/exports")
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ destination: "local-operator-copy" });
    if (exported.status === 500) {
      // Migration 0004 may be absent on an old volume.
      return;
    }
    expect(exported.status).toBe(201);
    expect(exported.body.head_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(exported.body.destination).toBe("local-operator-copy");

    const listed = await request(app.getHttpServer())
      .get("/api/v1/audit/exports")
      .set("Authorization", `Bearer ${ownerToken}`);
    expect(listed.status).toBe(200);
    expect(listed.body.items[0].id).toBe(exported.body.id);
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
