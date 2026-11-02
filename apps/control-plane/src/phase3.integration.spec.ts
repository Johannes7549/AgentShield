import { generateKeyPairSync, randomUUID } from "crypto";
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

describe("phase 3 credential and approval lifecycle", () => {
  let app: INestApplication | undefined;
  let pool: Pool | undefined;
  let organizationId = "";
  let ownerToken = "";
  let operatorToken = "";
  let approverToken = "";

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

    const slug = `p3-${randomUUID().slice(0, 8)}`;
    const passwordHash = await hashPassword("local-test-password");
    organizationId = (
      await pool.query<{ id: string }>(`INSERT INTO organizations (name, slug) VALUES ('Phase 3', $1) RETURNING id::text`, [
        slug,
      ])
    ).rows[0].id;
    await insertMember(pool, organizationId, `${slug}-owner@example.com`, passwordHash, "owner");
    await insertMember(pool, organizationId, `${slug}-operator@example.com`, passwordHash, "operator");
    await insertMember(pool, organizationId, `${slug}-approver@example.com`, passwordHash, "approver");
    ownerToken = await login(app, `${slug}-owner@example.com`);
    operatorToken = await login(app, `${slug}-operator@example.com`);
    approverToken = await login(app, `${slug}-approver@example.com`);
  });

  afterAll(async () => {
    await app?.close();
    if (pool && organizationId) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(`DELETE FROM audit_chain WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM audit_chain_heads WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM security_events WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM approval_requests WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM authorization_decisions WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM tool_invocations WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM executions WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM user_sessions WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM agent_credentials WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM agents WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM memberships WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM users WHERE email LIKE 'p3-%@example.com'`);
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

  it("rotates, suspends, and revokes through an owner session", async () => {
    if (!app || !pool) {
      return;
    }
    const created = await request(app.getHttpServer())
      .post("/api/v1/agents")
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ name: "phase3-agent", framework: "python", public_key: rawKey() });
    expect(created.status).toBe(201);
    const agentId = created.body.id as string;

    const operatorRevoke = await request(app.getHttpServer())
      .post(`/api/v1/agents/${agentId}/revoke`)
      .set("Authorization", `Bearer ${operatorToken}`);
    expect(operatorRevoke.status).toBe(403);

    const rotated = await request(app.getHttpServer())
      .post(`/api/v1/agents/${agentId}/credentials/rotate`)
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ public_key: rawKey() });
    expect(rotated.status).toBe(201);
    expect(rotated.body.status).toBe("active");
    expect(rotated.body.algorithm).toBe("ed25519");
    expect(rotated.body.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(rotated.body)).not.toContain("public_key");

    const suspended = await request(app.getHttpServer())
      .post(`/api/v1/agents/${agentId}/suspend`)
      .set("Authorization", `Bearer ${ownerToken}`);
    expect(suspended.status).toBe(200);
    expect(suspended.body.status).toBe("suspended");
    expect(suspended.body.credential_status).toBe("active");

    const rotateWhileSuspended = await request(app.getHttpServer())
      .post(`/api/v1/agents/${agentId}/credentials/rotate`)
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ public_key: rawKey() });
    expect(rotateWhileSuspended.status).toBe(409);

    const revoked = await request(app.getHttpServer())
      .post(`/api/v1/agents/${agentId}/revoke`)
      .set("Authorization", `Bearer ${ownerToken}`);
    expect(revoked.status).toBe(200);
    expect(revoked.body.status).toBe("revoked");
    expect(revoked.body.credential_status).toBe("revoked");

    const suspendRevoked = await request(app.getHttpServer())
      .post(`/api/v1/agents/${agentId}/suspend`)
      .set("Authorization", `Bearer ${ownerToken}`);
    expect(suspendRevoked.status).toBe(409);
  });

  it("approves once, rejects a different request, and refuses the agent principal", async () => {
    if (!app || !pool) {
      return;
    }
    const created = await request(app.getHttpServer())
      .post("/api/v1/agents")
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({ name: "phase3-approval-agent", framework: "python", public_key: rawKey() });
    expect(created.status).toBe(201);
    const agentId = created.body.id as string;
    const pending = await insertApproval(pool, organizationId, agentId, "15 minutes");
    const rejected = await insertApproval(pool, organizationId, agentId, "15 minutes");
    const expired = await insertApproval(pool, organizationId, agentId, "-1 minutes");

    const missing = await request(app.getHttpServer())
      .post("/api/v1/approvals")
      .set("Authorization", `Bearer ${approverToken}`)
      .send({});
    expect(missing.status).toBe(404);

    const agentCall = await request(app.getHttpServer())
      .post(`/api/v1/approvals/${pending}/approve`)
      .set("X-AgentShield-Signature", "not-a-human");
    expect(agentCall.status).toBe(401);

    const operator = await request(app.getHttpServer())
      .post(`/api/v1/approvals/${pending}/approve`)
      .set("Authorization", `Bearer ${operatorToken}`);
    expect(operator.status).toBe(403);

    const approved = await request(app.getHttpServer())
      .post(`/api/v1/approvals/${pending}/approve`)
      .set("Authorization", `Bearer ${approverToken}`);
    expect(approved.status).toBe(200);
    expect(approved.body.status).toBe("approved");
    expect(approved.body.payload_hash).toMatch(/^[0-9a-f]{64}$/);

    const again = await request(app.getHttpServer())
      .post(`/api/v1/approvals/${pending}/approve`)
      .set("Authorization", `Bearer ${approverToken}`);
    expect(again.status).toBe(409);

    const rejection = await request(app.getHttpServer())
      .post(`/api/v1/approvals/${rejected}/reject`)
      .set("Authorization", `Bearer ${approverToken}`);
    expect(rejection.status).toBe(200);
    expect(rejection.body.status).toBe("rejected");

    const stale = await request(app.getHttpServer())
      .post(`/api/v1/approvals/${expired}/approve`)
      .set("Authorization", `Bearer ${approverToken}`);
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe("approval_expired");

    const passwordHash = await hashPassword("local-test-password");
    await pool.query(
      `INSERT INTO users (id, email, password_hash, display_name) VALUES ($1, $2, $3, 'Agent Shaped User')`,
      [agentId, `p3-self-${agentId.slice(0, 8)}@example.com`, passwordHash],
    );
    await pool.query(`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'approver')`, [
      organizationId,
      agentId,
    ]);
    const selfToken = await login(app, `p3-self-${agentId.slice(0, 8)}@example.com`);
    const own = await insertApproval(pool, organizationId, agentId, "15 minutes");
    const selfApproval = await request(app.getHttpServer())
      .post(`/api/v1/approvals/${own}/approve`)
      .set("Authorization", `Bearer ${selfToken}`);
    expect(selfApproval.status).toBe(403);
    expect(selfApproval.body.error.code).toBe("self_approval");

    const listed = await request(app.getHttpServer())
      .get("/api/v1/approvals")
      .set("Authorization", `Bearer ${approverToken}`);
    expect(listed.status).toBe(200);
    const ids = (listed.body.items as { id: string }[]).map((item) => item.id);
    expect(ids).toContain(pending);
    expect(ids).not.toContain(randomUUID());
  });
});

function rawKey(): string {
  const { publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der).subarray(Buffer.from(der).length - 32).toString("base64url");
}

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

async function insertApproval(pool: Pool, organizationId: string, agentId: string, expiry: string): Promise<string> {
  const executionId = randomUUID();
  const hash = "ab".repeat(32);
  await pool.query(
    `INSERT INTO executions (organization_id, id, agent_id, status, metadata)
     VALUES ($1, $2, $3, 'awaiting_approval', $4::jsonb)`,
    [organizationId, executionId, agentId, JSON.stringify({ payload_hash: hash })],
  );
  const invocation = await pool.query<{ id: string }>(
    `INSERT INTO tool_invocations (
       organization_id, execution_id, agent_id, idempotency_key, tool_name, operation,
       resource, arguments_redacted, arguments_hash, requested_at
     ) VALUES ($1, $2, $3, $4, 'sample.echo', 'sample.echo', 'demo', '{}'::jsonb, $5, now())
     RETURNING id::text`,
    [organizationId, executionId, agentId, `idem-${executionId}`, hash],
  );
  const decision = await pool.query<{ id: string }>(
    `INSERT INTO authorization_decisions (
       organization_id, tool_invocation_id, agent_id, outcome, explanation, risk_level
     ) VALUES ($1, $2, $3, 'require_approval', '{"reason":"approval required"}'::jsonb, 'medium')
     RETURNING id::text`,
    [organizationId, invocation.rows[0].id, agentId],
  );
  const approval = await pool.query<{ id: string }>(
    `INSERT INTO approval_requests (
       organization_id, tool_invocation_id, authorization_decision_id, agent_id, payload_hash, expires_at
     ) VALUES ($1, $2, $3, $4, $5, now() + $6::interval)
     RETURNING id::text`,
    [organizationId, invocation.rows[0].id, decision.rows[0].id, agentId, hash, expiry],
  );
  return approval.rows[0].id;
}
