import { generateKeyPairSync, randomUUID } from "crypto";
import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { Pool } from "pg";
import request from "supertest";
import { hashPassword } from "./auth/passwords";
import { AppModule } from "./app.module";
import { applicationOptions, configureApp } from "./http/configure-app";
import { documentHash, validatePolicyDocument } from "./policies/document";

const databaseUrl =
  process.env.AGENTSHIELD_TEST_DATABASE_URL ??
  "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield?sslmode=disable";

describe("phase 1 control plane", () => {
  let app: INestApplication | undefined;
  let pool: Pool | undefined;
  let organizationId = "";

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

    const slug = `p1-${randomUUID().slice(0, 8)}`;
    const passwordHash = await hashPassword("local-test-password");
    const user = await pool.query<{ id: string }>(
      `INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Phase 1') RETURNING id::text`,
      [`${slug}@example.com`, passwordHash],
    );
    const organization = await pool.query<{ id: string }>(
      `INSERT INTO organizations (name, slug) VALUES ('Phase 1', $1) RETURNING id::text`,
      [slug],
    );
    organizationId = organization.rows[0].id;
    await pool.query(`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')`, [
      organizationId,
      user.rows[0].id,
    ]);
  });

  afterAll(async () => {
    await app?.close();
    if (pool && organizationId) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(`DELETE FROM user_sessions WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM agent_permissions WHERE organization_id = $1`, [organizationId]);
        await client.query(`UPDATE security_policies SET current_version_id = NULL WHERE organization_id = $1`, [
          organizationId,
        ]);
        await client.query(`ALTER TABLE policy_versions DISABLE TRIGGER policy_versions_append_only`);
        await client.query(`DELETE FROM policy_versions WHERE organization_id = $1`, [organizationId]);
        await client.query(`ALTER TABLE policy_versions ENABLE TRIGGER policy_versions_append_only`);
        await client.query(`DELETE FROM security_policies WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM agent_credentials WHERE organization_id = $1`, [organizationId]);
        await client.query(`DELETE FROM agents WHERE organization_id = $1`, [organizationId]);
        await client.query(
          `DELETE FROM memberships WHERE organization_id = $1`,
          [organizationId],
        );
        await client.query(`DELETE FROM users WHERE email LIKE $1`, [`p1-%@example.com`]);
        await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        await client.query(`ALTER TABLE policy_versions ENABLE TRIGGER policy_versions_append_only`);
        throw error;
      } finally {
        client.release();
        await pool.end();
      }
    }
  });

  it("registers an agent and an active policy for the session organization", async () => {
    if (!app || !pool) {
      return;
    }
    const login = await request(app.getHttpServer())
      .post("/api/v1/sessions")
      .send({ email: (await ownerEmail(pool, organizationId)), password: "local-test-password" });
    expect(login.status).toBe(201);
    expect(login.body.organization_id).toBe(organizationId);
    expect(login.body.token_type).toBe("bearer");

    const { publicKey } = generateKeyPairSync("ed25519");
    const der = publicKey.export({ format: "der", type: "spki" });
    const raw = Buffer.from(der).subarray(Buffer.from(der).length - 32);
    const created = await request(app.getHttpServer())
      .post("/api/v1/agents")
      .set("Authorization", `Bearer ${login.body.token}`)
      .send({ name: "sample-agent", framework: "python", public_key: raw.toString("base64url") });
    expect(created.status).toBe(201);
    expect(created.body.organization_id).toBe(organizationId);
    expect(created.body.credential_status).toBe("active");
    expect(JSON.stringify(created.body)).not.toContain("public_key");

    const document = {
      permissions: {
        allowed: ["sample.echo"],
        denied: ["database.export"],
        approval_required: ["email.send"],
      },
    };
    const policy = await request(app.getHttpServer())
      .post("/api/v1/policies")
      .set("Authorization", `Bearer ${login.body.token}`)
      .send({ name: "sample", scope: "organization", document });
    expect(policy.status).toBe(201);
    expect(policy.body.current_version).toBe(1);
    const stored = await pool.query<{ document_hash: string }>(
      `SELECT document_hash FROM policy_versions WHERE organization_id = $1`,
      [organizationId],
    );
    expect(stored.rows[0].document_hash).toBe(documentHash(validatePolicyDocument(document)));

    const duplicate = await request(app.getHttpServer())
      .post("/api/v1/policies")
      .set("Authorization", `Bearer ${login.body.token}`)
      .send({ name: "sample-2", scope: "organization", document });
    expect(duplicate.status).toBe(409);

    const listed = await request(app.getHttpServer())
      .get("/api/v1/agents")
      .set("Authorization", `Bearer ${login.body.token}`);
    expect(listed.status).toBe(200);
    expect(listed.body.items).toHaveLength(1);
  });
});

async function ownerEmail(pool: Pool, organizationId: string): Promise<string> {
  const result = await pool.query<{ email: string }>(
    `SELECT u.email::text FROM users u
     JOIN memberships m ON m.user_id = u.id
     WHERE m.organization_id = $1`,
    [organizationId],
  );
  return result.rows[0].email;
}
