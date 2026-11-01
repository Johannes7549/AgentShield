import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { AppModule } from "../app.module";
import { applicationOptions, configureApp } from "../http/configure-app";

describe("health HTTP", () => {
  let app: INestApplication;
  const secret = "super-secret-password";

  beforeAll(async () => {
    process.env.AGENTSHIELD_ENV = "test";
    process.env.DATABASE_URL = `postgres://agentshield:${secret}@127.0.0.1:5432/agentshield`;
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleRef.createNestApplication(applicationOptions);
    configureApp(app);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it("answers liveness without revealing the database URL", async () => {
    const response = await request(app.getHttpServer()).get("/health/live");
    expect(response.status).toBe(200);
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.body).toMatchObject({
      status: "ok",
      service: "control-plane",
      environment: "test",
      checks: { process: "ok", api: "ok" },
    });
    expect(JSON.stringify(response.body)).not.toContain(secret);
  });

  it("is not ready when the database rejects the connection", async () => {
    const response = await request(app.getHttpServer()).get("/health/ready");
    expect(response.status).toBe(503);
    expect(response.body.status).toBe("not_ready");
    expect(JSON.stringify(response.body)).not.toContain(secret);
  });

  it("requires a human session before listing agents", async () => {
    const response = await request(app.getHttpServer()).get("/api/v1/agents");
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("unauthenticated");
    expect(JSON.stringify(response.body)).not.toContain(secret);
  });

  it("rejects an agent signature on the control plane", async () => {
    const response = await request(app.getHttpServer())
      .post("/api/v1/sessions")
      .set("X-AgentShield-Signature", "not-a-human-session")
      .send({ email: "owner@example.com", password: "change-me-local-only" });
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("unauthenticated");
  });

  it("rejects an oversized JSON body", async () => {
    const response = await request(app.getHttpServer())
      .post("/health/live")
      .send({ blob: "x".repeat(300 * 1024) });
    expect(response.status).toBe(413);
  });
});
