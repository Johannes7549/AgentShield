import { loadConfig } from "./configuration";

describe("loadConfig", () => {
  it("uses loopback defaults", () => {
    const config = loadConfig({});
    expect(config.environment).toBe("development");
    expect(config.host).toBe("127.0.0.1");
    expect(config.port).toBe(8080);
    expect(config.databaseUrl).toBeUndefined();
  });

  it("refuses production without the app role", () => {
    expect(() => loadConfig({ AGENTSHIELD_ENV: "production" })).toThrow(/agentshield_app/);
    expect(() =>
      loadConfig({
        AGENTSHIELD_ENV: "production",
        DATABASE_URL: "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield",
      }),
    ).toThrow(/agentshield_app/);
  });

  it("allows production with the app role", () => {
    const config = loadConfig({
      AGENTSHIELD_ENV: "production",
      DATABASE_URL: "postgres://agentshield_app:agentshield-app@127.0.0.1:5432/agentshield",
    });
    expect(config.environment).toBe("production");
    expect(config.enforceOrganizationIsolation).toBe(true);
  });

  it("rejects a non-postgres URL without echoing the secret", () => {
    const secret = "super-secret-password";
    try {
      loadConfig({ DATABASE_URL: `http://agentshield:${secret}@127.0.0.1/agentshield` });
      throw new Error("expected configuration to fail");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).not.toContain(secret);
    }
  });

  it("accepts a postgres URL", () => {
    const config = loadConfig({
      DATABASE_URL: "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield",
    });
    expect(config.databaseUrl).toContain("postgres://");
  });
});
