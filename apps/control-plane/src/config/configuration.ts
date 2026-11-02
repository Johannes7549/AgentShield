import { z } from "zod";

const portSchema = z.preprocess(
  (value) => (value === undefined || value === "" ? "8080" : value),
  z.coerce.number().int().min(1).max(65535),
);

const hostSchema = z.preprocess(
  (value) => (value === undefined || value === "" ? "127.0.0.1" : value),
  z.string().min(1),
);

const environmentSchema = z.preprocess(
  (value) => (value === undefined || value === "" ? "development" : value),
  z.enum(["development", "test", "production"]),
);

const databaseUrlSchema = z
  .string()
  .optional()
  .transform((value) => (value && value.length > 0 ? value : undefined))
  .refine((value) => value === undefined || isPostgresUrl(value), {
    message: "DATABASE_URL must be a postgres URL",
  });

const envSchema = z.object({
  AGENTSHIELD_ENV: environmentSchema,
  CONTROL_PLANE_HOST: hostSchema,
  CONTROL_PLANE_PORT: portSchema,
  DATABASE_URL: databaseUrlSchema,
});

export interface AppConfig {
  environment: "development" | "test" | "production";
  host: string;
  port: number;
  databaseUrl?: string;
  enforceOrganizationIsolation: boolean;
}

export const APP_CONFIG = Symbol("APP_CONFIG");

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const fields = parsed.error.issues.map((issue) => issue.path.join(".") || "configuration").join(", ");
    throw new Error(`invalid control plane configuration: ${fields}`);
  }
  const databaseUrl = parsed.data.DATABASE_URL;
  const appRole = isAppRoleUrl(databaseUrl);
  if (parsed.data.AGENTSHIELD_ENV === "production" && !appRole) {
    throw new Error(
      "production mode requires DATABASE_URL to use the agentshield_app role with row level security",
    );
  }
  return {
    environment: parsed.data.AGENTSHIELD_ENV,
    host: parsed.data.CONTROL_PLANE_HOST,
    port: parsed.data.CONTROL_PLANE_PORT,
    databaseUrl,
    enforceOrganizationIsolation: appRole,
  };
}

export function isAppRoleUrl(value: string | undefined): boolean {
  if (!value) {
    return false;
  }
  try {
    return new URL(value).username === "agentshield_app";
  } catch {
    return false;
  }
}

function isPostgresUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "postgres:" || url.protocol === "postgresql:") && url.hostname.length > 0;
  } catch {
    return false;
  }
}
