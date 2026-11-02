import { Injectable, OnApplicationShutdown, Inject } from "@nestjs/common";
import { Pool } from "pg";
import { APP_CONFIG, type AppConfig } from "../config/configuration";
import { wrapPool } from "./organization";

export const DATABASE_POOL = Symbol("DATABASE_POOL");

export function createPool(config: AppConfig): Pool | null {
  if (!config.databaseUrl) {
    return null;
  }
  const pool = new Pool({
    connectionString: withStatementTimeout(config.databaseUrl),
    max: 10,
    connectionTimeoutMillis: 2000,
  });
  pool.on("error", () => undefined);
  return config.enforceOrganizationIsolation ? wrapPool(pool) : pool;
}

function withStatementTimeout(url: string): string {
  const parsed = new URL(url);
  const existing = parsed.searchParams.get("options");
  const timeout = "-c statement_timeout=5000";
  parsed.searchParams.set("options", existing ? `${existing} ${timeout}` : timeout);
  return parsed.toString();
}

@Injectable()
export class DatabaseLifecycle implements OnApplicationShutdown {
  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async onApplicationShutdown(): Promise<void> {
    await this.pool?.end();
  }
}
