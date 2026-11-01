import { Controller, Get, HttpCode, HttpStatus, Inject, Res } from "@nestjs/common";
import type { Response } from "express";
import type { Pool } from "pg";
import { APP_CONFIG, type AppConfig } from "../config/configuration";
import { DATABASE_POOL } from "../db/database";

export const SERVICE_VERSION = "0.1.0";

@Controller("health")
export class HealthController {
  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Inject(DATABASE_POOL) private readonly pool: Pool | null,
  ) {}

  @Get("live")
  @HttpCode(HttpStatus.OK)
  live(): Record<string, unknown> {
    return {
      status: "ok",
      service: "control-plane",
      version: SERVICE_VERSION,
      environment: this.config.environment,
      checks: { process: "ok", api: "ok" },
    };
  }

  @Get("ready")
  async ready(@Res() response: Response): Promise<void> {
    if (!this.pool) {
      response.status(HttpStatus.SERVICE_UNAVAILABLE).json({
        status: "not_ready",
        service: "control-plane",
        version: SERVICE_VERSION,
        environment: this.config.environment,
        reason: "database is not configured",
        checks: { process: "ok", api: "ok", database: "not_configured" },
      });
      return;
    }
    try {
      await this.pool.query("SELECT 1");
      response.status(HttpStatus.OK).json({
        status: "ok",
        service: "control-plane",
        version: SERVICE_VERSION,
        environment: this.config.environment,
        reason: "database answered",
        checks: { process: "ok", api: "ok", database: "ok" },
      });
    } catch {
      response.status(HttpStatus.SERVICE_UNAVAILABLE).json({
        status: "not_ready",
        service: "control-plane",
        version: SERVICE_VERSION,
        environment: this.config.environment,
        reason: "database is unavailable",
        checks: { process: "ok", api: "ok", database: "unavailable" },
      });
    }
  }
}
