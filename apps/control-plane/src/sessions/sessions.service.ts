import { Inject, Injectable } from "@nestjs/common";
import { randomBytes } from "crypto";
import type { Pool } from "pg";
import { hashPassword, hashSessionToken, verifyPassword } from "../auth/passwords";
import { DATABASE_POOL } from "../db/database";
import { apiError } from "../http/errors";

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

@Injectable()
export class SessionsService {
  private dummyHash: Promise<string> | undefined;

  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async create(email: string, password: string): Promise<{
    token: string;
    token_type: "bearer";
    expires_at: string;
    organization_id: string;
  }> {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    const result = await this.pool.query<{
      id: string;
      password_hash: string;
      status: string;
      organization_id: string | null;
    }>(
      `SELECT u.id::text, u.password_hash, u.status, o.id::text AS organization_id
       FROM users u
       LEFT JOIN memberships m ON m.user_id = u.id
       LEFT JOIN organizations o ON o.id = m.organization_id AND o.status = 'active'
       WHERE u.email = $1`,
      [email],
    );
    const memberships = result.rows.filter((row) => row.organization_id);
    if (result.rows.length !== 1 || result.rows[0].status !== "active" || memberships.length !== 1) {
      await verifyPassword(await this.dummy(), password);
      if (result.rows.length === 1 && result.rows[0].status === "active" && memberships.length !== 1) {
        throw apiError(403, "forbidden", "user does not have one active organization");
      }
      throw apiError(401, "unauthenticated", "invalid email or password");
    }
    const user = memberships[0];
    const matches = await verifyPassword(user.password_hash, password);
    if (!matches) {
      throw apiError(401, "unauthenticated", "invalid email or password");
    }
    const token = randomBytes(32).toString("base64url");
    const expires = new Date(Date.now() + SESSION_TTL_MS);
    await this.pool.query(
      `INSERT INTO user_sessions (user_id, organization_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [user.id, user.organization_id, hashSessionToken(token), expires],
    );
    return {
      token,
      token_type: "bearer",
      expires_at: expires.toISOString(),
      organization_id: user.organization_id ?? "",
    };
  }

  private dummy(): Promise<string> {
    this.dummyHash ??= hashPassword("agentshield-dummy-password");
    return this.dummyHash;
  }
}
