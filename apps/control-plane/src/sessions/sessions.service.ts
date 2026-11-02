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
    const result = await this.loginCandidates(email);
    const memberships = result.filter((row) => row.organization_id);
    const uniqueUsers = new Set(result.map((row) => row.id));
    if (uniqueUsers.size !== 1 || result[0]?.status !== "active" || memberships.length !== 1) {
      await verifyPassword(await this.dummy(), password);
      if (uniqueUsers.size === 1 && result[0]?.status === "active" && memberships.length !== 1) {
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
    await this.createSession(user.id, user.organization_id ?? "", hashSessionToken(token), expires);
    return {
      token,
      token_type: "bearer",
      expires_at: expires.toISOString(),
      organization_id: user.organization_id ?? "",
    };
  }

  private async loginCandidates(email: string): Promise<
    { id: string; password_hash: string; status: string; organization_id: string | null }[]
  > {
    try {
      const result = await this.pool!.query<{
        user_id: string;
        password_hash: string;
        user_status: string;
        organization_id: string | null;
      }>(`SELECT user_id::text, password_hash, user_status, organization_id::text FROM agentshield_login_candidates($1)`, [
        email,
      ]);
      return result.rows.map((row) => ({
        id: row.user_id,
        password_hash: row.password_hash,
        status: row.user_status,
        organization_id: row.organization_id,
      }));
    } catch {
      const result = await this.pool!.query<{
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
      return result.rows;
    }
  }

  private async createSession(
    userId: string,
    organizationId: string,
    tokenHash: Buffer,
    expires: Date,
  ): Promise<void> {
    try {
      await this.pool!.query(`SELECT agentshield_create_session($1, $2, $3, $4)`, [
        userId,
        organizationId,
        tokenHash,
        expires,
      ]);
    } catch {
      await this.pool!.query(
        `INSERT INTO user_sessions (user_id, organization_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [userId, organizationId, tokenHash, expires],
      );
    }
  }

  private dummy(): Promise<string> {
    this.dummyHash ??= hashPassword("agentshield-dummy-password");
    return this.dummyHash;
  }
}
