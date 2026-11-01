import { CanActivate, ExecutionContext, Inject, Injectable, SetMetadata } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { createHash } from "crypto";
import type { Request } from "express";
import type { Pool } from "pg";
import { DATABASE_POOL } from "../db/database";
import { apiError } from "../http/errors";

export const ROLES = "roles";

export type Role = "owner" | "admin" | "operator" | "auditor" | "approver";

export interface Principal {
  userId: string;
  organizationId: string;
  role: Role;
}

export interface RequestWithPrincipal extends Request {
  principal?: Principal;
}

export const Roles = (...roles: Role[]): ReturnType<typeof SetMetadata> => SetMetadata(ROLES, roles);

@Injectable()
export class HumanSessionGuard implements CanActivate {
  constructor(@Inject(DATABASE_POOL) private readonly pool: Pool | null) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.pool) {
      throw apiError(500, "internal_error", "database is not configured");
    }
    const request = context.switchToHttp().getRequest<RequestWithPrincipal>();
    const header = request.header("authorization") ?? "";
    const match = /^Bearer ([A-Za-z0-9_-]{20,200})$/.exec(header);
    if (!match) {
      throw apiError(401, "unauthenticated", "authentication failed");
    }
    const tokenHash = createHash("sha256").update(match[1], "utf8").digest();
    let rows: { user_id: string; organization_id: string; role: Role }[];
    try {
      const result = await this.pool.query<{ user_id: string; organization_id: string; role: Role }>(
        `SELECT s.user_id::text, s.organization_id::text, m.role
         FROM user_sessions s
         JOIN memberships m ON m.user_id = s.user_id AND m.organization_id = s.organization_id
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1
           AND s.revoked_at IS NULL
           AND s.expires_at > now()
           AND u.status = 'active'`,
        [tokenHash],
      );
      rows = result.rows;
    } catch {
      throw apiError(500, "internal_error", "internal error");
    }
    if (rows.length !== 1) {
      throw apiError(401, "unauthenticated", "authentication failed");
    }
    request.principal = {
      userId: rows[0].user_id,
      organizationId: rows[0].organization_id,
      role: rows[0].role,
    };
    return true;
  }
}

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.get<Role[] | undefined>(ROLES, context.getHandler());
    if (!roles || roles.length === 0) {
      return true;
    }
    const request = context.switchToHttp().getRequest<RequestWithPrincipal>();
    if (!request.principal || !roles.includes(request.principal.role)) {
      throw apiError(403, "forbidden", "insufficient role");
    }
    return true;
  }
}
