import { Body, Controller, Get, HttpCode, Post, Req, UseGuards } from "@nestjs/common";
import { z } from "zod";
import { HumanSessionGuard, Roles, RolesGuard, type RequestWithPrincipal } from "../auth/guards";
import { apiError } from "../http/errors";
import { AuditService, type AuditHeadExport, type AuditLinkRecord } from "./audit.service";

const exportSchema = z
  .object({
    destination: z.string().trim().min(1).max(256),
  })
  .strict();

@Controller("v1/audit")
@UseGuards(HumanSessionGuard, RolesGuard)
export class AuditController {
  constructor(private readonly audit: AuditService) {}

  @Get()
  @Roles("owner", "admin", "auditor")
  list(@Req() request: RequestWithPrincipal): Promise<{ items: AuditLinkRecord[] }> {
    return this.audit.list(principal(request).organizationId);
  }

  @Post("exports")
  @HttpCode(201)
  @Roles("owner", "admin", "auditor")
  exportHead(@Req() request: RequestWithPrincipal, @Body() body: unknown): Promise<AuditHeadExport> {
    const parsed = exportSchema.safeParse(body);
    if (!parsed.success) {
      throw apiError(400, "validation_failed", "request validation failed");
    }
    return this.audit.exportHead(principal(request).organizationId, parsed.data.destination);
  }

  @Get("exports")
  @Roles("owner", "admin", "auditor")
  listExports(@Req() request: RequestWithPrincipal): Promise<{ items: AuditHeadExport[] }> {
    return this.audit.listExports(principal(request).organizationId);
  }
}

function principal(request: RequestWithPrincipal): NonNullable<RequestWithPrincipal["principal"]> {
  if (!request.principal) {
    throw apiError(401, "unauthenticated", "authentication failed");
  }
  return request.principal;
}
