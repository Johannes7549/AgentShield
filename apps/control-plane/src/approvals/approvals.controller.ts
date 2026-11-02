import { Controller, Get, Param, Post, Req, UseGuards } from "@nestjs/common";
import { HumanSessionGuard, Roles, RolesGuard, type RequestWithPrincipal } from "../auth/guards";
import { apiError } from "../http/errors";
import { ApprovalsService, type ApprovalRecord } from "./approvals.service";

@Controller("v1/approvals")
@UseGuards(HumanSessionGuard, RolesGuard)
export class ApprovalsController {
  constructor(private readonly approvals: ApprovalsService) {}

  @Get()
  @Roles("owner", "admin", "approver")
  list(@Req() request: RequestWithPrincipal): Promise<{ items: ApprovalRecord[] }> {
    return this.approvals.list(principal(request).organizationId);
  }

  @Post(":approvalId/approve")
  @Roles("owner", "admin", "approver")
  approve(@Req() request: RequestWithPrincipal, @Param("approvalId") approvalId: string): Promise<ApprovalRecord> {
    const current = principal(request);
    return this.approvals.decide(current.organizationId, current.userId, approvalParam(approvalId), "approved");
  }

  @Post(":approvalId/reject")
  @Roles("owner", "admin", "approver")
  reject(@Req() request: RequestWithPrincipal, @Param("approvalId") approvalId: string): Promise<ApprovalRecord> {
    const current = principal(request);
    return this.approvals.decide(current.organizationId, current.userId, approvalParam(approvalId), "rejected");
  }
}

function principal(request: RequestWithPrincipal): NonNullable<RequestWithPrincipal["principal"]> {
  if (!request.principal) {
    throw apiError(401, "unauthenticated", "authentication failed");
  }
  return request.principal;
}

function approvalParam(approvalId: string): string {
  if (!/^[0-9a-f-]{36}$/i.test(approvalId)) {
    throw apiError(400, "validation_failed", "approval id is invalid");
  }
  return approvalId;
}
