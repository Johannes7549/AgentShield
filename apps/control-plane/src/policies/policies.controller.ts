import { Body, Controller, Get, HttpCode, Param, Post, Put, Req, UseGuards } from "@nestjs/common";
import { z } from "zod";
import { HumanSessionGuard, Roles, RolesGuard, type RequestWithPrincipal } from "../auth/guards";
import { apiError } from "../http/errors";
import { PoliciesService, type PolicyRecord } from "./policies.service";

const createSchema = z
  .object({
    name: z.string().trim().min(1).max(128),
    scope: z.enum(["organization", "agent"]),
    agent_id: z.string().uuid().optional(),
    document: z.unknown(),
  })
  .strict();

const replaceSchema = z.object({ document: z.unknown() }).strict();

@Controller("v1/policies")
@UseGuards(HumanSessionGuard, RolesGuard)
export class PoliciesController {
  constructor(private readonly policies: PoliciesService) {}

  @Post()
  @HttpCode(201)
  @Roles("owner", "admin")
  create(@Req() request: RequestWithPrincipal, @Body() body: unknown): Promise<PolicyRecord> {
    const parsed = createSchema.safeParse(body);
    if (!parsed.success) {
      throw apiError(400, "validation_failed", "request validation failed");
    }
    const principal = required(request);
    return this.policies.create(principal.organizationId, principal.userId, {
      name: parsed.data.name,
      scope: parsed.data.scope,
      agentId: parsed.data.agent_id,
      document: parsed.data.document,
    });
  }

  @Get()
  list(@Req() request: RequestWithPrincipal): Promise<{ items: PolicyRecord[] }> {
    return this.policies.list(required(request).organizationId);
  }

  @Put(":policyId")
  @Roles("owner", "admin")
  replace(
    @Req() request: RequestWithPrincipal,
    @Param("policyId") policyId: string,
    @Body() body: unknown,
  ): Promise<PolicyRecord> {
    if (!/^[0-9a-f-]{36}$/i.test(policyId)) {
      throw apiError(400, "validation_failed", "policy id is invalid");
    }
    const parsed = replaceSchema.safeParse(body);
    if (!parsed.success) {
      throw apiError(400, "validation_failed", "request validation failed");
    }
    const principal = required(request);
    return this.policies.replace(principal.organizationId, principal.userId, policyId, parsed.data.document);
  }
}

function required(request: RequestWithPrincipal): NonNullable<RequestWithPrincipal["principal"]> {
  if (!request.principal) {
    throw apiError(401, "unauthenticated", "authentication failed");
  }
  return request.principal;
}
