import { Body, Controller, Get, HttpCode, Param, Post, Req, UseGuards } from "@nestjs/common";
import { z } from "zod";
import { HumanSessionGuard, Roles, RolesGuard, type RequestWithPrincipal } from "../auth/guards";
import { apiError } from "../http/errors";
import { ChaosService, type ExperimentRecord } from "./chaos.service";

const createSchema = z
  .object({
    agent_id: z.string().uuid(),
    scenario_id: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  })
  .strict();

@Controller("v1/chaos/experiments")
@UseGuards(HumanSessionGuard, RolesGuard)
export class ChaosController {
  constructor(private readonly chaos: ChaosService) {}

  @Post()
  @HttpCode(201)
  @Roles("owner", "admin")
  create(@Req() request: RequestWithPrincipal, @Body() body: unknown): Promise<ExperimentRecord> {
    const parsed = createSchema.safeParse(body);
    if (!parsed.success) {
      throw apiError(400, "validation_failed", "request validation failed");
    }
    const current = principal(request);
    return this.chaos.create(current.organizationId, parsed.data.agent_id, parsed.data.scenario_id);
  }

  @Get(":experimentId")
  @Roles("owner", "admin")
  get(@Req() request: RequestWithPrincipal, @Param("experimentId") experimentId: string): Promise<ExperimentRecord> {
    if (!/^[0-9a-f-]{36}$/i.test(experimentId)) {
      throw apiError(400, "validation_failed", "experiment id is invalid");
    }
    return this.chaos.get(principal(request).organizationId, experimentId);
  }
}

function principal(request: RequestWithPrincipal): NonNullable<RequestWithPrincipal["principal"]> {
  if (!request.principal) {
    throw apiError(401, "unauthenticated", "authentication failed");
  }
  return request.principal;
}
