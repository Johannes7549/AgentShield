import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import { HumanSessionGuard, Roles, RolesGuard, type RequestWithPrincipal } from "../auth/guards";
import { apiError } from "../http/errors";
import { IncidentsService, type IncidentRecord } from "./incidents.service";

@Controller("v1/incidents")
@UseGuards(HumanSessionGuard, RolesGuard)
export class IncidentsController {
  constructor(private readonly incidents: IncidentsService) {}

  @Get()
  @Roles("owner", "admin", "auditor")
  list(@Req() request: RequestWithPrincipal): Promise<{ items: IncidentRecord[] }> {
    if (!request.principal) {
      throw apiError(401, "unauthenticated", "authentication failed");
    }
    return this.incidents.list(request.principal.organizationId);
  }
}
