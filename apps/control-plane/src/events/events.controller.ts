import { Controller, Get, MessageEvent, Query, Req, Sse, UseGuards } from "@nestjs/common";
import { Observable, interval, switchMap, startWith } from "rxjs";
import { HumanSessionGuard, Roles, RolesGuard, type RequestWithPrincipal } from "../auth/guards";
import { apiError } from "../http/errors";
import { EventsService, type SecurityEventRecord } from "./events.service";

@Controller("v1/events")
@UseGuards(HumanSessionGuard, RolesGuard)
export class EventsController {
  constructor(private readonly events: EventsService) {}

  @Get()
  @Roles("owner", "admin", "auditor", "operator")
  list(
    @Req() request: RequestWithPrincipal,
    @Query("limit") limitRaw?: string,
    @Query("cursor") cursor?: string,
  ): Promise<{ items: SecurityEventRecord[]; next_cursor: string | null }> {
    return this.events.list(principal(request).organizationId, parseLimit(limitRaw), cursor);
  }

  @Sse("stream")
  @Roles("owner", "admin", "auditor", "operator")
  stream(@Req() request: RequestWithPrincipal): Observable<MessageEvent> {
    const organizationId = principal(request).organizationId;
    return interval(5000).pipe(
      startWith(0),
      switchMap(async () => {
        const page = await this.events.list(organizationId, 20, undefined);
        return { data: page } as MessageEvent;
      }),
    );
  }
}

function principal(request: RequestWithPrincipal): NonNullable<RequestWithPrincipal["principal"]> {
  if (!request.principal) {
    throw apiError(401, "unauthenticated", "authentication failed");
  }
  return request.principal;
}

function parseLimit(raw: string | undefined): number {
  if (raw === undefined || raw === "") {
    return 50;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > 200) {
    throw apiError(400, "validation_failed", "limit is invalid");
  }
  return value;
}
