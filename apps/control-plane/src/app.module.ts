import { Module } from "@nestjs/common";
import { APP_FILTER, APP_INTERCEPTOR } from "@nestjs/core";
import { HumanSessionGuard, RolesGuard } from "./auth/guards";
import { AgentsController } from "./agents/agents.controller";
import { AgentsService } from "./agents/agents.service";
import { ApprovalsController } from "./approvals/approvals.controller";
import { ApprovalsService } from "./approvals/approvals.service";
import { AuditController } from "./audit/audit.controller";
import { AuditService } from "./audit/audit.service";
import { IncidentsController } from "./incidents/incidents.controller";
import { IncidentsService } from "./incidents/incidents.service";
import { EventsController } from "./events/events.controller";
import { EventsService } from "./events/events.service";
import { ChaosController } from "./chaos/chaos.controller";
import { ChaosService } from "./chaos/chaos.service";
import { CHAOS_RUNNER, GoChaosRunner } from "./chaos/runner";
import { APP_CONFIG, loadConfig } from "./config/configuration";
import { DATABASE_POOL, DatabaseLifecycle, createPool } from "./db/database";
import { OrganizationInterceptor } from "./db/organization.interceptor";
import { HealthController } from "./health/health.controller";
import { ApiExceptionFilter } from "./http/errors";
import { PoliciesController } from "./policies/policies.controller";
import { PoliciesService } from "./policies/policies.service";
import { SessionsController } from "./sessions/sessions.controller";
import { SessionsService } from "./sessions/sessions.service";
import { TracingInterceptor } from "./telemetry/tracing.interceptor";

@Module({
  controllers: [
    HealthController,
    SessionsController,
    AgentsController,
    PoliciesController,
    ApprovalsController,
    IncidentsController,
    EventsController,
    AuditController,
    ChaosController,
  ],
  providers: [
    {
      provide: APP_CONFIG,
      useFactory: () => loadConfig(process.env),
    },
    {
      provide: DATABASE_POOL,
      inject: [APP_CONFIG],
      useFactory: createPool,
    },
    DatabaseLifecycle,
    HumanSessionGuard,
    RolesGuard,
    SessionsService,
    AgentsService,
    PoliciesService,
    ApprovalsService,
    IncidentsService,
    EventsService,
    AuditService,
    ChaosService,
    GoChaosRunner,
    { provide: CHAOS_RUNNER, useExisting: GoChaosRunner },
    { provide: APP_FILTER, useClass: ApiExceptionFilter },
    { provide: APP_INTERCEPTOR, useClass: OrganizationInterceptor },
    { provide: APP_INTERCEPTOR, useClass: TracingInterceptor },
  ],
})
export class AppModule {}
