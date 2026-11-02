import { Module } from "@nestjs/common";
import { APP_FILTER } from "@nestjs/core";
import { HumanSessionGuard, RolesGuard } from "./auth/guards";
import { AgentsController } from "./agents/agents.controller";
import { AgentsService } from "./agents/agents.service";
import { ApprovalsController } from "./approvals/approvals.controller";
import { ApprovalsService } from "./approvals/approvals.service";
import { APP_CONFIG, loadConfig } from "./config/configuration";
import { DATABASE_POOL, DatabaseLifecycle, createPool } from "./db/database";
import { HealthController } from "./health/health.controller";
import { ApiExceptionFilter } from "./http/errors";
import { PoliciesController } from "./policies/policies.controller";
import { PoliciesService } from "./policies/policies.service";
import { SessionsController } from "./sessions/sessions.controller";
import { SessionsService } from "./sessions/sessions.service";

@Module({
  controllers: [HealthController, SessionsController, AgentsController, PoliciesController, ApprovalsController],
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
    { provide: APP_FILTER, useClass: ApiExceptionFilter },
  ],
})
export class AppModule {}
