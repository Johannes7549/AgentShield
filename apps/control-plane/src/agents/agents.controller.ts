import { Body, Controller, Get, HttpCode, Param, Post, Query, UseGuards } from "@nestjs/common";
import { z } from "zod";
import { HumanSessionGuard, Roles, RolesGuard, type RequestWithPrincipal } from "../auth/guards";
import { apiError } from "../http/errors";
import { AgentsService, type AgentRecord } from "./agents.service";
import { Req } from "@nestjs/common";

const frameworks = ["langchain", "langgraph", "crewai", "openai_agents", "python", "typescript", "mcp", "custom"] as const;

const createSchema = z
  .object({
    name: z.string().trim().min(1).max(128),
    framework: z.enum(frameworks),
    public_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  })
  .strict();

@Controller("v1/agents")
@UseGuards(HumanSessionGuard, RolesGuard)
export class AgentsController {
  constructor(private readonly agents: AgentsService) {}

  @Post()
  @HttpCode(201)
  @Roles("owner", "admin", "operator")
  async create(@Req() request: RequestWithPrincipal, @Body() body: unknown): Promise<AgentRecord> {
    const parsed = createSchema.safeParse(body);
    if (!parsed.success) {
      throw apiError(400, "validation_failed", "request validation failed", fieldIssues(parsed.error.issues));
    }
    const publicKey = Buffer.from(parsed.data.public_key, "base64url");
    if (publicKey.length !== 32) {
      throw apiError(400, "validation_failed", "public key is invalid");
    }
    return this.agents.create(principal(request).organizationId, {
      name: parsed.data.name,
      framework: parsed.data.framework,
      publicKey,
    });
  }

  @Get()
  async list(
    @Req() request: RequestWithPrincipal,
    @Query("limit") limit: unknown,
    @Query("cursor") cursor: unknown,
  ): Promise<{ items: AgentRecord[]; next_cursor: string | null }> {
    return this.agents.list(principal(request).organizationId, parseLimit(limit), parseCursor(cursor));
  }

  @Get(":agentId")
  async get(@Req() request: RequestWithPrincipal, @Param("agentId") agentId: string): Promise<AgentRecord> {
    if (!/^[0-9a-f-]{36}$/i.test(agentId)) {
      throw apiError(400, "validation_failed", "agent id is invalid");
    }
    const agent = await this.agents.get(principal(request).organizationId, agentId);
    if (!agent) {
      throw apiError(404, "not_found", "agent not found");
    }
    return agent;
  }
}

function principal(request: RequestWithPrincipal): NonNullable<RequestWithPrincipal["principal"]> {
  if (!request.principal) {
    throw apiError(401, "unauthenticated", "authentication failed");
  }
  return request.principal;
}

function parseLimit(value: unknown): number {
  if (value === undefined) {
    return 50;
  }
  const parsed = z.coerce.number().int().min(1).max(200).safeParse(value);
  if (!parsed.success) {
    throw apiError(400, "validation_failed", "limit is invalid");
  }
  return parsed.data;
}

function parseCursor(value: unknown): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.length > 512) {
    throw apiError(400, "validation_failed", "cursor is invalid");
  }
  return value;
}

function fieldIssues(values: { path: PropertyKey[]; code: string }[]): { field: string; issue: string }[] {
  return values.map((issue) => ({ field: issue.path.map(String).join(".") || "body", issue: issue.code }));
}
