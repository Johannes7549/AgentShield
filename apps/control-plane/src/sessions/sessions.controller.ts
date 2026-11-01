import { Body, Controller, HttpCode, Post } from "@nestjs/common";
import { z } from "zod";
import { apiError } from "../http/errors";
import { SessionsService } from "./sessions.service";

const bodySchema = z
  .object({
    email: z.string().trim().email().max(320),
    password: z.string().min(12).max(128),
  })
  .strict();

@Controller("v1/sessions")
export class SessionsController {
  constructor(private readonly sessions: SessionsService) {}

  @Post()
  @HttpCode(201)
  async create(@Body() body: unknown): Promise<{
    token: string;
    token_type: "bearer";
    expires_at: string;
    organization_id: string;
  }> {
    const parsed = bodySchema.safeParse(body);
    if (!parsed.success) {
      throw apiError(400, "validation_failed", "request validation failed", issues(parsed.error.issues));
    }
    return this.sessions.create(parsed.data.email, parsed.data.password);
  }
}

function issues(values: { path: PropertyKey[]; code: string }[]): { field: string; issue: string }[] {
  return values.map((issue) => ({
    field: issue.path.map(String).join(".") || "body",
    issue: issue.code,
  }));
}
