import { INestApplication, RequestMethod, type NestApplicationOptions } from "@nestjs/common";
import { randomUUID } from "crypto";
import { json, type ErrorRequestHandler, type NextFunction, type Request, type Response } from "express";

export const applicationOptions: NestApplicationOptions = {
  bodyParser: false,
};

export const JSON_BODY_LIMIT = "256kb";

export function securityHeaders(_request: Request, response: Response, next: NextFunction): void {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cache-Control", "no-store");
  next();
}

const bodyErrors: ErrorRequestHandler = (error, _request, response, next) => {
  if (response.headersSent) {
    next(error);
    return;
  }
  const tooLarge =
    typeof error === "object" &&
    error !== null &&
    "type" in error &&
    (error as { type?: string }).type === "entity.too.large";
  if (tooLarge) {
    response.status(413).json({
      error: { code: "validation_failed", message: "request body is too large" },
    });
    return;
  }
  response.status(500).json({
    error: { code: "internal_error", message: "internal error" },
  });
};

export function rejectAgentCredentials(request: Request, response: Response, next: NextFunction): void {
  const agentHeader = request.header("x-agentshield-signature") || request.header("x-agentshield-agent-id");
  if (request.path.startsWith("/api/") && agentHeader) {
    response.status(401).json({
      error: {
        code: "unauthenticated",
        message: "agent signatures are not accepted on the control plane",
        request_id: randomUUID(),
      },
    });
    return;
  }
  next();
}

export function configureApp(app: INestApplication): void {
  app.enableShutdownHooks();
  app.use(securityHeaders);
  app.use(rejectAgentCredentials);
  app.use(json({ limit: JSON_BODY_LIMIT }));
  app.use(bodyErrors);
  app.setGlobalPrefix("api", {
    exclude: [
      { path: "health/live", method: RequestMethod.GET },
      { path: "health/ready", method: RequestMethod.GET },
    ],
  });
}
