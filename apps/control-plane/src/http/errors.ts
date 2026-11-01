import { createHash, randomUUID } from "crypto";
import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from "@nestjs/common";
import type { Response } from "express";

export interface FieldIssue {
  field: string;
  issue: string;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id: string;
    details?: FieldIssue[];
  };
}

export function apiError(status: number, code: string, message: string, details?: FieldIssue[]): HttpException {
  const error: ApiErrorBody["error"] = { code, message, request_id: randomUUID() };
  if (details && details.length > 0) {
    error.details = details;
  }
  return new HttpException({ error }, status);
}

@Catch()
export class ApiExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const response = host.switchToHttp().getResponse<Response>();
    if (response.headersSent) {
      return;
    }
    if (exception instanceof HttpException) {
      const body = exception.getResponse();
      if (isApiBody(body)) {
        response.status(exception.getStatus()).json(body);
        return;
      }
      const status = exception.getStatus();
      response.status(status).json(fallback(status));
      return;
    }
    response.status(HttpStatus.INTERNAL_SERVER_ERROR).json(fallback(HttpStatus.INTERNAL_SERVER_ERROR));
  }
}

function isApiBody(body: unknown): body is ApiErrorBody {
  return (
    typeof body === "object" &&
    body !== null &&
    "error" in body &&
    typeof (body as { error?: { request_id?: unknown } }).error?.request_id === "string"
  );
}

function fallback(status: number): ApiErrorBody {
  if (status === HttpStatus.NOT_FOUND) {
    return { error: { code: "not_found", message: "not found", request_id: randomUUID() } };
  }
  if (status === HttpStatus.BAD_REQUEST) {
    return { error: { code: "validation_failed", message: "request validation failed", request_id: randomUUID() } };
  }
  return { error: { code: "internal_error", message: "internal error", request_id: randomUUID() } };
}
