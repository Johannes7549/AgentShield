import { randomBytes } from "crypto";
import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from "@nestjs/common";
import { Observable, tap } from "rxjs";

@Injectable()
export class TracingInterceptor implements NestInterceptor {
  private readonly logger = new Logger("otel");

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<{ method?: string; url?: string }>();
    const started = Date.now();
    const span = {
      trace_id: randomBytes(16).toString("hex"),
      span_id: randomBytes(8).toString("hex"),
      name: `${request.method ?? "UNKNOWN"} ${request.url ?? ""}`,
    };
    return next.handle().pipe(
      tap({
        next: () => {
          this.logger.log(JSON.stringify({ ...span, status: "ok", duration_ms: Date.now() - started }));
        },
        error: () => {
          this.logger.log(JSON.stringify({ ...span, status: "error", duration_ms: Date.now() - started }));
        },
      }),
    );
  }
}
