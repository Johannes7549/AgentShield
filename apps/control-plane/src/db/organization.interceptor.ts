import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from "@nestjs/common";
import { Observable } from "rxjs";
import type { RequestWithPrincipal } from "../auth/guards";
import { runWithOrganization } from "./organization";

@Injectable()
export class OrganizationInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<RequestWithPrincipal>();
    const organizationId = request.principal?.organizationId;
    if (!organizationId) {
      return next.handle();
    }
    return new Observable((subscriber) => {
      runWithOrganization(organizationId, () => {
        next.handle().subscribe({
          next: (value) => subscriber.next(value),
          error: (error) => subscriber.error(error),
          complete: () => subscriber.complete(),
        });
      });
    });
  }
}
