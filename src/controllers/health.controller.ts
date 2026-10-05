import { Controller, Get, Route, Tags } from "@tsoa/runtime";

export interface HealthStatus {
  status: "ok";
}

/**
 * Liveness. Mounted bare for local dev and compose and under /api/auth because production CloudFront only routes
 * requests matching a configured path pattern. Credentials are ignored: nothing here reads a header.
 */
@Route("")
@Tags("operational")
export class HealthController extends Controller {
  /** Liveness check. */
  @Get("health")
  public health(): HealthStatus {
    return { status: "ok" };
  }

  /** Liveness check on the production path prefix. */
  @Get("api/auth/health")
  public apiHealth(): HealthStatus {
    return { status: "ok" };
  }
}
