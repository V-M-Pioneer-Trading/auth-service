import { Controller, Get, Request, Route, Tags } from "@tsoa/runtime";
import type { Request as ExpressRequest } from "express";

import { readStatus, type StatusResponse } from "../status";
import { credentialsOf, nowOf } from "./support";

/**
 * The state machine for the stored credential. Public: it never returns a token, in any state. Mounted bare (the
 * dashboard polls it directly) and under /api/auth (CloudFront).
 */
@Route("")
@Tags("status")
export class StatusController extends Controller {
  /** UNCONFIGURED, HEALTHY, WIPE_IMMINENT or APP_TOKEN_EXPIRED, with the agent symbol and the dates when known. */
  @Get("auth/v1/status")
  public status(@Request() request: ExpressRequest): StatusResponse {
    return readStatus(credentialsOf(request), nowOf(request));
  }

  /** The same answer on the production path prefix. */
  @Get("api/auth/v1/status")
  public apiStatus(@Request() request: ExpressRequest): StatusResponse {
    return readStatus(credentialsOf(request), nowOf(request));
  }
}
