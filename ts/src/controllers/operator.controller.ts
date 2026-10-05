import { Body, Controller, Header, Post, Request, Response, Route, SuccessResponse, Tags } from "@tsoa/runtime";
import type { Request as ExpressRequest } from "express";

import { registerAgent, restoreToken, sessionGate, SCOPE_AGENT_RESET } from "../vault";
import { introspectionOf, nowOf, vaultOf } from "./support";

/** The `{"error":{"message":…}}` envelope of a refused session. */
export interface SessionRefusal {
  error: { message: string };
}

/** Restore Token's body, decoded as Go's encoding/json would: key case ignored, unknown keys ignored. */
export interface RestoreTokenRequest {
  /** The regenerated agent token, stored verbatim. */
  agentToken: string;
}

/** Reset Agent's body, decoded the same way. */
export interface RegisterRequest {
  /** The SpaceTraders account token: stored, never answered, never logged. */
  accountToken: string;
  symbol: string;
  faction: string;
  /** Reserves the call sign across a reset; left out upstream when empty. */
  email?: string;
}

export interface Restored {
  status: "restored";
}

export interface Registered {
  /** The symbol SpaceTraders answered, not necessarily the one asked for. */
  agentSymbol: string;
  status: "registered";
}

/**
 * The operator routes, behind a Clerk session carrying `agent:reset`, verified in-process by the introspection
 * verifier (decision 21). The session is checked before the body is read; the body is read by the handler itself with
 * Go's encoding/json rules (vault.ts), and the `@Body` parameter only documents it.
 */
@Route("api/auth/v1")
@Tags("operator")
export class OperatorController extends Controller {
  /**
   * Restore Token (decision 8): replaces only the agent token of the agent already registered and clears
   * APP_TOKEN_EXPIRED. No upstream call. `409` (text) when nothing is registered, `400` (text) for a missing token or
   * a body that does not decode.
   * @param _authorization `Bearer <Clerk session JWT>` carrying `agent:reset`. The first of repeated headers counts.
   */
  @Post("agent-token")
  @SuccessResponse(200, "Restored")
  @Response<SessionRefusal>(401, "a bearer token is required / invalid or expired session")
  @Response<SessionRefusal>(403, "this action requires a scope this session does not carry")
  @Response<string>(400, "agentToken is required, or invalid request body: … (text/plain)")
  @Response<string>(409, "no credential configured to restore a token onto (text/plain)")
  public async restore(
    @Request() request: ExpressRequest,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- documents the header; vault.ts reads the first raw one
    @Header("Authorization") _authorization?: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- documents the body; vault.ts reads it after the session gate
    @Body() _body?: RestoreTokenRequest,
  ): Promise<Restored | SessionRefusal> {
    const refused = await sessionGate(request, introspectionOf(request).verifier, nowOf(request), SCOPE_AGENT_RESET);
    if (refused !== null) return this.refuse(refused.status, refused.message);
    return restoreToken(request, vaultOf(request), nowOf(request));
  }

  /**
   * Reset Agent (decision 7): registers with SpaceTraders through st-gateway (`POST /proxy/register`, the account
   * token as the bearer), replaces the stored credential wholesale, then polls the root once for the dates. An
   * upstream 4xx/5xx is passed through as text `POST /register: <upstream body>`; a transport failure or an unusable
   * 2xx is `502`.
   * @param _authorization `Bearer <Clerk session JWT>` carrying `agent:reset`. The first of repeated headers counts.
   */
  @Post("register")
  @SuccessResponse(200, "Registered")
  @Response<SessionRefusal>(401, "a bearer token is required / invalid or expired session")
  @Response<SessionRefusal>(403, "this action requires a scope this session does not carry")
  @Response<string>(400, "accountToken, symbol and faction are required, or invalid request body: … (text/plain)")
  @Response<string>(502, "SpaceTraders could not be reached or answered something unusable (text/plain)")
  public async register(
    @Request() request: ExpressRequest,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- documents the header; vault.ts reads the first raw one
    @Header("Authorization") _authorization?: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- documents the body; vault.ts reads it after the session gate
    @Body() _body?: RegisterRequest,
  ): Promise<Registered | SessionRefusal> {
    const refused = await sessionGate(request, introspectionOf(request).verifier, nowOf(request), SCOPE_AGENT_RESET);
    if (refused !== null) return this.refuse(refused.status, refused.message);
    return registerAgent(request, vaultOf(request), () => nowOf(request));
  }

  /** writeAuthError: the envelope, never cacheable. */
  private refuse(status: 401 | 403, message: string): SessionRefusal {
    this.setStatus(status);
    this.setHeader("Cache-Control", "no-store");
    return { error: { message } };
  }
}
