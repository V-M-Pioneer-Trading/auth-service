import { Controller, Get, Header, Query, Request, Response, Route, SuccessResponse, Tags } from "@tsoa/runtime";
import type { Request as ExpressRequest } from "express";

import { getToken } from "../vault";
import { vaultOf } from "./support";

/** The `{"error":{"message":…}}` envelope of a refused caller. */
export interface VaultRefusal {
  error: { message: string };
}

/** The game credential, for st-gateway alone. */
export interface AgentToken {
  agentToken: string;
}

/**
 * `GET /auth/v1/token`, the only route that can return the game credential (decision 5). Mounted bare and nowhere
 * else: never under /api/auth, at any method (decision 9), so no public route reaches it.
 */
@Route("")
@Tags("vault")
export class VaultController extends Controller {
  /**
   * The agent token st-gateway injects on every upstream call. Gated by the shared secret, compared in constant time;
   * a secret in the query string is never read. With `afterUnauthorized=true` (exactly) a forced poll of SpaceTraders
   * runs before the answer, at most once per 10 s process-wide, and may replace the token (a wipe re-registers).
   * `503` text `no agent token configured` while nothing is stored or the stored token is empty. The token answer has
   * no `Cache-Control`, as Go's had none: decision 23 allows `no-store` here, but 15 cases of the contract suite pin
   * the header's absence on this answer (only one accepts either), and contract/ is never edited by a port.
   * @param _secret AUTH_SERVICE_SHARED_SECRET. The first of repeated headers counts.
   * @param _afterUnauthorized `true` when st-gateway just saw SpaceTraders answer 401.
   */
  @Get("auth/v1/token")
  @SuccessResponse(200, "The agent token")
  @Response<VaultRefusal>(403, "invalid or missing shared secret")
  @Response<string>(503, "no agent token configured (text/plain)")
  public async token(
    @Request() request: ExpressRequest,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- documents the header; vault.ts reads the FIRST raw header itself
    @Header("X-Auth-Service-Secret") _secret?: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- documents the flag; vault.ts reads it with Go's query rules
    @Query("afterUnauthorized") _afterUnauthorized?: string,
  ): Promise<AgentToken | VaultRefusal> {
    const answer = await getToken(request, vaultOf(request));
    if ("refusal" in answer) {
      // writeAuthError: nothing about an authentication decision belongs in a cache.
      this.setHeader("Cache-Control", "no-store");
      this.setStatus(answer.refusal.status);
      return { error: { message: answer.refusal.message } };
    }
    return { agentToken: answer.agentToken };
  }
}
