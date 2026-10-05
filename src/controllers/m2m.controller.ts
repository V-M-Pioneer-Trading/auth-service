import { Controller, Header, Post, Request, Response, Route, SuccessResponse, Tags } from "@tsoa/runtime";
import type { Request as ExpressRequest } from "express";

import { firstHeader } from "../introspection";
import { M2M_CALLER_SECRET_HEADER, type M2MError, type MintedToken } from "../m2m/service";
import { m2mOf } from "./support";

/**
 * Machine tokens for the headless services of the fleet (decision 22): the only process that holds a Clerk Machine
 * Secret Key mints for them.
 */
@Route("")
@Tags("machine tokens")
export class M2MController extends Controller {
  /**
   * A Clerk M2M JWT for the calling service, whose `sub` names its Machine and whose `scope` is fixed by auth-service's
   * caller table (`automation-service`: `fleet:control`; `ai-service`: `events:write planner:advise`). The caller is
   * identified by its secret alone and requests nothing: no body, query or other header is read. The token is cached
   * and served again until half its lifetime has passed. Never cacheable.
   * @param _secret The caller's own secret (M2M_CALLER_SECRET_<caller>). The first of repeated headers counts.
   */
  @Post("auth/v1/m2m-token")
  @SuccessResponse(200, "The token and its `exp` as `expires_at`")
  @Response<M2MError>(401, "unknown caller")
  @Response<M2MError>(503, "the token could not be minted")
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- the header parameter documents the secret in the spec; the handler reads the FIRST raw header itself
  public async mint(@Request() request: ExpressRequest, @Header("X-M2M-Caller-Secret") _secret?: string): Promise<MintedToken | M2MError> {
    this.setHeader("Cache-Control", "no-store");
    // The caller hanging up ends this request's wait, and nothing else: the mint is detached (m2m/cache.ts).
    const left = new AbortController();
    const res = request.res;
    res?.once("close", () => {
      if (!res.writableFinished) left.abort();
    });
    const answer = await m2mOf(request).answer(firstHeader(request, M2M_CALLER_SECRET_HEADER), left.signal);
    this.setStatus(answer.status);
    return answer.body;
  }
}
