import { Controller, Header, Post, Request, Response, Route, SuccessResponse, Tags } from "@tsoa/runtime";
import type { Request as ExpressRequest } from "express";

import { introspect, INTROSPECTION_SECRET_REQUIRED, type IntrospectionAnswer } from "../introspection";
import { introspectionOf, nowOf } from "./support";

/** What a refused caller gets. */
export interface IntrospectionRefusal {
  error: { message: string };
}

/**
 * Token introspection for the services of the fleet (decision 21): the only place a Clerk token is verified.
 */
@Route("")
@Tags("introspection")
export class IntrospectController extends Controller {
  /**
   * Verifies a Clerk JWT and says what it carries (RFC 7662). The request body is `application/x-www-form-urlencoded`
   * with `token=<jwt>`, at most 8 KiB, read by this handler with Go's rules; a token in the query string is never
   * read. The answer is `{"active":false}` for anything that does not verify, with no reason, and is never cacheable.
   * `scope` is the token's claim verbatim (an array claim joined with single spaces), `""` when it carries none; `kind`
   * is `operator` when `sub` starts `user_`, otherwise `machine`.
   * @param _secret The shared introspection secret (AUTH_INTROSPECTION_SECRET). The first of repeated headers counts.
   */
  @Post("auth/v1/introspect")
  @SuccessResponse(200, "The verdict: `{active:false}`, or `{active:true, sub, scope, exp, kind}` and nothing else")
  @Response<IntrospectionRefusal>(401, "a valid introspection secret is required")
  public async introspect(@Request() request: ExpressRequest, @Header("X-Introspection-Secret") _secret?: string): Promise<IntrospectionAnswer | IntrospectionRefusal> {
    this.setHeader("Cache-Control", "no-store");
    const answer = await introspect(request, introspectionOf(request), () => nowOf(request));
    if (answer.status === 401) {
      this.setStatus(401);
      return { error: { message: INTROSPECTION_SECRET_REQUIRED } };
    }
    return answer.body;
  }
}
