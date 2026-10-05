/**
 * @file POST /auth/v1/introspect without the HTTP framework: the caller-secret gate and the form, as Go's handler
 * (src/api/introspect.go) reads them. The controller (controllers/introspect.controller.ts) only wires these to the
 * route; what answers what is here and in jwt/verify.ts.
 *
 * Shape is RFC 7662: form-encoded `token=<jwt>` in the BODY, never a query string (a token in a URL lands in access
 * logs), and the answer is always 200 with `{"active":false}` for anything that does not verify. Nothing about why it
 * failed is returned: the remedy is the same for an expired token, a foreign signature and a wrong issuer, and telling
 * them apart is a probing oracle.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";

import { readBody } from "./http/body";
import { FORM_MEDIA_TYPE, parseMediaType, parseQuery } from "./http/goForm";
import { kindOf, type Verifier } from "./jwt/verify";

/** The header a calling service authenticates with (meta/fixtures/introspection.json pins the spelling). */
export const INTROSPECTION_SECRET_HEADER = "X-Introspection-Secret";
/** The 401's message when the caller's secret is wrong, missing, or none is configured. */
export const INTROSPECTION_SECRET_REQUIRED = "a valid introspection secret is required";
/**
 * The form body cap: a Clerk session JWT is about 1 KB. Over it is not an error but `{"active":false}`: such a body
 * cannot hold a token this service would accept. 8192 bytes are read, 8193 are too many.
 */
export const MAX_INTROSPECTION_BODY = 8 << 10;

export interface IntrospectionDeps {
  /** AUTH_INTROSPECTION_SECRET. Empty means every caller is refused (fail closed, not a startup error). */
  readonly secret: string;
  readonly verifier: Verifier;
}

export type IntrospectionAnswer = { active: false } | { active: true; sub: string; scope: string; exp: number; kind: "operator" | "machine" };

/**
 * The first value of a request header, as Go's `Header.Get` reads it. Node joins repeated unknown headers with ", ",
 * which would never match: two X-Introspection-Secret headers are read as the first (contract README note 18).
 * Values are Node's latin1 strings, one char per byte.
 */
export function firstHeader(req: IncomingMessage, name: string): string | undefined {
  const wanted = name.toLowerCase();
  const raw = req.rawHeaders;
  for (let i = 0; i + 1 < raw.length; i += 2) {
    if ((raw[i] ?? "").toLowerCase() === wanted) return raw[i + 1];
  }
  return undefined;
}

const sha256 = (bytes: Buffer): Buffer => createHash("sha256").update(bytes).digest();

/**
 * introspectionSecretOK: fails closed on an unconfigured secret before any comparison, so an empty
 * AUTH_INTROSPECTION_SECRET is never satisfied by an empty or absent header; otherwise the bytes are compared in
 * constant time (their SHA-256, so the length is not a shortcut either).
 */
export function introspectionSecretOk(configured: string, presented: string | undefined): boolean {
  if (configured === "") return false;
  return timingSafeEqual(sha256(Buffer.from(configured, "utf8")), sha256(Buffer.from(presented ?? "", "latin1")));
}

/**
 * The `token` form value as Go's `r.ParseForm()` then `r.PostForm.Get("token")` produce it; null when ParseForm
 * returns an error, which the handler answers `{"active":false}` whatever token came with it.
 *
 *  - The body is read only when Content-Type's media type is `application/x-www-form-urlencoded` (a missing or empty
 *    one is application/octet-stream), capped by MAX_INTROSPECTION_BODY, and parsed by url.ParseQuery.
 *  - The URL query is parsed too, only for its error: a `?token=` is never read, but `?%zz` or `?a=1;b=2` fails the
 *    request.
 *  - The first `token` value counts; none is "".
 */
export async function formToken(req: IncomingMessage): Promise<string | null> {
  const contentType = req.headers["content-type"];
  const { mediaType, failed: badMediaType } = parseMediaType(contentType === undefined || contentType === "" ? "application/octet-stream" : contentType);
  let failed = badMediaType;
  let form = new Map<string, string[]>();
  if (mediaType === FORM_MEDIA_TYPE) {
    const { bytes, exceeded } = await readBody(req, MAX_INTROSPECTION_BODY);
    if (exceeded) {
      failed = true;
    } else {
      const body = parseQuery(bytes.toString("latin1"));
      form = body.values;
      failed ||= body.failed;
    }
  }
  const url = req.url ?? "";
  const q = url.indexOf("?");
  if (parseQuery(q < 0 ? "" : url.slice(q + 1)).failed) failed = true;
  if (failed) return null;
  return form.get("token")?.[0] ?? "";
}

/** The whole handler, minus writing: the status and the body. `Cache-Control: no-store` goes on every answer. */
export async function introspect(req: IncomingMessage, deps: IntrospectionDeps, nowMs: () => number): Promise<{ status: 200; body: IntrospectionAnswer } | { status: 401 }> {
  if (!introspectionSecretOk(deps.secret, firstHeader(req, INTROSPECTION_SECRET_HEADER))) return { status: 401 };
  const token = await formToken(req);
  const verified = token === null ? null : await deps.verifier(token, nowMs());
  if (verified === null) return { status: 200, body: { active: false } };
  return {
    status: 200,
    body: { active: true, sub: verified.subject, scope: verified.scope, exp: verified.expiry, kind: kindOf(verified.subject) },
  };
}
