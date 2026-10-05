/**
 * @file THE verification function (decision 21): every service in the fleet asks POST /auth/v1/introspect what a Clerk
 * token carries, and the answer comes from here. The vault's operator routes (7c) call the same function in-process,
 * so there is one verification code path and auth-service never calls itself over HTTP. Ported from the Go service's
 * verifyToken (src/api/introspect.go, golang-jwt v5.3.1); `jose` does the cryptography.
 *
 * A token is active only when ALL of these hold, and nothing about which one failed ever leaves this module:
 *
 *  1. Its spelling is one golang-jwt reads (`goSpelling`): exactly three segments of base64url without padding, where
 *     Go skips \r and \n and refuses everything else (jose would also take padding, spaces and tabs), and header and
 *     claims that encoding/json would decode (jose would also take a UTF-8 BOM and a number beyond float64, which it
 *     reads as Infinity).
 *  2. jose's jwtVerify with: `algorithms: ["RS256"]` (the pin: `none`, HS256 keyed with the public PEM, RS384/512 and
 *     PS256 are refused before any key is used), the configured key as a KeyObject (so an embedded `jwk`, `jku` or
 *     `x5u` header is never consulted), `requiredClaims: ["exp"]`, `clockTolerance` 60 s (on `exp` and `nbf`), and
 *     `issuer` only when CLERK_ISSUER is set. No JWKS, no network, no bypass flag (decision 10).
 *  3. `exp` as Go judges it (`goExpiryValid`): truncated to whole seconds and checked with Go's int64 time arithmetic.
 *     jose compares the raw number, which lets a fractional `exp` live up to a second longer and accepts values Go's
 *     arithmetic overflows on.
 *  4. `sub` is a non-empty string (jose does not look at `sub`).
 *
 * The answer then carries `sub`, `scope` (a string claim verbatim, an array joined with single spaces with
 * non-strings dropped, anything else ""), `exp` (the truncated seconds) and `kind` (operator iff `sub` starts `user_`).
 * Lone UTF-16 surrogates from `\uD800`-style escapes become U+FFFD, as Go's decoder makes them.
 *
 * Deliberately stricter than Go (decision 23 and the PR that ported this; each pinned by verifyToken.test.ts against
 * Go's recorded answers): a `crit` header other than `["b64"]` with `b64: true`; an RSA key under 2048 bits (jose
 * refuses it for RS256, so every token is inactive with such a key; Clerk's and every key in use are 2048); a present
 * `iat` that is not a number; claims that are not valid UTF-8; a fractional `nbf` in the last second of the leeway,
 * and an `nbf` so large that Go's int64 conversion overflows it into the past. `azp` is deliberately not checked
 * (decision 21), and neither are `aud`, `iat`'s value, `typ` and `kid`.
 */
import type { KeyObject } from "node:crypto";
import { jwtVerify, type JWTPayload } from "jose";

/** The `exp`/`nbf` leeway, as Go's clockSkewLeeway: clock drift between Clerk's minting host and this one. */
export const CLOCK_SKEW_LEEWAY_SECONDS = 60;

export interface VerifiedToken {
  readonly subject: string;
  /** Verbatim: whatever the claim held, never split or normalised (an array is joined with single spaces). */
  readonly scope: string;
  /** `exp` in whole seconds since the epoch. */
  readonly expiry: number;
}

export type Kind = "operator" | "machine";

/** `operator` when the subject starts `user_`, case-sensitively; otherwise `machine`. The one place that knows Clerk's `sub` conventions. */
export function kindOf(subject: string): Kind {
  return subject.startsWith("user_") ? "operator" : "machine";
}

export interface VerifierConfig {
  /** CLERK_JWT_KEY, parsed (keys.ts). */
  readonly key: KeyObject;
  /** CLERK_ISSUER; "" means `iss` is not checked. */
  readonly issuer: string;
}

/** Verifies a token at `nowMs`; null for anything that is not a token this service vouches for. Never throws. */
export type Verifier = (token: string, nowMs: number) => Promise<VerifiedToken | null>;

export function createVerifier(config: VerifierConfig): Verifier {
  const { key, issuer } = config;
  return async (token, nowMs) => {
    if (token === "" || !goSpelling(token)) return null;
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, key, {
        algorithms: ["RS256"],
        requiredClaims: ["exp"],
        clockTolerance: CLOCK_SKEW_LEEWAY_SECONDS,
        currentDate: new Date(nowMs),
        ...(issuer === "" ? {} : { issuer }),
      }));
    } catch {
      return null;
    }
    const sub = own(payload, "sub");
    if (typeof sub !== "string" || sub === "") return null;
    const expiry = goExpiryValid(own(payload, "exp"), nowMs);
    if (expiry === null) return null;
    return { subject: sub.toWellFormed(), scope: scopeString(own(payload, "scope")), expiry };
  };
}

function own(payload: JWTPayload, claim: string): unknown {
  return Object.hasOwn(payload, claim) ? payload[claim] : undefined;
}

/** Go's scopeStringFrom. */
export function scopeString(claim: unknown): string {
  if (typeof claim === "string") return claim.toWellFormed();
  if (Array.isArray(claim)) {
    return claim
      .filter((item): item is string => typeof item === "string")
      .map((s) => s.toWellFormed())
      .join(" ");
  }
  return "";
}

const MAX_INT64 = (1n << 63n) - 1n;
const MIN_INT64 = -(1n << 63n);
/** Seconds from Go's internal epoch (year 1) to the Unix epoch. */
const UNIX_TO_INTERNAL = 62135596800n;

/** Two's-complement int64 addition, as Go's `+` on int64 (it wraps). */
function wrapInt64(v: bigint): bigint {
  return BigInt.asIntN(64, v);
}

/**
 * golang-jwt's exp check with Go's leeway, on Go's own arithmetic; the whole seconds Go reports, or null if Go would
 * refuse. `newNumericDateFromSeconds` truncates to whole seconds (`int64(f)`, which on amd64 is MinInt64 for anything
 * out of range), `time.Unix` adds the internal epoch (wrapping), `Add(60 s)` saturates, and the token is valid while
 * now's whole internal second is before that. An `exp` of 0 is "absent" to golang-jwt, and a non-number is refused.
 */
export function goExpiryValid(exp: unknown, nowMs: number): number | null {
  if (typeof exp !== "number" || Number.isNaN(exp) || exp === 0) return null;
  const seconds = exp >= 2 ** 63 || exp < -(2 ** 63) ? MIN_INT64 : BigInt(Math.floor(exp));
  const internal = wrapInt64(seconds + UNIX_TO_INTERNAL);
  const sum = internal + BigInt(CLOCK_SKEW_LEEWAY_SECONDS);
  const deadline = sum > MAX_INT64 ? MAX_INT64 : sum;
  const now = BigInt(Math.floor(nowMs / 1000)) + UNIX_TO_INTERNAL;
  return now < deadline ? Number(seconds) : null;
}

/** Go's RawURLEncoding alphabet; \r and \n are skipped by its decoder, nothing else is. */
const SEGMENT = /^[A-Za-z0-9_\-\r\n]*$/;
const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);

/**
 * What golang-jwt refuses before verification and jose would take. Signature validity is jose's business; this only
 * refuses spellings, so it can never make a token active.
 */
function goSpelling(token: string): boolean {
  const segments = token.split(".");
  if (segments.length !== 3) return false;
  for (const segment of segments) {
    if (!SEGMENT.test(segment) || segment.replace(/[\r\n]/g, "").length % 4 === 1) return false;
  }
  // Header and claims: no byte order mark (TextDecoder drops one, encoding/json does not), and no number that
  // overflows a float64 (JSON.parse reads Infinity, encoding/json fails the whole token).
  for (const segment of segments.slice(0, 2)) {
    const bytes = Buffer.from(segment.replace(/[\r\n]/g, ""), "base64url");
    if (bytes.subarray(0, 3).equals(UTF8_BOM)) return false;
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytes.toString("utf8"));
    } catch {
      return false;
    }
    if (hasInfinity(parsed)) return false;
  }
  return true;
}

/** Whether a parsed JSON value holds ±Infinity anywhere. Iterative: the depth is the caller's. */
function hasInfinity(value: unknown): boolean {
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === "number") {
      if (!Number.isFinite(v)) return true;
    } else if (typeof v === "object" && v !== null) {
      for (const child of Object.values(v)) stack.push(child);
    }
  }
  return false;
}
