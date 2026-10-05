/**
 * @file cacheEntryFrom (src/api/m2m.go): what a minted token is worth caching, read from its own `iat` and `exp`.
 * No signature check: the token came from Clerk over TLS (or from our own key), and this is bookkeeping, not trust.
 * A token whose lifetime cannot be used safely is refused, as a failed mint, rather than cached.
 */
import { unmarshalGo } from "./goJson";

/** A minted token and the two instants the cache acts on, in whole seconds since the epoch. */
export interface CachedToken {
  readonly token: string;
  readonly expiresAt: number;
  readonly refreshAt: number;
}

/** The shortest token worth caching: anything shorter refreshes on nearly every request, and every mint is billed. */
export const MIN_LIFETIME_SECONDS = 60;
/** The longest: we ask for 24 h, and one living far longer stretches the leak window decision 22 accepted. */
export const MAX_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
/** `iat` and `exp` stay where float64 holds every integer exactly (Go's maxJWTSeconds). */
export const MAX_JWT_SECONDS = 2 ** 53;

/** A mint that produced nothing usable. The message is ours (status codes, claim checks), never upstream text. */
export class MintFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MintFailed";
  }
}

/** base64.RawURLEncoding.DecodeString: the URL alphabet, no padding, \r and \n skipped, a length of 4n+1 refused. */
function rawUrlDecode(segment: string): Buffer | null {
  if (!/^[A-Za-z0-9_\-\r\n]*$/.test(segment)) return null;
  const clean = segment.replace(/[\r\n]/g, "");
  if (clean.length % 4 === 1) return null;
  return Buffer.from(clean, "base64url");
}

/** The cache entry for a freshly minted token at `nowMs`; throws MintFailed with Go's reason when it is not usable. */
export function cacheEntryFrom(token: string, nowMs: number): CachedToken {
  const parts = token.split(".");
  if (parts.length !== 3) throw new MintFailed("minted token is not a JWT");
  const raw = rawUrlDecode(parts[1] ?? "");
  if (raw === null) throw new MintFailed("minted token payload: illegal base64 data");
  const claims = unmarshalGo(raw, [
    { name: "iat", kind: "float-pointer" },
    { name: "exp", kind: "float-pointer" },
  ]);
  if (claims === null) throw new MintFailed("minted token payload: not the JSON Go decodes");
  const iatClaim = claims.get("iat");
  const expClaim = claims.get("exp");
  if (typeof iatClaim !== "number" || typeof expClaim !== "number") throw new MintFailed("minted token has no iat/exp");
  for (const v of [iatClaim, expClaim]) {
    if (!(v >= 0 && v <= MAX_JWT_SECONDS)) throw new MintFailed("minted token has an iat/exp out of range");
  }
  // int64(f): truncation, exact inside the range above.
  const iat = Math.trunc(iatClaim);
  const exp = Math.trunc(expClaim);
  const lifetime = exp - iat;
  if (lifetime < MIN_LIFETIME_SECONDS) throw new MintFailed(`minted token lives ${String(lifetime)} s, under the ${String(MIN_LIFETIME_SECONDS)} s minimum`);
  if (lifetime > MAX_LIFETIME_SECONDS) throw new MintFailed(`minted token lives ${String(lifetime)} s, over the ${String(MAX_LIFETIME_SECONDS)} s maximum`);
  const now = Math.floor(nowMs / 1000);
  if (exp <= now) throw new MintFailed("minted token is already expired");
  // Already past its own refresh point on arrival (a skewed or backdated `iat`): caching it would start another mint
  // on the very next request. Go's integer division; the lifetime is positive here.
  const refreshAt = iat + Math.floor(lifetime / 2);
  if (refreshAt <= now) throw new MintFailed("minted token is already past its refresh point");
  return { token, expiresAt: exp, refreshAt };
}
