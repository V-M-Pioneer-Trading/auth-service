/**
 * @file devMinter (src/api/m2m.go): signs locally with the committed dev key (decision 10), so a fresh clone gets real
 * machine tokens with no Clerk account. Shaped like Clerk's: `sub` names a Machine (`mch_local_<caller>`, so
 * introspection says `kind: "machine"`), `scope` is flat, the same 24 h lifetime, `iss` only when CLERK_ISSUER is set.
 *
 * Signed with node:crypto (RSASSA-PKCS1-v1_5 over SHA-256, which is RS256), not jose: golang-jwt signs with any RSA key,
 * and jose would refuse one under 2048 bits. Header and claims are written as golang-jwt writes them (json.Marshal of
 * a map: keys sorted, `<`, `>`, `&`, U+2028 and U+2029 escaped), so the bytes are Go's for the same clock.
 */
import { sign, type KeyObject } from "node:crypto";

import type { Mint } from "./cache";
import { TOKEN_LIFETIME_SECONDS } from "./clerk";

/** The `kid` the dev key has always been published under (decision 10). */
export const DEV_KEY_ID = "dev-only-do-not-use";

/** encoding/json's HTMLEscape and line-separator escapes on JSON.stringify's output. */
const goJsonText = (value: unknown): string =>
  JSON.stringify(value).replace(new RegExp(`[<>&${String.fromCharCode(0x2028, 0x2029)}]`, "g"), (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);

const segment = (value: unknown): string => Buffer.from(goJsonText(value), "utf8").toString("base64url");

/** `now` is milliseconds since the epoch. */
export function devMinter(key: KeyObject, caller: string, scopes: string, issuer: string, now: () => number): Mint {
  return () => {
    const iat = Math.floor(now() / 1000);
    const claims: Record<string, unknown> = { exp: iat + TOKEN_LIFETIME_SECONDS, iat };
    if (issuer !== "") claims.iss = issuer;
    claims.scope = scopes;
    claims.sub = `mch_local_${caller}`;
    const input = `${segment({ alg: "RS256", kid: DEV_KEY_ID, typ: "JWT" })}.${segment(claims)}`;
    return Promise.resolve(`${input}.${sign("sha256", Buffer.from(input), key).toString("base64url")}`);
  };
}
