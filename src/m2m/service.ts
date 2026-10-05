/**
 * @file POST /auth/v1/m2m-token without the HTTP framework (decision 22; src/api/m2m.go's m2mHandler). The controller
 * (controllers/m2m.controller.ts) only wires this to the route.
 *
 * The secret IS the caller's identity: there is no body field, query or header in which a caller names itself or
 * asks for a scope, so there is nothing to forge. A caller can only ever get the token the scope table says it gets.
 * Every answer is JSON with `Cache-Control: no-store` (a bearer token in a shared cache would be handed to whoever
 * asked next): `{token, expires_at}`, 401 `{"error":"unknown caller"}`, or 503 `{"error":"the token could not be
 * minted"}`. Neither error names a caller, a secret or a reason.
 */
import { createHash, timingSafeEqual } from "node:crypto";

import { M2M_CALLERS, validateM2MConfig, type Env, type M2MConfig } from "../config";
import { parseClerkBaseUrl } from "../goUrl";
import type { Logger } from "../log";
import { RETRY_BACKOFF_MS, TokenCache, type Mint } from "./cache";
import { CLERK_M2M_TOKENS_URL, clerkMinter } from "./clerk";
import { devMinter } from "./dev";
import { proxyConfigFrom, proxyFor, type ProxyDecision } from "./proxy";

/** The header a calling service authenticates with. */
export const M2M_CALLER_SECRET_HEADER = "X-M2M-Caller-Secret";
export const UNKNOWN_CALLER = "unknown caller";
export const MINT_FAILED = "the token could not be minted";

export interface MintedToken {
  token: string;
  /**
   * The token's own `exp`, in whole seconds: read from it, never computed.
   * @isLong
   */
  expires_at: number;
}

export interface M2MError {
  error: string;
}

export type M2MAnswer = { readonly status: 200; readonly body: MintedToken } | { readonly status: 401 | 503; readonly body: M2MError };

export interface M2MService {
  /**
   * The answer for a request presenting `presented` (the first X-M2M-Caller-Secret header, undefined when absent).
   * `callerLeft` fires when the request's caller hangs up: it ends this request's wait and cancels no mint.
   */
  answer(presented: string | undefined, callerLeft?: AbortSignal): Promise<M2MAnswer>;
}

const UNKNOWN: M2MAnswer = { status: 401, body: { error: UNKNOWN_CALLER } };
const FAILED: M2MAnswer = { status: 503, body: { error: MINT_FAILED } };

/** The zero configuration (Go's zero M2MConfig): the route is mounted and every caller is unknown. */
export const REJECT_EVERY_CALLER: M2MService = { answer: () => Promise.resolve(UNKNOWN) };

export interface M2MServiceOptions {
  readonly log: Logger;
  /** Milliseconds since the epoch; the wall clock if not given. */
  readonly now?: () => number;
  /** Where HTTPS_PROXY and friends are read (Go reads the process environment); process.env if not given. */
  readonly env?: Env;
  readonly mintTimeoutMs?: number;
  /** Replaces the minter (tests): what a caller's mint is. */
  readonly mintFor?: (caller: string, scopes: string) => Mint;
}

const sha256 = (bytes: Buffer): Buffer => createHash("sha256").update(bytes).digest();

interface Caller {
  readonly name: string;
  readonly secretDigest: Buffer;
  readonly cache: TokenCache;
}

/**
 * newM2MHandler: validates again (so no future caller can assemble a collision by hand), then one cache per enabled
 * caller, each minting with the process's one trust anchor.
 */
export function createM2MService(config: M2MConfig, sharedSecret: string, introspectionSecret: string, options: M2MServiceOptions): M2MService {
  validateM2MConfig(config.callers, config.devSigningKey !== undefined, sharedSecret, introspectionSecret);
  const now = options.now ?? Date.now;
  const tokensUrl = config.clerkTokensUrl === "" ? CLERK_M2M_TOKENS_URL : config.clerkTokensUrl;
  let proxy: ProxyDecision | undefined;
  const proxyDecision = (): ProxyDecision => {
    if (proxy === undefined) {
      const parsed = parseClerkBaseUrl(tokensUrl);
      proxy = parsed === null ? { kind: "direct" } : proxyFor(proxyConfigFrom(options.env ?? process.env), parsed.scheme, parsed.host);
    }
    return proxy;
  };

  const callers: Caller[] = [];
  for (const c of config.callers) {
    if (c.secret === "") continue;
    const scopes = M2M_CALLERS.find((known) => known.name === c.name)?.scopes ?? "";
    let mint: Mint;
    if (options.mintFor !== undefined) mint = options.mintFor(c.name, scopes);
    else if (config.devSigningKey !== undefined) mint = devMinter(config.devSigningKey, c.name, scopes, config.issuer, now);
    else mint = clerkMinter({ url: tokensUrl, machineKey: c.machineKey, scopes, proxy: proxyDecision() });
    callers.push({
      name: c.name,
      secretDigest: sha256(Buffer.from(c.secret, "utf8")),
      cache: new TokenCache({ name: c.name, mint, now, log: options.log, ...(options.mintTimeoutMs === undefined ? {} : { mintTimeoutMs: options.mintTimeoutMs }) }),
    });
  }

  /**
   * Compares the presented secret with EVERY enabled caller's, in constant time (their SHA-256, so the length is not
   * a shortcut either), and never stops early: the time says nothing about which caller, if any, came close.
   */
  const lookup = (presented: string | undefined): Caller | undefined => {
    if (presented === undefined || presented === "") return undefined;
    // Header values are Node's latin1 strings, one char per byte: the bytes the caller sent.
    const digest = sha256(Buffer.from(presented, "latin1"));
    let match: Caller | undefined;
    for (const c of callers) if (timingSafeEqual(c.secretDigest, digest)) match = c;
    return match;
  };

  return {
    async answer(presented, callerLeft) {
      // Names no caller and no secret, here or in the log: the request line already said method and path.
      const caller = lookup(presented);
      if (caller === undefined) return UNKNOWN;
      const got = await caller.cache.get(callerLeft);
      if (got.ok) return { status: 200, body: { token: got.token.token, expires_at: got.token.expiresAt } };
      if (got.reason === "backoff") {
        options.log(`minting a machine token for ${caller.name}: the last mint failed less than ${String(RETRY_BACKOFF_MS / 1000)} s ago; not calling Clerk again yet`);
      }
      // "failed" was logged once by the mint, whoever waited; "backoff-repeat" was said once in this window; and a
      // caller who left is not a failure (the mint carries on and its token is cached).
      return FAILED;
    },
  };
}
