/**
 * @file m2mTokenCache (src/api/m2m.go): one caller's token, in memory, nothing persisted.
 *
 *  - Until the token's refresh point (`iat + (exp - iat) / 2`) it is answered from memory.
 *  - After it, the next request starts a mint, and every request that finds one in flight joins it rather than
 *    starting its own (each is billed). A request WAITS only when there is no unexpired token to give it; while the
 *    cached one is unexpired it gets that at once and the refresh runs behind it.
 *  - A mint is detached: it runs under its own 10 s timeout, never the request's, so a caller giving up cancels
 *    nothing, a retry joins it, and a token that lands after everyone left is still cached.
 *  - After a failed mint no new one starts for 10 s; inside that window the answer is whatever is in hand (a valid
 *    cached token, or a failure). A token past its `exp` is never served.
 */
import type { Logger } from "../log";
import { cacheEntryFrom, type CachedToken } from "./token";

/** One mint, under `signal` (aborted by the mint timeout, never by a request). Resolves to the token as minted. */
export type Mint = (signal: AbortSignal) => Promise<string>;

/** m2mMintTimeout: finite, so that a hung Clerk becomes a 503 (or a stale token); far above a caller's own 1 s. */
export const MINT_TIMEOUT_MS = 10_000;
/** m2mRetryBackoff: a Clerk outage costs one call per caller per 10 s, not one per request. */
export const RETRY_BACKOFF_MS = 10_000;

/** Why a request got no token. Never sent: the caller always gets the same flat 503. */
export type NoToken =
  /** The mint failed; it has been logged once, by the mint. */
  | "failed"
  /** Inside the backoff window, the first request of it (logged by the route). */
  | "backoff"
  /** Inside the backoff window again (already said once). */
  | "backoff-repeat"
  /** The request's caller left while it waited; the mint carries on. */
  | "caller-left";

export type CacheAnswer = { readonly ok: true; readonly token: CachedToken } | { readonly ok: false; readonly reason: NoToken };

type Outcome = { readonly ok: true; readonly token: CachedToken } | { readonly ok: false };

export interface TokenCacheOptions {
  /** The caller, for the one line a failed mint writes. */
  readonly name: string;
  readonly mint: Mint;
  /** Milliseconds since the epoch. */
  readonly now: () => number;
  readonly log: Logger;
  readonly mintTimeoutMs?: number;
}

export class TokenCache {
  private readonly options: TokenCacheOptions;
  private cached: CachedToken | undefined;
  private inflight: Promise<Outcome> | undefined;
  /** When the last mint failed; undefined after a success. */
  private failedAt: number | undefined;
  /** Whether this backoff window has been reported already: a scheduler ticking every second must not write ten lines. */
  private backoffLogged = false;

  constructor(options: TokenCacheOptions) {
    this.options = options;
  }

  /**
   * The token to answer with. `callerLeft` is the request's own signal: it ends this request's wait, and nothing else.
   */
  async get(callerLeft?: AbortSignal): Promise<CacheAnswer> {
    const now = this.options.now();
    const cached = this.cached;
    if (cached !== undefined && now < cached.refreshAt * 1000) return { ok: true, token: cached };
    const valid = cached !== undefined && now < cached.expiresAt * 1000;
    let flight = this.inflight;
    if (flight === undefined && this.failedAt !== undefined && now < this.failedAt + RETRY_BACKOFF_MS) {
      // Inside the window the answer is whatever is already in hand.
      if (valid) return { ok: true, token: cached };
      if (this.backoffLogged) return { ok: false, reason: "backoff-repeat" };
      this.backoffLogged = true;
      return { ok: false, reason: "backoff" };
    }
    flight ??= this.start();
    // Past the refresh point but not expired: the refresh is started (or already running) and this request does not
    // wait for it. A slow Clerk then costs a caller nothing until the token actually expires.
    if (valid) return { ok: true, token: cached };

    const outcome = await waitFor(flight, callerLeft);
    if (outcome === "left") return { ok: false, reason: "caller-left" };
    if (outcome.ok) return { ok: true, token: outcome.token };
    // Nothing was valid when this request started waiting, but look again: another mint may have landed meanwhile.
    const latest = this.cached;
    if (latest !== undefined && this.options.now() < latest.expiresAt * 1000) return { ok: true, token: latest };
    return { ok: false, reason: "failed" };
  }

  /** Starts the one mint, detached from every request; it settles the cache itself and never rejects. */
  private start(): Promise<Outcome> {
    // A microtask later, so that `inflight` is set before anything in the mint can settle it.
    const flight = Promise.resolve().then(() => this.run());
    this.inflight = flight;
    return flight;
  }

  private async run(): Promise<Outcome> {
    const { name, mint, now, log } = this.options;
    const timeout = new AbortController();
    const timer = setTimeout(() => {
      timeout.abort(new Error("context deadline exceeded"));
    }, this.options.mintTimeoutMs ?? MINT_TIMEOUT_MS);
    let outcome: Outcome;
    try {
      const token = await mint(timeout.signal);
      outcome = { ok: true, token: cacheEntryFrom(token, now()) };
    } catch (err) {
      // Logged here, once per mint, and not by the requests: a refresh past the refresh point runs behind a request
      // that has already been answered with the cached token. The text is ours, never Clerk's body.
      log(`minting a machine token for ${name} failed: ${err instanceof Error ? err.message : "unknown error"}`);
      outcome = { ok: false };
    } finally {
      clearTimeout(timer);
    }
    if (outcome.ok) {
      this.cached = outcome.token;
      this.failedAt = undefined;
    } else {
      this.failedAt = now();
      this.backoffLogged = false;
    }
    this.inflight = undefined;
    return outcome;
  }
}

/** The flight's outcome, or "left" as soon as the caller's signal fires; the flight itself is untouched either way. */
function waitFor(flight: Promise<Outcome>, callerLeft: AbortSignal | undefined): Promise<Outcome | "left"> {
  if (callerLeft === undefined) return flight;
  if (callerLeft.aborted) return Promise.resolve("left");
  return new Promise((resolve) => {
    const onLeft = (): void => {
      resolve("left");
    };
    callerLeft.addEventListener("abort", onLeft, { once: true });
    void flight.then((outcome) => {
      callerLeft.removeEventListener("abort", onLeft);
      resolve(outcome);
    });
  });
}
