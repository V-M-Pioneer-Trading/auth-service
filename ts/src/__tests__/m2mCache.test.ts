/**
 * The per-caller token cache (m2m/cache.ts) on a fake clock: single flight, the detached mint, the refresh at half
 * the lifetime, the 10 s backoff, the 10 s mint timeout, and that a token past its `exp` is never served.
 */
import { MINT_TIMEOUT_MS, RETRY_BACKOFF_MS, TokenCache, type Mint } from "../m2m/cache";

const T0 = Date.parse("2026-10-05T12:00:00Z");
const S0 = T0 / 1000;

const b64u = (s: string): string => Buffer.from(s).toString("base64url");
/** An unsigned token: the cache reads `iat` and `exp` only. */
const token = (iat: number, exp: number, tag = ""): string => `${b64u('{"alg":"RS256"}')}.${b64u(JSON.stringify({ iat, exp, tag }))}.sig`;

interface Controlled {
  mint: Mint;
  calls: AbortSignal[];
  /** Settles the n-th call (0-based). */
  resolve(n: number, value: string): void;
  reject(n: number, why?: string): void;
}

/** A mint whose calls the test settles by hand. A call also rejects when its signal aborts, as the Clerk minter does. */
function controlled(): Controlled {
  const calls: AbortSignal[] = [];
  const settlers: { resolve: (v: string) => void; reject: (e: Error) => void }[] = [];
  return {
    calls,
    mint: (signal) =>
      new Promise<string>((resolve, reject) => {
        calls.push(signal);
        settlers.push({ resolve, reject });
        signal.addEventListener("abort", () => {
          reject(new Error("context deadline exceeded"));
        });
      }),
    resolve: (n, value) => {
      settlers[n]?.resolve(value);
    },
    reject: (n, why = "status 500") => {
      settlers[n]?.reject(new Error(why));
    },
  };
}

/** Lets every pending promise callback run. */
const flush = async (): Promise<void> => {
  for (let i = 0; i < 10; i++) await Promise.resolve();
};

let logs: string[];
const cacheWith = (mint: Mint): TokenCache => new TokenCache({ name: "automation-service", mint, now: () => Date.now(), log: (l) => logs.push(l) });

beforeEach(() => {
  jest.useFakeTimers({ now: T0 });
  logs = [];
});
afterEach(() => {
  jest.useRealTimers();
});

describe("single flight", () => {
  it("25 concurrent first requests cost one mint and all get the same token", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const waiting = Array.from({ length: 25 }, () => cache.get());
    await flush();
    expect(m.calls).toHaveLength(1);
    m.resolve(0, token(S0, S0 + 86400));
    const answers = await Promise.all(waiting);
    expect(new Set(answers.map((a) => (a.ok ? a.token.token : "none")))).toEqual(new Set([token(S0, S0 + 86400)]));
    expect(m.calls).toHaveLength(1);
  });

  it("serves from memory afterwards: no second mint before the refresh point", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const first = cache.get();
    await flush();
    m.resolve(0, token(S0, S0 + 86400));
    await first;
    for (let i = 0; i < 5; i++) expect((await cache.get()).ok).toBe(true);
    expect(m.calls).toHaveLength(1);
  });
});

describe("the mint is detached from the request", () => {
  it("a caller that leaves does not cancel the mint, and its retry finds the token", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const left = new AbortController();
    const waiting = cache.get(left.signal);
    await flush();
    left.abort();
    expect(await waiting).toEqual({ ok: false, reason: "caller-left" });
    expect(m.calls[0]?.aborted).toBe(false);
    m.resolve(0, token(S0, S0 + 86400));
    await flush();
    const retry = await cache.get();
    expect(retry.ok && retry.token.token).toBe(token(S0, S0 + 86400));
    expect(m.calls).toHaveLength(1);
  });

  it("a retry while the mint still runs joins it", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const left = new AbortController();
    const first = cache.get(left.signal);
    await flush();
    left.abort();
    await first;
    const retry = cache.get();
    await flush();
    m.resolve(0, token(S0, S0 + 86400));
    expect((await retry).ok).toBe(true);
    expect(m.calls).toHaveLength(1);
  });
});

describe("refresh at half the lifetime", () => {
  it("mints again only from iat + (exp - iat) / 2, answering with the cached token at once while it runs", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    // A 101 s token: the refresh point is iat + 50 (Go's integer division).
    const old = token(S0, S0 + 101, "old");
    const first = cache.get();
    await flush();
    m.resolve(0, old);
    await first;

    jest.setSystemTime(T0 + 50_000 - 1);
    expect(await cache.get()).toMatchObject({ ok: true, token: { token: old } });
    await flush();
    expect(m.calls).toHaveLength(1);

    jest.setSystemTime(T0 + 50_000);
    const during = await cache.get();
    expect(during).toMatchObject({ ok: true, token: { token: old } });
    await flush();
    expect(m.calls).toHaveLength(2);
    // Concurrent requests share the one refresh.
    expect(await cache.get()).toMatchObject({ ok: true, token: { token: old } });
    await flush();
    expect(m.calls).toHaveLength(2);

    const fresh = token(S0 + 50, S0 + 50 + 86400, "new");
    m.resolve(1, fresh);
    await flush();
    expect(await cache.get()).toMatchObject({ ok: true, token: { token: fresh } });
    expect(m.calls).toHaveLength(2);
  });

  it("a failed refresh never costs the caller its unexpired token", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const old = token(S0, S0 + 100);
    const first = cache.get();
    await flush();
    m.resolve(0, old);
    await first;
    jest.setSystemTime(T0 + 60_000);
    expect(await cache.get()).toMatchObject({ ok: true, token: { token: old } });
    await flush();
    m.reject(1);
    await flush();
    expect(await cache.get()).toMatchObject({ ok: true, token: { token: old } });
    expect(logs).toEqual(["minting a machine token for automation-service failed: status 500"]);
  });
});

describe("the 10 s backoff after a failed mint", () => {
  it("answers without minting for 10 s, logs the window once, then mints again", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const first = cache.get();
    await flush();
    m.reject(0);
    expect(await first).toEqual({ ok: false, reason: "failed" });

    expect(RETRY_BACKOFF_MS).toBe(10_000);
    jest.setSystemTime(T0 + 10_000 - 1);
    expect(await cache.get()).toEqual({ ok: false, reason: "backoff" });
    expect(await cache.get()).toEqual({ ok: false, reason: "backoff-repeat" });
    await flush();
    expect(m.calls).toHaveLength(1);

    jest.setSystemTime(T0 + RETRY_BACKOFF_MS);
    const again = cache.get();
    await flush();
    expect(m.calls).toHaveLength(2);
    m.resolve(1, token(S0 + 10, S0 + 10 + 86400));
    expect((await again).ok).toBe(true);
  });

  it("a failure inside a window opens a new one, and its first answer is reported again", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const first = cache.get();
    await flush();
    m.reject(0);
    await first;
    jest.setSystemTime(T0 + 10_500);
    const second = cache.get();
    await flush();
    m.reject(1);
    await second;
    jest.setSystemTime(T0 + 20_000);
    expect(await cache.get()).toEqual({ ok: false, reason: "backoff" });
    await flush();
    expect(m.calls).toHaveLength(2);
  });

  it("inside the window a valid cached token is still served", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const first = cache.get();
    await flush();
    m.resolve(0, token(S0, S0 + 100));
    await first;
    jest.setSystemTime(T0 + 50_000);
    await cache.get();
    await flush();
    m.reject(1);
    await flush();
    jest.setSystemTime(T0 + 55_000);
    expect((await cache.get()).ok).toBe(true);
    await flush();
    expect(m.calls).toHaveLength(2);
  });
});

describe("an expired token is never served", () => {
  it("not at its exp, even inside the backoff window with Clerk down", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const first = cache.get();
    await flush();
    m.resolve(0, token(S0, S0 + 100));
    await first;
    // Past the refresh point: the refresh fails, the old token is still served.
    jest.setSystemTime(T0 + 95_000);
    expect((await cache.get()).ok).toBe(true);
    await flush();
    m.reject(1);
    await flush();
    jest.setSystemTime(T0 + 100_000 - 1);
    expect((await cache.get()).ok).toBe(true);
    jest.setSystemTime(T0 + 100_000);
    expect(await cache.get()).toEqual({ ok: false, reason: "backoff" });
    expect(m.calls).toHaveLength(2);
  });

  it("a request that waited for a failed mint gets no expired token either", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const first = cache.get();
    await flush();
    m.resolve(0, token(S0, S0 + 100));
    await first;
    jest.setSystemTime(T0 + 200_000);
    const waiting = cache.get();
    await flush();
    m.reject(1);
    expect(await waiting).toEqual({ ok: false, reason: "failed" });
  });
});

describe("the 10 s mint timeout", () => {
  it("aborts the mint's own signal at 10 s, not before; a waiter then gets the failure", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const waiting = cache.get();
    await flush();
    // Decision 22: 10 s, written out so that a changed constant is a failing test.
    expect(MINT_TIMEOUT_MS).toBe(10_000);
    await jest.advanceTimersByTimeAsync(10_000 - 1);
    expect(m.calls[0]?.aborted).toBe(false);
    await jest.advanceTimersByTimeAsync(1);
    expect(m.calls[0]?.aborted).toBe(true);
    expect(await waiting).toEqual({ ok: false, reason: "failed" });
    expect(logs).toEqual(["minting a machine token for automation-service failed: context deadline exceeded"]);
  });

  it("a mint that lands before the timeout clears it", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const waiting = cache.get();
    await flush();
    m.resolve(0, token(S0, S0 + 86400));
    await waiting;
    expect(jest.getTimerCount()).toBe(0);
  });
});

describe("what a minted token must be", () => {
  it("a token that cannot be cached is a failed mint: logged with our reason, nothing cached, backoff opened", async () => {
    const m = controlled();
    const cache = cacheWith(m.mint);
    const first = cache.get();
    await flush();
    m.resolve(0, token(S0, S0 + 59));
    expect(await first).toEqual({ ok: false, reason: "failed" });
    expect(logs).toEqual(["minting a machine token for automation-service failed: minted token lives 59 s, under the 60 s minimum"]);
    expect(await cache.get()).toEqual({ ok: false, reason: "backoff" });
  });

  it("a mint that throws synchronously still settles the flight", async () => {
    const cache = cacheWith(() => {
      throw new Error("bad key");
    });
    expect(await cache.get()).toEqual({ ok: false, reason: "failed" });
    jest.setSystemTime(T0 + RETRY_BACKOFF_MS);
    expect(await cache.get()).toEqual({ ok: false, reason: "failed" });
  });
});
