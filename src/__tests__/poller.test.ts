/**
 * The poller (decisions 7 and 8) with a fake clock, a stubbed st-gateway and the real SQLite store: the cadence, every
 * transition of the state machine, the forced poll's cooldown, no overlapping polls, shutdown, and what survives a
 * restart on the same file.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";

import { getCredential, sqliteVaultStore, type Credential, type VaultStore } from "../db/credential";
import { openDatabase, openInMemory } from "../db/database";
import { formatRfc3339 } from "../goTime";
import { FORCED_POLL_COOLDOWN_MS, Poller } from "../poller";
import { UpstreamError, type RootInfo } from "../spacetraders/client";
import { DAY_MS, HOUR_MS, nextPollInterval } from "../state/machine";
import { credential, time } from "../testSupport/createTestApp";
import { deferred, FakeUpstream, rootOf } from "../testSupport/fakeUpstream";

const T0 = Date.parse("2026-10-04T12:00:00Z");

const STORED = credential({
  accountToken: "account-token-1",
  agentToken: "agent-token-0",
  agentSymbol: "CONTRACT-1",
  faction: "COSMIC",
  email: "pilot@example.com",
  resetDate: time("2026-09-01T00:00:00Z"),
  nextPredictedReset: time("2099-01-01T00:00:00Z"),
});

interface World {
  db: DatabaseSync;
  store: VaultStore;
  upstream: FakeUpstream;
  poller: Poller;
  logs: string[];
  monotonic: { now: number };
}

const worlds: World[] = [];
/** A poller over a fresh store holding `row` (null: nothing registered). */
function world(row: Credential | null = STORED, db: DatabaseSync = openInMemory()): World {
  const store = sqliteVaultStore(db);
  if (row !== null) store.upsert(row, T0 - DAY_MS);
  if (row?.tokenExpired === true) store.setTokenExpired(true, T0 - DAY_MS);
  const upstream = new FakeUpstream();
  const logs: string[] = [];
  const monotonic = { now: 1_000 };
  const poller = new Poller({ store, upstream, log: (l) => logs.push(l), now: () => Date.now(), monotonic: () => monotonic.now });
  const w = { db, store, upstream, poller, logs, monotonic };
  worlds.push(w);
  return w;
}

const history = (db: DatabaseSync): string[] => (db.prepare("SELECT event FROM registration_history ORDER BY id").all() as { event: string }[]).map((r) => r.event);
const dates = (c: Credential | undefined): [string, string] => [c?.resetDate ? formatRfc3339(c.resetDate) : "", c?.nextPredictedReset ? formatRfc3339(c.nextPredictedReset) : ""];

beforeEach(() => {
  jest.useFakeTimers({ now: T0 });
});
afterEach(async () => {
  for (const w of worlds.splice(0)) await w.poller.stop();
  jest.useRealTimers();
});

describe("nextPollInterval (decision 7's cadence)", () => {
  it("is a day with no prediction, a day outside the 24 h window, an hour inside it and after the reset", () => {
    expect(nextPollInterval(T0, null)).toBe(DAY_MS);
    expect(nextPollInterval(T0, time("0001-01-01T00:00:00Z"))).toBe(DAY_MS);
    expect(nextPollInterval(T0, { ...time("2026-10-05T12:00:00Z"), ms: T0 + DAY_MS + 1 })).toBe(DAY_MS);
    expect(nextPollInterval(T0, { ...time("2026-10-05T12:00:00Z"), ms: T0 + DAY_MS })).toBe(HOUR_MS);
    expect(nextPollInterval(T0, time("2026-10-04T13:00:00Z"))).toBe(HOUR_MS);
    expect(nextPollInterval(T0, time("2020-01-01T00:00:00Z"))).toBe(HOUR_MS);
  });
});

describe("the scheduled cadence", () => {
  it("polls at start, then once a day while the predicted reset is far off", async () => {
    const w = world();
    w.poller.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(w.upstream.rootCalls.map((c) => c.at)).toEqual([T0]);
    await jest.advanceTimersByTimeAsync(DAY_MS - 1);
    expect(w.upstream.rootCalls).toHaveLength(1);
    await jest.advanceTimersByTimeAsync(1);
    expect(w.upstream.rootCalls.map((c) => c.at - T0)).toEqual([0, DAY_MS]);
    await jest.advanceTimersByTimeAsync(DAY_MS);
    expect(w.upstream.rootCalls).toHaveLength(3);
  });

  it("polls hourly from 24 h before the predicted reset, recomputing after every poll", async () => {
    const w = world();
    // The first poll learns of a reset 30 h away: a day's wait is still right (it ends inside the window) ...
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-01", "2026-10-05T18:00:00Z"));
    w.poller.start();
    await jest.advanceTimersByTimeAsync(DAY_MS);
    expect(w.upstream.rootCalls.map((c) => c.at - T0)).toEqual([0, DAY_MS]);
    // ... and from there, 6 h before the reset, every hour.
    await jest.advanceTimersByTimeAsync(3 * HOUR_MS);
    expect(w.upstream.rootCalls.map((c) => (c.at - T0) / HOUR_MS)).toEqual([0, 24, 25, 26, 27]);
  });

  it("takes up a new prediction at once: a reset moved out ends the hourly polls", async () => {
    const w = world(credential({ ...STORED, nextPredictedReset: time("2026-10-04T18:00:00Z") }));
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-01", "2026-10-04T18:00:00Z"));
    w.poller.start();
    await jest.advanceTimersByTimeAsync(HOUR_MS);
    expect(w.upstream.rootCalls).toHaveLength(2);
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-01", "2026-10-20T00:00:00Z"));
    await jest.advanceTimersByTimeAsync(HOUR_MS);
    expect(w.upstream.rootCalls).toHaveLength(3);
    await jest.advanceTimersByTimeAsync(DAY_MS - 1);
    expect(w.upstream.rootCalls).toHaveLength(3);
    await jest.advanceTimersByTimeAsync(1);
    expect(w.upstream.rootCalls).toHaveLength(4);
  });

  it("with no credential calls nothing, and looks again a day later", async () => {
    const w = world(null);
    w.poller.start();
    await jest.advanceTimersByTimeAsync(DAY_MS - 1);
    expect(w.upstream.rootCalls).toHaveLength(0);
    w.store.upsert(STORED, Date.now());
    await jest.advanceTimersByTimeAsync(1);
    expect(w.upstream.rootCalls).toHaveLength(1);
  });

  it("keeps going after a failed poll, logging it without upstream's text", async () => {
    const w = world();
    w.upstream.root = () => Promise.reject(new UpstreamError(503, "GET /", Buffer.from("upstream-body-sentinel")));
    w.poller.start();
    await jest.advanceTimersByTimeAsync(DAY_MS);
    expect(w.upstream.rootCalls).toHaveLength(2);
    expect(w.logs).toEqual(["poller tick failed: spacetraders upstream error (503) on GET /", "poller tick failed: spacetraders upstream error (503) on GET /"]);
    expect(w.logs.join("\n")).not.toContain("upstream-body-sentinel");
  });

  it("waits a day when the row cannot be read", async () => {
    const w = world();
    const get = jest.spyOn(w.store, "get").mockImplementation(() => {
      throw new Error("disk I/O error");
    });
    w.poller.start();
    await jest.advanceTimersByTimeAsync(DAY_MS - 1);
    expect(w.logs).toEqual(["poller tick failed: Error: disk I/O error"]);
    get.mockRestore();
    await jest.advanceTimersByTimeAsync(1);
    expect(w.upstream.rootCalls).toHaveLength(1);
  });

  it("is a chain of timeouts, one at a time, never an interval", async () => {
    const w = world();
    const interval = jest.spyOn(global, "setInterval");
    w.poller.start();
    await jest.advanceTimersByTimeAsync(3 * DAY_MS);
    expect(interval).not.toHaveBeenCalled();
    expect(jest.getTimerCount()).toBe(1);
    interval.mockRestore();
  });
});

describe("one poll: the state machine", () => {
  it("on schedule, an unchanged resetDate changes nothing but the dates, and never flags the token", async () => {
    const w = world();
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-01", "2099-02-01T00:00:00Z"));
    await w.poller.tick(false);
    const row = getCredential(w.db);
    expect(row).toMatchObject({ agentToken: "agent-token-0", tokenExpired: false });
    expect(dates(row)).toEqual(["2026-09-01T00:00:00Z", "2099-02-01T00:00:00Z"]);
    expect(w.upstream.registerCalls).toHaveLength(0);
    expect(history(w.db)).toEqual([]);
  });

  it("on schedule, does not clear a flag that is up", async () => {
    const w = world(credential({ ...STORED, tokenExpired: true }));
    await w.poller.tick(false);
    expect(getCredential(w.db)?.tokenExpired).toBe(true);
  });

  it("after a 401, an unchanged resetDate is a dead token: APP_TOKEN_EXPIRED, the token kept", async () => {
    const w = world();
    await w.poller.tick(true);
    expect(getCredential(w.db)).toMatchObject({ agentToken: "agent-token-0", tokenExpired: true });
    expect(history(w.db)).toEqual(["token_expired_detected"]);
    expect(w.upstream.registerCalls).toHaveLength(0);
  });

  it("after a 401, a root without resetDate still flags the token, and forgets the stored dates", async () => {
    const w = world();
    w.upstream.root = () => Promise.resolve(rootOf(null, null));
    await w.poller.tick(true);
    const row = getCredential(w.db);
    expect(row?.tokenExpired).toBe(true);
    expect(dates(row)).toEqual(["", ""]);
  });

  it.each([true, false])("a changed resetDate is a wipe (afterUnauthorized=%s): re-registers with what is stored, keeps the symbol, adopts the dates", async (after) => {
    const w = world(credential({ ...STORED, tokenExpired: true }));
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-15", "2099-02-01T00:00:00Z"));
    await w.poller.tick(after);
    expect(w.upstream.registerCalls).toEqual([{ accountToken: "account-token-1", symbol: "CONTRACT-1", faction: "COSMIC", email: "pilot@example.com" }]);
    const row = getCredential(w.db);
    // A fresh token is not expired, whatever the flag said; the reset explains the 401, so it is not raised either.
    expect(row).toMatchObject({ accountToken: "account-token-1", agentToken: "agent-token-1", agentSymbol: "CONTRACT-1", faction: "COSMIC", email: "pilot@example.com", tokenExpired: false });
    expect(dates(row)).toEqual(["2026-09-15T00:00:00Z", "2099-02-01T00:00:00Z"]);
    expect(history(w.db)).toEqual(["wipe_detected", "registered"]);
  });

  it("a failed re-registration is not a dead token: old token, old dates, the flag as it was, and the poll fails", async () => {
    const w = world();
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-15", "2099-02-01T00:00:00Z"));
    w.upstream.registration = () => Promise.reject(new UpstreamError(500, "POST /register", Buffer.from("boom")));
    await expect(w.poller.tick(true)).rejects.toBeInstanceOf(UpstreamError);
    const row = getCredential(w.db);
    expect(row).toMatchObject({ agentToken: "agent-token-0", tokenExpired: false });
    expect(dates(row)).toEqual(["2026-09-01T00:00:00Z", "2099-01-01T00:00:00Z"]);
    expect(history(w.db)).toEqual(["wipe_detected"]);
  });

  it("a re-registration whose history row cannot be written fails the poll: the new token is kept, the dates are not adopted", async () => {
    const w = world();
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-15", "2099-02-01T00:00:00Z"));
    const append = jest.spyOn(w.store, "appendHistory").mockImplementation(() => {
      throw new Error("disk full");
    });
    await expect(w.poller.tick(false)).rejects.toThrow("disk full");
    append.mockRestore();
    const row = getCredential(w.db);
    expect(row?.agentToken).toBe("agent-token-1");
    expect(dates(row)).toEqual(["2026-09-01T00:00:00Z", "2099-01-01T00:00:00Z"]);
    expect(w.logs).toEqual(["failed to record wipe_detected: Error: disk full"]);
  });

  it("is not a wipe when either date is zero, or when the two are the same instant in other zones", async () => {
    for (const [stored, fetched] of [
      [null, "2026-09-15"],
      ["2026-09-01T00:00:00Z", null],
      ["2026-09-01T00:00:00Z", "2026-09-01T02:00:00+02:00"],
    ] as const) {
      const w = world(credential({ ...STORED, resetDate: stored === null ? null : time(stored) }));
      w.upstream.root = () => Promise.resolve(rootOf(fetched, "2099-01-01T00:00:00Z"));
      await w.poller.tick(false);
      expect(w.upstream.registerCalls).toHaveLength(0);
    }
  });

  it("is not a wipe when the stored date is Go's zero time written out (only a hand-edited file holds one)", async () => {
    const w = world();
    w.db.prepare("UPDATE credential SET reset_date = '0001-01-01T02:00:00+02:00'").run();
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-15", "2099-02-01T00:00:00Z"));
    await w.poller.tick(false);
    expect(w.upstream.registerCalls).toHaveLength(0);
    expect(dates(getCredential(w.db))).toEqual(["2026-09-15T00:00:00Z", "2099-02-01T00:00:00Z"]);
  });

  it("compares to the nanosecond, as Go's Time.Equal does: a fraction on SpaceTraders' resetDate is a change", async () => {
    const w = world();
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-01T00:00:00.000000001Z", "2099-01-01T00:00:00Z"));
    await w.poller.tick(false);
    expect(w.upstream.registerCalls).toHaveLength(1);
  });

  it("a root that cannot be fetched changes nothing and does not flag the token", async () => {
    const w = world();
    w.upstream.root = () => Promise.reject(new Error("socket hang up"));
    await expect(w.poller.tick(true)).rejects.toThrow("socket hang up");
    expect(getCredential(w.db)).toEqual(STORED);
  });

  it("with no credential calls nothing", async () => {
    const w = world(null);
    await w.poller.tick(true);
    expect(w.upstream.rootCalls).toHaveLength(0);
  });
});

describe("forced polls: the 10 s cooldown", () => {
  it("lets the first through, and one of a burst", async () => {
    const w = world();
    w.monotonic.now = 0;
    await Promise.all(Array.from({ length: 12 }, () => w.poller.pollNow()));
    expect(w.upstream.rootCalls).toHaveLength(1);
    expect(getCredential(w.db)?.tokenExpired).toBe(true);
  });

  it("is closed until 10 s have passed on the monotonic clock, and open at 10 s exactly", async () => {
    expect(FORCED_POLL_COOLDOWN_MS).toBe(10_000);
    const w = world();
    await w.poller.pollNow();
    w.monotonic.now += 9_999;
    await w.poller.pollNow();
    expect(w.upstream.rootCalls).toHaveLength(1);
    w.monotonic.now += 1;
    await w.poller.pollNow();
    expect(w.upstream.rootCalls).toHaveLength(2);
  });

  it("is opened by a forced poll that fails, and by one with no credential", async () => {
    const failing = world();
    failing.upstream.root = () => Promise.reject(new Error("down"));
    await expect(failing.poller.pollNow()).rejects.toThrow("down");
    failing.upstream.root = () => Promise.resolve(rootOf("2026-09-01", "2099-01-01T00:00:00Z"));
    await failing.poller.pollNow();
    expect(failing.upstream.rootCalls).toHaveLength(1);

    const empty = world(null);
    await empty.poller.pollNow();
    empty.store.upsert(STORED, Date.now());
    await empty.poller.pollNow();
    expect(empty.upstream.rootCalls).toHaveLength(0);
    empty.monotonic.now += FORCED_POLL_COOLDOWN_MS;
    await empty.poller.pollNow();
    expect(empty.upstream.rootCalls).toHaveLength(1);
  });

  it("does not hold back scheduled polls or the poll after a registration", async () => {
    const w = world();
    await w.poller.pollNow();
    await w.poller.tick(false);
    await w.poller.tick(false);
    expect(w.upstream.rootCalls).toHaveLength(3);
  });

  it("returns at once inside the window, without waiting for a poll in flight", async () => {
    const w = world();
    const slow = deferred<RootInfo>();
    w.upstream.root = () => slow.promise;
    const first = w.poller.pollNow();
    let second = false;
    void w.poller.pollNow().then(() => {
      second = true;
    });
    await jest.advanceTimersByTimeAsync(0);
    expect(second).toBe(true);
    slow.resolve(rootOf("2026-09-01", "2099-01-01T00:00:00Z"));
    await first;
  });
});

describe("no overlapping polls", () => {
  it("queues a forced poll behind a scheduled one in flight, and each runs whole", async () => {
    const w = world();
    const slow = deferred<RootInfo>();
    w.upstream.root = () => slow.promise;
    const scheduled = w.poller.tick(false);
    const forced = w.poller.pollNow();
    await jest.advanceTimersByTimeAsync(0);
    expect(w.upstream.rootCalls).toHaveLength(1);
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-01", "2099-01-01T00:00:00Z"));
    slow.resolve(rootOf("2026-09-01", "2099-01-01T00:00:00Z"));
    await scheduled;
    await forced;
    expect(w.upstream.rootCalls).toHaveLength(2);
    expect(getCredential(w.db)?.tokenExpired).toBe(true);
  });

  it("runs the next poll after one that failed", async () => {
    const w = world();
    const slow = deferred<RootInfo>();
    w.upstream.root = () => slow.promise;
    const first = w.poller.tick(false);
    const second = w.poller.tick(false);
    await jest.advanceTimersByTimeAsync(0);
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-01", "2099-01-01T00:00:00Z"));
    slow.reject(new Error("down"));
    await expect(first).rejects.toThrow("down");
    await second;
    expect(w.upstream.rootCalls).toHaveLength(2);
  });

  it("never starts a scheduled poll while another is in flight", async () => {
    const w = world(credential({ ...STORED, nextPredictedReset: time("2026-10-04T18:00:00Z") }));
    let inFlight = 0;
    let most = 0;
    w.upstream.root = async () => {
      most = Math.max(most, ++inFlight);
      await new Promise((r) => setTimeout(r, 2 * HOUR_MS));
      inFlight--;
      return rootOf("2026-09-01", "2026-10-04T18:00:00Z");
    };
    w.poller.start();
    const forced = w.poller.pollNow();
    await jest.advanceTimersByTimeAsync(10 * HOUR_MS);
    await forced;
    const stopped = w.poller.stop();
    await jest.advanceTimersByTimeAsync(2 * HOUR_MS);
    await stopped;
    expect(w.upstream.rootCalls.length).toBeGreaterThan(4);
    expect(most).toBe(1);
  });
});

describe("shutdown", () => {
  it("ends the wait at once and polls no more", async () => {
    const w = world();
    w.poller.start();
    await jest.advanceTimersByTimeAsync(0);
    await w.poller.stop();
    expect(jest.getTimerCount()).toBe(0);
    await jest.advanceTimersByTimeAsync(3 * DAY_MS);
    expect(w.upstream.rootCalls).toHaveLength(1);
  });

  it("abandons an upstream call in flight and resolves once the poll has settled", async () => {
    const w = world();
    w.upstream.root = () => new Promise((_, reject) => w.upstream.rootCalls[0]?.signal?.addEventListener("abort", () => { reject(new Error("aborted")); }));
    w.poller.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(w.upstream.rootCalls[0]?.signal?.aborted).toBe(false);
    await w.poller.stop();
    expect(w.upstream.rootCalls[0]?.signal?.aborted).toBe(true);
    expect(w.logs).toEqual(["poller tick failed: Error: aborted"]);
    expect(w.upstream.rootCalls).toHaveLength(1);
  });

  it("passes the same signal to registration, so a re-registration is abandoned too", () => {
    const w = world();
    const register = jest.spyOn(w.upstream, "register");
    void w.poller.register("a", "b", "c", "d").catch(() => undefined);
    expect(register).toHaveBeenCalledWith("a", "b", "c", "d", expect.any(AbortSignal));
  });
});

describe("the wait between polls does not keep the process alive", () => {
  it("is unref'd, as the Go goroutine never held the process", async () => {
    jest.useRealTimers();
    const w = world();
    const timeouts = (): number => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
    const before = timeouts();
    w.poller.start();
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    expect(w.upstream.rootCalls).toHaveLength(1);
    expect(timeouts()).toBe(before);
  });
});

describe("what survives a restart on the same file", () => {
  const dirs: string[] = [];
  afterAll(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  it("the credential, the dates and the flag; a scheduled poll at start does not clear the flag", async () => {
    const dir = mkdtempSync(join(tmpdir(), "auth-poller-"));
    dirs.push(dir);
    const path = join(dir, "auth.db");
    const quiet = (): void => undefined;

    const first = world(STORED, openDatabase(path, quiet));
    await first.poller.pollNow();
    await first.poller.stop();
    first.db.close();

    const second = world(null, openDatabase(path, quiet));
    expect(getCredential(second.db)).toMatchObject({ agentToken: "agent-token-0", tokenExpired: true });
    second.poller.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(second.upstream.rootCalls).toHaveLength(1);
    expect(getCredential(second.db)?.tokenExpired).toBe(true);
    expect(history(second.db)).toEqual(["token_expired_detected"]);
    await second.poller.stop();
    second.db.close();
  });
});
