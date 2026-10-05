/**
 * @file Decision 7's poller and decision 8's APP_TOKEN_EXPIRED, ported from the Go service's src/poller/poller.go.
 *
 * auth-service polls SpaceTraders' unauthenticated root through st-gateway, adopts a `resetDate` change as proof that a
 * wipe already happened (the only trigger that re-registers), and treats a 401 that finds the same `resetDate` as a
 * dead token that was not wiped.
 *
 *  - **Cadence** (`start`): a poll at once, then again after `nextPollInterval` (a day; an hour from 24 h before the
 *    predicted reset), recomputed after every poll. A chain of setTimeouts, never setInterval. Errors are logged and the
 *    chain goes on: the service exists to survive exactly that kind of hiccup.
 *  - **Forced polls** (`pollNow`, from `GET /auth/v1/token?afterUnauthorized=true`): at most one per 10 s, process-wide.
 *    The window is taken BEFORE the poll and kept whatever happens to it: a forced poll with no credential, or whose
 *    fetch fails, still opens it (contract README note 27). The first forced poll after start always goes through.
 *  - **No overlapping polls, and no operator write inside one.** Every poll (scheduled, forced, the one after a
 *    registration) and both operator writes (Restore Token, Reset Agent) run on one queue (`exclusive`), so two never
 *    interleave their reads and writes of the row. Go ran them on separate goroutines, and two of those interleavings
 *    lost an operator's write. A forced poll inside the window does not wait for the queue; one outside it waits for
 *    what is in flight, so behind a stuck call it can take up to two upstream timeouts (about 60 s, Go: 30 s).
 *  - **Shutdown** (`stop`): the AbortController ends the wait at once and abandons an upstream call in flight; `stop`
 *    resolves when the poll that was running has settled, so the database can be closed after it.
 *  - The wait between polls is unref'd: in Go the poller goroutine never kept the process alive, the HTTP server did.
 *
 * Nothing here logs a credential: errors are logged with `describeError`, which never carries upstream's body.
 */
import { performance } from "node:perf_hooks";

import type { Credential, VaultStore } from "./db/credential";
import { sameInstant, isZeroTime } from "./goTime";
import type { Logger } from "./log";
import { describeError, type RegisterResult, type SpaceTradersClient } from "./spacetraders/client";
import { DAY_MS, nextPollInterval } from "./state/machine";

/**
 * How often an out-of-cycle poll (st-gateway forwarding a 401) may reach SpaceTraders: st-gateway's own retry loop
 * could otherwise turn a burst of 401s into a poll storm.
 */
export const FORCED_POLL_COOLDOWN_MS = 10_000;

export interface PollerDeps {
  readonly store: VaultStore;
  readonly upstream: SpaceTradersClient;
  readonly log: Logger;
  /** Wall clock, milliseconds since the epoch: the dates written and the cadence. */
  readonly now?: () => number;
  /** A monotonic clock in milliseconds, for the cooldown (Go's time.Now carries a monotonic reading). */
  readonly monotonic?: () => number;
}

export class Poller {
  private readonly store: VaultStore;
  private readonly upstream: SpaceTradersClient;
  private readonly log: Logger;
  private readonly now: () => number;
  private readonly monotonic: () => number;
  private readonly abort = new AbortController();
  /** The tail of the poll queue; never rejects. */
  private queue: Promise<void> = Promise.resolve();
  /** When the last forced poll was let through; -Infinity before the first. */
  private lastForced = Number.NEGATIVE_INFINITY;
  private timer: NodeJS.Timeout | undefined;
  private wake: (() => void) | undefined;
  private running: Promise<void> | undefined;

  constructor(deps: PollerDeps) {
    this.store = deps.store;
    this.upstream = deps.upstream;
    this.log = deps.log;
    this.now = deps.now ?? Date.now;
    this.monotonic = deps.monotonic ?? (() => performance.now());
  }

  /** Run: poll now, then on decision 7's cadence until `stop`. */
  start(): void {
    if (this.running !== undefined) throw new Error("the poller is already running");
    this.running = this.loop();
  }

  /** Ends the cadence, abandons an upstream call in flight, and resolves once no poll is running. */
  async stop(): Promise<void> {
    this.abort.abort();
    clearTimeout(this.timer);
    this.wake?.();
    await this.running;
    await this.queue;
  }

  private async loop(): Promise<void> {
    for (;;) {
      try {
        await this.tick(false);
      } catch (err) {
        this.log(`poller tick failed: ${describeError(err)}`);
      }
      if (this.stopped()) return;
      await this.sleep(this.nextInterval());
      if (this.stopped()) return;
    }
  }

  private stopped(): boolean {
    return this.abort.signal.aborted;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      this.wake = resolve;
      this.timer = setTimeout(resolve, ms);
      this.timer.unref();
    });
  }

  private nextInterval(): number {
    let credential: Credential | undefined;
    try {
      credential = this.store.get();
    } catch {
      return DAY_MS;
    }
    return credential === undefined ? DAY_MS : nextPollInterval(this.now(), credential.nextPredictedReset);
  }

  /**
   * PollNow: the out-of-cycle poll decision 7 requires. Inside the cooldown it returns at once without polling; outside
   * it takes the window first, then polls with `afterUnauthorized` (the only poll that can conclude APP_TOKEN_EXPIRED).
   */
  pollNow(): Promise<void> {
    const now = this.monotonic();
    if (now - this.lastForced < FORCED_POLL_COOLDOWN_MS) return Promise.resolve();
    this.lastForced = now;
    return this.tick(true);
  }

  /** Tick, queued behind any poll or operator write in flight. Rejects with the poll's error. */
  tick(afterUnauthorized: boolean): Promise<void> {
    return this.exclusive(() => this.pollOnce(afterUnauthorized));
  }

  /**
   * Runs `work` on the poll queue, so that nothing else that reads and writes the row (a poll, a re-registration, the
   * other operator route) runs meanwhile. The operator routes' writes go through here: in Go they raced with a poll in
   * flight (a Restore Token landing during a forced poll was undone by its expired flag; a Reset Agent landing during a
   * re-registration was overwritten with the old account). Resolves or rejects with `work`'s outcome; the queue goes on.
   */
  exclusive<T>(work: () => T | Promise<T>): Promise<T> {
    const run = this.queue.then(work);
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /** The registration both the register route and the re-registration make, through the same upstream client. */
  register(accountToken: string, symbol: string, faction: string, email: string): Promise<RegisterResult> {
    return this.upstream.register(accountToken, symbol, faction, email, this.abort.signal);
  }

  /**
   * One poll-and-react cycle. `afterUnauthorized` tells "polling because a 401 just happened" from "polling on
   * schedule": only the former can conclude APP_TOKEN_EXPIRED, because an unchanged resetDate found on schedule says
   * nothing about whether the token still works.
   */
  private async pollOnce(afterUnauthorized: boolean): Promise<void> {
    const now = this.now();
    const credential = this.store.get();
    // UNCONFIGURED: nothing to compare a fetched resetDate with yet.
    if (credential === undefined) return;

    const root = await this.upstream.getRoot(this.abort.signal);
    const stored = credential.resetDate;
    const fetched = root.resetDate;
    const resetChanged = stored !== null && !isZeroTime(stored) && fetched !== null && !isZeroTime(fetched) && !sameInstant(fetched, stored);

    if (resetChanged) {
      this.record(now, "wipe_detected", "observed resetDate change");
      // A failed re-registration leaves token_expired alone (it is not the same claim as a dead token) and the dates
      // as they were, and the next poll retries.
      await this.reregister(credential, now);
    } else if (afterUnauthorized) {
      this.store.setTokenExpired(true, now);
      this.record(now, "token_expired_detected", "401 with no resetDate change");
    }
    this.store.updateResetInfo(root.resetDate, root.nextReset, now);
  }

  /**
   * Re-mints the agent with the account token and the reserved call sign on file (decision 7: reserve the call sign and
   * pass it), so the event log keeps correlating across a reset. The stored symbol is kept whatever SpaceTraders answers.
   */
  private async reregister(credential: Credential, now: number): Promise<void> {
    const result = await this.register(credential.accountToken, credential.agentSymbol, credential.faction, credential.email);
    this.store.upsert({ ...credential, agentToken: result.agentToken }, now);
    // Unlike the other history rows, a failure here fails the poll (Go returns it), so the dates are not updated.
    this.store.appendHistory(now, "registered", "automatic re-registration after observed reset");
  }

  /** A history row whose failure is only logged. */
  private record(now: number, event: string, detail: string): void {
    try {
      this.store.appendHistory(now, event, detail);
    } catch (err) {
      this.log(`failed to record ${event}: ${describeError(err)}`);
    }
  }
}
