/**
 * @file auth-service's own lifecycle, HEALTHY / WIPE_IMMINENT / APP_TOKEN_EXPIRED / UNCONFIGURED (decision 8): a pure
 * function of the stored row and the clock, so it needs no database to test.
 */
import { isZeroTime, type GoTime } from "../goTime";

export type State = "UNCONFIGURED" | "HEALTHY" | "WIPE_IMMINENT" | "APP_TOKEN_EXPIRED";

/** How far ahead of a predicted reset WIPE_IMMINENT fires. */
export const WIPE_WINDOW_MS = 24 * 3600 * 1000;

export interface Input {
  readonly hasCredential: boolean;
  readonly agentSymbol: string;
  readonly resetDate: GoTime | null;
  readonly nextPredictedReset: GoTime | null;
  readonly tokenExpired: boolean;
}

export interface Status {
  readonly state: State;
  readonly agentSymbol: string;
  readonly resetDate: GoTime | null;
  readonly nextPredictedReset: GoTime | null;
}

/**
 * Compute. Order matters: no credential at all outranks everything, and a confirmed-expired token outranks the
 * imminent-wipe forecast, because a dead token needs a human however close the next predicted reset is.
 * WIPE_IMMINENT is `now >= next - 24h` and stays on after `next` has passed.
 */
export function compute(input: Input, nowMs: number): Status {
  const status = { agentSymbol: input.agentSymbol, resetDate: input.resetDate, nextPredictedReset: input.nextPredictedReset };
  const next = input.nextPredictedReset;
  if (!input.hasCredential) return { ...status, state: "UNCONFIGURED" };
  if (input.tokenExpired) return { ...status, state: "APP_TOKEN_EXPIRED" };
  if (next !== null && !isZeroTime(next) && nowMs >= next.ms - WIPE_WINDOW_MS) return { ...status, state: "WIPE_IMMINENT" };
  return { ...status, state: "HEALTHY" };
}

export const DAY_MS = 24 * 3600 * 1000;
export const HOUR_MS = 3600 * 1000;

/**
 * NextPollInterval, decision 7's cadence: once a day, hourly from 24 h before a predicted reset on (and after it has
 * passed, until a poll brings a new prediction). It only decides how often the prediction is refreshed, never
 * WIPE_IMMINENT itself: `compute` compares the clock independently, so a missed poll cannot shrink the warning window.
 */
export function nextPollInterval(nowMs: number, nextPredictedReset: GoTime | null): number {
  if (nextPredictedReset === null || isZeroTime(nextPredictedReset)) return DAY_MS;
  return nowMs >= nextPredictedReset.ms - WIPE_WINDOW_MS ? HOUR_MS : DAY_MS;
}
