/**
 * @file A stubbed st-gateway for the vault's unit tests: SpaceTraders' root and registration answered from functions
 * the test sets, every call recorded. Tests import this; nothing else does.
 */
import type { GoTime } from "../goTime";
import type { RegisterResult, RootInfo, SpaceTradersClient } from "../spacetraders/client";
import { time } from "./createTestApp";

/** A stubbed st-gateway: answers from queues (a function per call) or a default, and records every call. */
export class FakeUpstream implements SpaceTradersClient {
  root: () => Promise<RootInfo> = () => Promise.resolve(rootOf("2026-09-01", "2099-01-01T00:00:00Z"));
  registration: () => Promise<RegisterResult> = () => Promise.resolve({ agentToken: `agent-token-${String(this.registerCalls.length)}`, agentSymbol: "UPSTREAM", credits: 0n });
  readonly rootCalls: { at: number; signal: AbortSignal | undefined }[] = [];
  readonly registerCalls: { accountToken: string; symbol: string; faction: string; email: string }[] = [];
  getRoot(signal?: AbortSignal): Promise<RootInfo> {
    this.rootCalls.push({ at: Date.now(), signal });
    return this.root();
  }
  register(accountToken: string, symbol: string, faction: string, email: string): Promise<RegisterResult> {
    this.registerCalls.push({ accountToken, symbol, faction, email });
    return this.registration();
  }
}

export function rootOf(resetDate: string | null, next: string | null): RootInfo {
  const t = (s: string | null): GoTime | null => (s === null ? null : s.length === 10 ? time(`${s}T00:00:00Z`) : time(s));
  return { resetDate: t(resetDate), nextReset: t(next), frequency: "weekly" };
}

export function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void } {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

