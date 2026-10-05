/**
 * @file `createApp` with a fake credential store and a fixed clock. Tests import this; nothing else does.
 */
import type { Express } from "express";

import type { Credential, CredentialStore } from "../db/credential";
import type { IntrospectionDeps } from "../introspection";
import { parseRfc3339, type GoTime } from "../goTime";
import { createApp } from "../server";

export const TEST_ORIGIN = "https://dashboard.contract.example";
export const NOW = Date.parse("2026-10-04T12:00:00Z");

export function time(text: string): GoTime {
  const parsed = parseRfc3339(text);
  if (parsed === null) throw new Error(`not a time: ${text}`);
  return parsed;
}

export function credential(overrides: Partial<Credential> = {}): Credential {
  return {
    accountToken: "account-token-sentinel",
    agentToken: "agent-token-sentinel",
    agentSymbol: "AGENT_ONE",
    faction: "COSMIC",
    email: "",
    resetDate: null,
    nextPredictedReset: null,
    tokenExpired: false,
    ...overrides,
  };
}

export const storeOf = (row: Credential | undefined): CredentialStore => ({ get: () => row });

export function createTestApp(
  row?: Credential,
  extra: { log?: (line: string) => void; store?: CredentialStore; now?: () => number; introspection?: IntrospectionDeps } = {},
): Express {
  return createApp({
    corsAllowedOrigin: TEST_ORIGIN,
    credentials: extra.store ?? storeOf(row),
    now: extra.now ?? (() => NOW),
    ...(extra.log === undefined ? {} : { log: extra.log }),
    ...(extra.introspection === undefined ? {} : { introspection: extra.introspection }),
  });
}
