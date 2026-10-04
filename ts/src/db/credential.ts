/**
 * @file The one row this service exists to hold (decision 6): the account token is at rest here, never in SSM or an
 * environment variable. Only the read is ported in this step; the writes arrive with the routes that make them
 * (register, restore, the poller).
 */
import type { DatabaseSync } from "node:sqlite";

import { parseRfc3339, type GoTime } from "../goTime";

export interface Credential {
  readonly accountToken: string;
  readonly agentToken: string;
  readonly agentSymbol: string;
  readonly faction: string;
  readonly email: string;
  /** null = never observed (or a stored value Go would not parse). */
  readonly resetDate: GoTime | null;
  /** null = unknown. */
  readonly nextPredictedReset: GoTime | null;
  readonly tokenExpired: boolean;
}

/** What the status route reads. The seam tests replace. */
export interface CredentialStore {
  /** The stored row; undefined means no row at all, which is UNCONFIGURED, not an error. */
  get(): Credential | undefined;
}

const SELECT = `SELECT account_token, agent_token, agent_symbol, faction, email,
		reset_date, next_predicted_reset, token_expired FROM credential WHERE id = 1`;

function text(row: Record<string, unknown>, column: string): string {
  const value = row[column];
  if (typeof value !== "string") throw new Error(`column ${column} of the credential row is not text`);
  return value;
}

/** GetCredential. */
export function getCredential(db: DatabaseSync): Credential | undefined {
  const row = db.prepare(SELECT).get();
  if (row === undefined) return undefined;
  const expired = row.token_expired;
  if (typeof expired !== "number" && typeof expired !== "bigint") throw new Error("column token_expired of the credential row is not an integer");
  return {
    accountToken: text(row, "account_token"),
    agentToken: text(row, "agent_token"),
    agentSymbol: text(row, "agent_symbol"),
    faction: text(row, "faction"),
    email: text(row, "email"),
    resetDate: parseRfc3339(text(row, "reset_date")),
    nextPredictedReset: parseRfc3339(text(row, "next_predicted_reset")),
    tokenExpired: expired !== 0 && expired !== 0n,
  };
}

export const sqliteCredentialStore = (db: DatabaseSync): CredentialStore => ({ get: () => getCredential(db) });
