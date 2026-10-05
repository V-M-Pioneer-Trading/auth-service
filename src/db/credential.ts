/**
 * @file The one row this service exists to hold (decision 6): the account token is at rest here, never in SSM or an
 * environment variable. Ported from the Go service's src/db/credential.go: the same statements against the same
 * schema, so either image reads and writes what the other wrote.
 *
 * Dates are stored as Go's `formatTime` writes them: `Time.Format(time.RFC3339)` (the offset kept, no fraction), "" for
 * the zero time. `updated_at` and `occurred_at` are the current time in UTC; Go writes its local time, which is UTC in
 * the image. Nothing reads either column.
 */
import type { DatabaseSync } from "node:sqlite";

import { formatRfc3339, isZeroTime, parseRfc3339, type GoTime } from "../goTime";

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

/** UpdateAgentToken's refusal when there is no row: Restore Token only makes sense for an agent registered once. */
export class NoCredentialConfigured extends Error {
  constructor() {
    super("no credential configured to restore a token onto");
    this.name = "NoCredentialConfigured";
  }
}

/** Every read and write the vault makes. The seam tests replace. */
export interface VaultStore extends CredentialStore {
  /** UpsertCredential: the whole row, `token_expired` cleared (a fresh agent token is by definition not expired). */
  upsert(c: Credential, nowMs: number): void;
  /** UpdateAgentToken (Restore Token): only the agent token, the flag cleared. NoCredentialConfigured without a row. */
  updateAgentToken(agentToken: string, nowMs: number): void;
  /** UpdateResetInfo: the latest root's two dates, null written as "". */
  updateResetInfo(resetDate: GoTime | null, nextPredictedReset: GoTime | null, nowMs: number): void;
  /** SetTokenExpired: the flag behind APP_TOKEN_EXPIRED. */
  setTokenExpired(expired: boolean, nowMs: number): void;
  /** AppendHistory: one row of the append-only registration history. */
  appendHistory(nowMs: number, event: string, detail: string): void;
}

/** formatTime: "" for the zero time, else RFC 3339 as Go formats it. */
export const formatTime = (t: GoTime | null): string => (t === null || isZeroTime(t) ? "" : formatRfc3339(t));

/** `time.Now().Format(time.RFC3339)` in UTC: seconds, `Z`. */
export const formatNow = (nowMs: number): string => new Date(Math.floor(nowMs / 1000) * 1000).toISOString().replace(".000Z", "Z");

const UPSERT = `
		INSERT INTO credential (id, account_token, agent_token, agent_symbol, faction, email,
			reset_date, next_predicted_reset, token_expired, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, 0, ?)
		ON CONFLICT(id) DO UPDATE SET
			account_token = excluded.account_token,
			agent_token = excluded.agent_token,
			agent_symbol = excluded.agent_symbol,
			faction = excluded.faction,
			email = excluded.email,
			reset_date = excluded.reset_date,
			next_predicted_reset = excluded.next_predicted_reset,
			token_expired = 0,
			updated_at = excluded.updated_at`;

export function sqliteVaultStore(db: DatabaseSync): VaultStore {
  return {
    get: () => getCredential(db),
    upsert(c, nowMs) {
      db.prepare(UPSERT).run(c.accountToken, c.agentToken, c.agentSymbol, c.faction, c.email, formatTime(c.resetDate), formatTime(c.nextPredictedReset), formatNow(nowMs));
    },
    updateAgentToken(agentToken, nowMs) {
      const result = db.prepare(`UPDATE credential SET agent_token = ?, token_expired = 0, updated_at = ?
		WHERE id = 1`).run(agentToken, formatNow(nowMs));
      if (Number(result.changes) === 0) throw new NoCredentialConfigured();
    },
    updateResetInfo(resetDate, nextPredictedReset, nowMs) {
      db.prepare(`UPDATE credential SET reset_date = ?, next_predicted_reset = ?, updated_at = ?
		WHERE id = 1`).run(formatTime(resetDate), formatTime(nextPredictedReset), formatNow(nowMs));
    },
    setTokenExpired(expired, nowMs) {
      db.prepare(`UPDATE credential SET token_expired = ?, updated_at = ? WHERE id = 1`).run(expired ? 1 : 0, formatNow(nowMs));
    },
    appendHistory(nowMs, event, detail) {
      db.prepare(`INSERT INTO registration_history (occurred_at, event, detail) VALUES (?, ?, ?)`).run(formatNow(nowMs), event, detail);
    },
  };
}
