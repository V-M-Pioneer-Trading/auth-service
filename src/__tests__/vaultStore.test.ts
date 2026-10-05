/**
 * The vault's writes to the one row and the history, through node:sqlite and the unchanged schema: what each write
 * touches, how dates are stored (Go's formatTime), and that a file the Go image wrote takes the writes and reads back.
 */
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { formatNow, formatTime, getCredential, NoCredentialConfigured, sqliteVaultStore } from "../db/credential";
import { openDatabase, openInMemory } from "../db/database";
import { credential, time } from "../testSupport/createTestApp";

const NOW = Date.parse("2026-10-04T12:34:56.789Z");
const rowOf = (db: DatabaseSync): Record<string, unknown> | undefined => db.prepare("SELECT * FROM credential").get();
const historyOf = (db: DatabaseSync): unknown[] => db.prepare("SELECT occurred_at, event, detail FROM registration_history ORDER BY id").all();

describe("formatTime and formatNow", () => {
  it("write dates as Go's Time.Format(RFC3339): the offset kept, no fraction, \"\" for zero", () => {
    expect(formatTime(null)).toBe("");
    expect(formatTime(time("0001-01-01T00:00:00Z"))).toBe("");
    expect(formatTime(time("2026-09-28T14:00:00.987+02:00"))).toBe("2026-09-28T14:00:00+02:00");
    expect(formatNow(NOW)).toBe("2026-10-04T12:34:56Z");
  });
});

describe("the writes", () => {
  it("upsert inserts the whole row, then replaces it wholesale and clears the flag", () => {
    const db = openInMemory();
    const store = sqliteVaultStore(db);
    store.upsert(credential({ resetDate: time("2026-09-28T14:00:00+02:00"), nextPredictedReset: null, tokenExpired: true }), NOW);
    expect(rowOf(db)).toEqual({
      id: 1,
      account_token: "account-token-sentinel",
      agent_token: "agent-token-sentinel",
      agent_symbol: "AGENT_ONE",
      faction: "COSMIC",
      email: "",
      reset_date: "2026-09-28T14:00:00+02:00",
      next_predicted_reset: "",
      token_expired: 0,
      updated_at: "2026-10-04T12:34:56Z",
    });
    store.setTokenExpired(true, NOW);
    store.upsert(credential({ accountToken: "a2", agentToken: "t2", agentSymbol: "S2", faction: "F2", email: "e2" }), NOW + 1000);
    expect(rowOf(db)).toMatchObject({ account_token: "a2", agent_token: "t2", agent_symbol: "S2", faction: "F2", email: "e2", reset_date: "", token_expired: 0, updated_at: "2026-10-04T12:34:57Z" });
    expect(db.prepare("SELECT COUNT(*) AS n FROM credential").get()).toEqual({ n: 1 });
  });

  it("updateAgentToken changes the token and the flag only, and refuses when nothing is stored", () => {
    const db = openInMemory();
    const store = sqliteVaultStore(db);
    expect(() => { store.updateAgentToken("x", NOW); }).toThrow(NoCredentialConfigured);
    expect(rowOf(db)).toBeUndefined();
    store.upsert(credential({ resetDate: time("2026-09-01T00:00:00Z") }), NOW);
    store.setTokenExpired(true, NOW);
    const before = rowOf(db);
    store.updateAgentToken("  restored\t", NOW + 5000);
    expect(rowOf(db)).toEqual({ ...before, agent_token: "  restored\t", token_expired: 0, updated_at: "2026-10-04T12:35:01Z" });
  });

  it("updateResetInfo writes both dates, null as \"\", and nothing else", () => {
    const db = openInMemory();
    const store = sqliteVaultStore(db);
    store.upsert(credential({ resetDate: time("2026-09-01T00:00:00Z"), nextPredictedReset: time("2099-01-01T00:00:00Z") }), NOW);
    store.setTokenExpired(true, NOW);
    store.updateResetInfo(time("2026-09-15T00:00:00Z"), null, NOW);
    expect(rowOf(db)).toMatchObject({ reset_date: "2026-09-15T00:00:00Z", next_predicted_reset: "", token_expired: 1, agent_token: "agent-token-sentinel" });
  });

  it("setTokenExpired sets and clears the flag; appendHistory appends", () => {
    const db = openInMemory();
    const store = sqliteVaultStore(db);
    store.upsert(credential(), NOW);
    store.setTokenExpired(true, NOW);
    expect(getCredential(db)?.tokenExpired).toBe(true);
    store.setTokenExpired(false, NOW);
    expect(getCredential(db)?.tokenExpired).toBe(false);
    store.appendHistory(NOW, "registered", "manual registration via POST /register");
    store.appendHistory(NOW, "token_restored", "");
    expect(historyOf(db)).toEqual([
      { occurred_at: "2026-10-04T12:34:56Z", event: "registered", detail: "manual registration via POST /register" },
      { occurred_at: "2026-10-04T12:34:56Z", event: "token_restored", detail: "" },
    ]);
  });
});

describe("a database the Go image wrote (fixtures/go-written.db)", () => {
  const dirs: string[] = [];
  afterAll(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  it("takes every write, keeps what it does not touch byte for byte, and keeps its history", () => {
    const dir = mkdtempSync(join(tmpdir(), "auth-vault-store-"));
    dirs.push(dir);
    const path = join(dir, "auth.db");
    copyFileSync(join(__dirname, "fixtures", "go-written.db"), path);
    const db = openDatabase(path, () => undefined);
    const store = sqliteVaultStore(db);
    const before = rowOf(db);
    store.updateAgentToken("restored-by-ts", NOW);
    expect(rowOf(db)).toEqual({ ...before, agent_token: "restored-by-ts", token_expired: 0, updated_at: "2026-10-04T12:34:56Z" });
    // Re-registration writes the row back from what it read: the dates Go wrote come back out identical.
    const read = getCredential(db);
    if (read === undefined) throw new Error("no row");
    store.upsert({ ...read, agentToken: "reregistered-by-ts" }, NOW);
    expect(rowOf(db)).toEqual({ ...before, agent_token: "reregistered-by-ts", token_expired: 0, updated_at: "2026-10-04T12:34:56Z" });
    store.appendHistory(NOW, "registered", "automatic re-registration after observed reset");
    expect(historyOf(db).map((r) => (r as { event: string }).event)).toEqual(["registered", "token_restored", "registered"]);
    db.close();

    const reopened = new DatabaseSync(path, { readOnly: true });
    expect(getCredential(reopened)).toMatchObject({ agentToken: "reregistered-by-ts", agentSymbol: "GO_WRITTEN", email: "go@example.test", tokenExpired: false });
    reopened.close();
  });
});
