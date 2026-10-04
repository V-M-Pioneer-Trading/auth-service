/**
 * SQLite through node:sqlite. The schema does not change in this port, so a rollback to the Go image opens the file the
 * TypeScript service wrote and the other way round: these tests open a file the Go image's own db package wrote
 * (fixtures/SOURCE.txt) and compare DDL with the Go service's schema.sql.
 */
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { getCredential, sqliteCredentialStore } from "../db/credential";
import { openDatabase, openInMemory } from "../db/database";
import { SCHEMA } from "../db/schema";
import { formatRfc3339 } from "../goTime";
import { readStatus } from "../status";

const FIXTURE = join(__dirname, "fixtures", "go-written.db");
const FIXTURE_SHA256 = "9ca9d183c8fb4b74f36c97eb711705360de01da6c82f4fc12a6d2e036e52f806";
/** The Go service's schema, while the Go code is still in the repository (the cutover deletes it, and this comparison with it). */
const GO_SCHEMA = join(__dirname, "..", "..", "..", "src", "db", "schema.sql");

const dirs: string[] = [];
const scratch = (): string => {
  const dir = mkdtempSync(join(tmpdir(), "auth-db-test-"));
  dirs.push(dir);
  return dir;
};
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const quiet = (): void => undefined;

interface MasterRow {
  type: string;
  name: string;
  sql: string;
}
const master = (db: DatabaseSync): MasterRow[] =>
  db.prepare("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").all() as unknown as MasterRow[];

describe("the schema", () => {
  (existsSync(GO_SCHEMA) ? it : it.skip)("is the Go service's schema.sql, statement for statement", () => {
    const go = readFileSync(GO_SCHEMA, "utf8").replace(/\r\n/g, "\n");
    expect(SCHEMA).toBe(go);
  });

  it("creates the two tables, and applying it twice changes nothing (it runs on every start)", () => {
    const db = openInMemory();
    const once = master(db);
    db.exec(SCHEMA);
    expect(master(db)).toEqual(once);
    expect(once.map((r) => r.name)).toEqual(["credential", "registration_history"]);
    db.close();
  });

  it("has the same DDL, as SQLite stored it, as a database the Go image wrote", () => {
    const go = new DatabaseSync(FIXTURE, { readOnly: true });
    const mine = openInMemory();
    expect(master(mine)).toEqual(master(go));
    go.close();
    mine.close();
  });
});

describe("a database written by the Go image", () => {
  it("is the fixture it claims to be", () => {
    expect(createHash("sha256").update(readFileSync(FIXTURE)).digest("hex")).toBe(FIXTURE_SHA256);
    expect(readFileSync(join(__dirname, "fixtures", "SOURCE.txt"), "utf8")).toContain(FIXTURE_SHA256);
  });

  it("opens, is migrated in place (nothing to do) and reads back what Go stored", () => {
    const path = join(scratch(), "auth.db");
    copyFileSync(FIXTURE, path);
    const lines: string[] = [];
    const db = openDatabase(path, (line) => void lines.push(line));
    expect(lines).toEqual([`Schema migrations applied to ${path}.`]);

    const credential = getCredential(db);
    expect(credential).toMatchObject({
      accountToken: "go-written-account-token",
      agentToken: "go-written-agent-token",
      agentSymbol: "GO_WRITTEN",
      faction: "COSMIC",
      email: "go@example.test",
      tokenExpired: true,
    });
    // Go wrote the dates with Time.Format(RFC3339): the offset a date carried survives, in the file and through us.
    expect(credential?.resetDate === null || credential?.resetDate === undefined ? "" : formatRfc3339(credential.resetDate)).toBe("2026-09-28T14:00:00+02:00");
    expect(credential?.nextPredictedReset === null || credential?.nextPredictedReset === undefined ? "" : formatRfc3339(credential.nextPredictedReset)).toBe("2026-10-12T03:04:05Z");

    // Its history is untouched by the migration.
    expect(db.prepare("SELECT event FROM registration_history ORDER BY id").all()).toEqual([{ event: "registered" }, { event: "token_restored" }]);
    db.close();
  });

  it("answers the status route as the Go service would: the expired token outranks everything", () => {
    const path = join(scratch(), "auth.db");
    copyFileSync(FIXTURE, path);
    const db = openDatabase(path, quiet);
    const status = readStatus(sqliteCredentialStore(db), Date.parse("2026-10-11T12:00:00Z"));
    expect(status).toEqual({ state: "APP_TOKEN_EXPIRED", agentSymbol: "GO_WRITTEN", resetDate: "2026-09-28T14:00:00+02:00", nextPredictedReset: "2026-10-12T03:04:05Z" });
    expect(JSON.stringify(status)).not.toContain("token\"");
    db.close();
  });

  it("is only read by this step: opening it leaves the row's bytes as they were", () => {
    const path = join(scratch(), "auth.db");
    copyFileSync(FIXTURE, path);
    const before = new DatabaseSync(path, { readOnly: true });
    const rowBefore = JSON.stringify(before.prepare("SELECT * FROM credential").all());
    before.close();
    openDatabase(path, quiet).close();
    const after = new DatabaseSync(path, { readOnly: true });
    expect(JSON.stringify(after.prepare("SELECT * FROM credential").all())).toBe(rowBefore);
    after.close();
  });
});

describe("opening", () => {
  it("creates the file and its directories", () => {
    const path = join(scratch(), "a", "b", "auth.db");
    openDatabase(path, quiet).close();
    expect(statSync(path).isFile()).toBe(true);
  });

  it("works for a bare file name in the current directory (Go skips MkdirAll for '.')", () => {
    const dir = scratch();
    const before = process.cwd();
    process.chdir(dir);
    try {
      openDatabase("auth.db", quiet).close();
      expect(statSync(join(dir, "auth.db")).isFile()).toBe(true);
    } finally {
      process.chdir(before);
    }
  });

  it("opens one connection, which survives and is reused across reads", () => {
    const db = openInMemory();
    expect(getCredential(db)).toBeUndefined();
    db.prepare("INSERT INTO credential (id, account_token, agent_token, agent_symbol, faction, updated_at) VALUES (1, 'a', 'b', 'S', 'F', 't')").run();
    expect(getCredential(db)).toMatchObject({ agentSymbol: "S", resetDate: null, nextPredictedReset: null, tokenExpired: false, email: "" });
    db.close();
  });

  it("allows only one credential row (id = 1), as the Go DDL does", () => {
    const db = openInMemory();
    db.prepare("INSERT INTO credential (id, account_token, agent_token, agent_symbol, faction, updated_at) VALUES (1, 'a', 'b', 'S', 'F', 't')").run();
    expect(() => db.prepare("INSERT INTO credential (id, account_token, agent_token, agent_symbol, faction, updated_at) VALUES (2, 'a', 'b', 'S', 'F', 't')").run()).toThrow();
    db.close();
  });

  it("reads a date Go would not parse as unset, and reports a row whose columns are not text as an error", () => {
    const db = openInMemory();
    db.prepare("INSERT INTO credential (id, account_token, agent_token, agent_symbol, faction, reset_date, updated_at) VALUES (1, 'a', 'b', 'S', 'F', 'not a date', 't')").run();
    expect(getCredential(db)?.resetDate).toBeNull();
    db.exec("UPDATE credential SET token_expired = 'x'");
    expect(() => getCredential(db)).toThrow(/token_expired/);
    db.close();
  });
});
