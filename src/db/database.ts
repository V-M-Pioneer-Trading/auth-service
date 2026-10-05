/**
 * @file SQLite through the built-in `node:sqlite` (Node 24.15 and later: release candidate, no flag). One
 * connection, which is all `DatabaseSync` has, so SQLite never sees concurrent writers (the Go service set
 * `SetMaxOpenConns(1)` for the same reason).
 */
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

import type { Logger } from "../log";
import { SCHEMA } from "./schema";

/** SetUpDatabase: opens (creating the file and its directory if needed) the database at `path` and applies the idempotent schema. */
export function openDatabase(path: string, log: Logger): DatabaseSync {
  const dir = dirname(path);
  if (dir !== ".") mkdirSync(dir, { recursive: true, mode: 0o755 });
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);
  log(`Schema migrations applied to ${path}.`);
  return db;
}

/** OpenInMemory: a fresh :memory: database with the schema applied, for tests. */
export function openInMemory(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec(SCHEMA);
  return db;
}
