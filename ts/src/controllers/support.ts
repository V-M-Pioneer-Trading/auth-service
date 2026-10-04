/**
 * @file What controllers share: where the app keeps its dependencies, and the answer writers.
 */
import type { Request } from "express";

import type { CredentialStore } from "../db/credential";

export const CREDENTIALS_LOCAL = "credentials";
export const CLOCK_LOCAL = "clock";

export function credentialsOf(req: Request): CredentialStore {
  return req.app.locals[CREDENTIALS_LOCAL] as CredentialStore;
}

/** Milliseconds since the epoch; replaced in tests. */
export function nowOf(req: Request): number {
  return (req.app.locals[CLOCK_LOCAL] as () => number)();
}
