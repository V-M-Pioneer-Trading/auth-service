/**
 * @file What controllers share: where the app keeps its dependencies, and the answer writers.
 */
import type { Request } from "express";

import type { CredentialStore } from "../db/credential";
import type { IntrospectionDeps } from "../introspection";
import type { VaultDeps } from "../vault";

export const CREDENTIALS_LOCAL = "credentials";
export const CLOCK_LOCAL = "clock";
export const INTROSPECTION_LOCAL = "introspection";

export function credentialsOf(req: Request): CredentialStore {
  return req.app.locals[CREDENTIALS_LOCAL] as CredentialStore;
}

export function introspectionOf(req: Request): IntrospectionDeps {
  return req.app.locals[INTROSPECTION_LOCAL] as IntrospectionDeps;
}

/** Milliseconds since the epoch; replaced in tests. */
export function nowOf(req: Request): number {
  return (req.app.locals[CLOCK_LOCAL] as () => number)();
}

// The vault (step 7c).
export const VAULT_LOCAL = "vault";

export function vaultOf(req: Request): VaultDeps {
  return req.app.locals[VAULT_LOCAL] as VaultDeps;
}
