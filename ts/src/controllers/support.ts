/**
 * @file What controllers share: where the app keeps its dependencies, and the answer writers.
 */
import type { Request } from "express";

import type { CredentialStore } from "../db/credential";
import type { IntrospectionDeps } from "../introspection";
import type { M2MService } from "../m2m/service";

export const CREDENTIALS_LOCAL = "credentials";
export const CLOCK_LOCAL = "clock";
export const INTROSPECTION_LOCAL = "introspection";
export const M2M_LOCAL = "m2m";

export function credentialsOf(req: Request): CredentialStore {
  return req.app.locals[CREDENTIALS_LOCAL] as CredentialStore;
}

export function introspectionOf(req: Request): IntrospectionDeps {
  return req.app.locals[INTROSPECTION_LOCAL] as IntrospectionDeps;
}

export function m2mOf(req: Request): M2MService {
  return req.app.locals[M2M_LOCAL] as M2MService;
}

/** Milliseconds since the epoch; replaced in tests. */
export function nowOf(req: Request): number {
  return (req.app.locals[CLOCK_LOCAL] as () => number)();
}
