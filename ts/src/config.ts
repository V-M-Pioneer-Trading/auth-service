/**
 * @file Environment configuration, with the same variables, defaults and refusals as the Go service
 * (src/app-runner.go, src/api/auth.go, src/api/introspect.go, src/api/m2m.go, src/db/db.go,
 * src/spacetraders/client.go). No new variable. Read the Go with `git show` at the cutover's parent if this file
 * says "like Go".
 *
 * An error thrown from here ends the process with status 1 before a port is bound (server.ts), like `log.Fatal`.
 * No message echoes a secret, a key or a URL's contents: they name the variable.
 *
 * The order of the reads is Go's, so that when two things are wrong the same one is reported:
 * the Clerk key text, the shared secret, the introspection secret, the M2M table (with CLERK_API_BASE_URL and the
 * dev key file), then the Clerk key is parsed, then the dev key.
 */
import { readFileSync } from "node:fs";
import type { KeyObject } from "node:crypto";

import { getEnv, goTrimSpace } from "./goText";
import { parseClerkBaseUrl } from "./goUrl";
import { parseRsaPrivateKey, parseRsaPublicKey, samePublicKey } from "./keys";
import type { Logger } from "./log";

export type Env = Record<string, string | undefined>;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/** The fixed table of machine callers (m2mCallerScopes in m2m.go): a pull request against this is where a scope change is reviewed. */
export const M2M_CALLERS = [
  { name: "automation-service", scopes: "fleet:control", envSuffix: "AUTOMATION_SERVICE" },
  { name: "ai-service", scopes: "events:write planner:advise", envSuffix: "AI_SERVICE" },
] as const;

export interface M2MCallerConfig {
  readonly name: string;
  /** M2M_CALLER_SECRET_<caller>. Empty disables the caller. */
  readonly secret: string;
  /** M2M_MACHINE_KEY_<caller>, the production mint source. */
  readonly machineKey: string;
}

export interface M2MConfig {
  readonly callers: readonly M2MCallerConfig[];
  /** DEV_M2M_SIGNING_KEY_FILE, parsed; every token is signed with it locally instead of asking Clerk. */
  readonly devSigningKey: KeyObject | undefined;
  /** CLERK_ISSUER: a dev token carries it as `iss`. */
  readonly issuer: string;
  /** CLERK_API_BASE_URL's mint endpoint, or "" when unset (the code then uses api.clerk.com). */
  readonly clerkTokensUrl: string;
}

export interface Config {
  readonly port: number;
  /** SQLITE_DB_PATH. */
  readonly sqlitePath: string;
  /** ST_GATEWAY_URL + "/proxy", with Go's trailing slash left as it is. */
  readonly gatewayProxyUrl: string;
  readonly corsAllowedOrigin: string;
  /** CLERK_JWT_KEY or CLERK_JWT_KEY_FILE, parsed. */
  readonly clerkJwtKey: KeyObject;
  /** CLERK_ISSUER; empty means "do not check". */
  readonly clerkIssuer: string;
  /** AUTH_SERVICE_SHARED_SECRET: st-gateway's alone. */
  readonly sharedSecret: string;
  /** AUTH_INTROSPECTION_SECRET; empty means the route rejects every caller. */
  readonly introspectionSecret: string;
  readonly m2m: M2MConfig;
}

export interface ConfigIo {
  readonly readFile: (path: string) => Buffer;
  readonly log: Logger;
}

export const DEFAULT_PORT = "80";
export const DEFAULT_SQLITE_PATH = "./data/auth.db";
export const DEFAULT_GATEWAY_URL = "http://localhost:3002";
export const DEFAULT_CORS_ORIGIN = "http://localhost:3000";

/** Go's `":" + port` fails to listen on anything that is not a TCP port; Node would treat a word as a pipe name. */
export function parsePort(raw: string): number {
  if (!/^[0-9]+$/.test(raw) || Number(raw) > 65535) {
    throw new ConfigError(`PORT must be a TCP port number, got "${raw}"`);
  }
  return Number(raw);
}

/** Why a file could not be read, without its contents. */
function readProblem(err: unknown): string {
  const code = (err as NodeJS.ErrnoException).code;
  return typeof code === "string" ? code : "unreadable";
}

/**
 * RequireClerkJWTKey: inline CLERK_JWT_KEY (production, from SSM through the bootstrap script) wins over
 * CLERK_JWT_KEY_FILE (compose's mounted dev key). Neither has a default: a service that can start without a trust
 * anchor is one that can be deployed with authentication silently off.
 */
function requireClerkJwtKeyText(env: Env, io: ConfigIo): string {
  const inline = env.CLERK_JWT_KEY;
  if (inline !== undefined && inline !== "") return inline.replaceAll("\\n", "\n");
  const path = env.CLERK_JWT_KEY_FILE;
  if (path !== undefined && path !== "") {
    let text: string;
    try {
      text = io.readFile(path).toString("utf8");
    } catch (err) {
      throw new ConfigError(`CLERK_JWT_KEY_FILE (${path}) cannot be read: ${readProblem(err)}`);
    }
    if (goTrimSpace(text).length === 0) throw new ConfigError(`CLERK_JWT_KEY_FILE (${path}) is empty`);
    return text;
  }
  throw new ConfigError("CLERK_JWT_KEY or CLERK_JWT_KEY_FILE must be set");
}

/**
 * ReadIntrospectionSecret. Unset is legal (the route is mounted and rejects every caller): production gets the
 * variable by a manual apply, and a service that refused to boot without it would take the vault down with it. Equal
 * to the vault's secret is not: the vault secret is st-gateway's alone, and every service holds this one.
 */
function readIntrospectionSecret(env: Env, sharedSecret: string): string {
  const secret = env.AUTH_INTROSPECTION_SECRET ?? "";
  if (secret !== "" && secret === sharedSecret) {
    throw new ConfigError(
      "AUTH_INTROSPECTION_SECRET must not be the same value as AUTH_SERVICE_SHARED_SECRET: " +
        "the vault secret is st-gateway's alone, and the introspection secret is held by every service",
    );
  }
  return secret;
}

interface RawM2M {
  readonly callers: readonly M2MCallerConfig[];
  readonly devSigningKeyPem: string;
}

/**
 * validateM2MConfig, the fail-closed half of decision 22. Every error names variables, never values.
 *
 *  - One trust anchor per process: a machine key next to the dev key.
 *  - An enabled caller with nothing to mint with.
 *  - A caller secret equal to the vault secret, the introspection secret (every service holds it, so every service
 *    could mint) or another caller's.
 *  - A caller secret with surrounding whitespace, which no request could ever present.
 */
export function validateM2MConfig(callers: readonly M2MCallerConfig[], devKeySet: boolean, sharedSecret: string, introspectionSecret: string): void {
  const seen = new Map<string, string>();
  const machineKeys = new Map<string, string>();
  for (const c of callers) {
    if (!M2M_CALLERS.some((known) => known.name === c.name)) {
      throw new ConfigError(`m2m caller "${c.name}" is not in the scope table`);
    }
    if (c.machineKey !== "" && devKeySet) {
      throw new ConfigError(
        "DEV_M2M_SIGNING_KEY_FILE and a M2M_MACHINE_KEY_* variable are both set: one process mints with exactly one trust anchor",
      );
    }
    // One Machine per caller is the point of decision 22: with a shared key both callers' tokens carry the same `sub`.
    if (c.machineKey !== "") {
      const other = machineKeys.get(c.machineKey);
      if (other !== undefined) {
        throw new ConfigError(`m2m callers ${other} and ${c.name} are configured with the same M2M_MACHINE_KEY_*: one Clerk Machine per caller`);
      }
      machineKeys.set(c.machineKey, c.name);
    }
    // Go trims a header value's surrounding whitespace before the handler sees it, so such a secret could never match.
    if (goTrimSpace(c.secret) !== c.secret) {
      throw new ConfigError(`the m2m caller secret for ${c.name} has leading or trailing whitespace, so no request could ever present it`);
    }
    if (c.secret === "") continue;
    if (c.machineKey === "" && !devKeySet) {
      throw new ConfigError(`m2m caller ${c.name} has a caller secret but no machine key and no DEV_M2M_SIGNING_KEY_FILE to mint with`);
    }
    if (c.secret === sharedSecret) {
      throw new ConfigError(`the m2m caller secret for ${c.name} must not be the same value as AUTH_SERVICE_SHARED_SECRET`);
    }
    if (introspectionSecret !== "" && c.secret === introspectionSecret) {
      throw new ConfigError(
        `the m2m caller secret for ${c.name} must not be the same value as AUTH_INTROSPECTION_SECRET: every service holds that one, so every service could mint`,
      );
    }
    const other = seen.get(c.secret);
    if (other !== undefined) {
      throw new ConfigError(`the m2m caller secrets for ${other} and ${c.name} must differ: either could mint as the other`);
    }
    seen.set(c.secret, c.name);
  }
}

/** clerkURLFromEnv: the mint endpoint for a valid CLERK_API_BASE_URL, "" for unset. The error never repeats the value. */
export function clerkTokensUrlFromEnv(base: string): { url: string; scheme: string; host: string } | undefined {
  if (base === "") return undefined;
  const parsed = parseClerkBaseUrl(base);
  if (parsed === null) {
    throw new ConfigError("CLERK_API_BASE_URL must be an http or https URL with a host and no credentials, query or fragment");
  }
  return { url: base.replace(/\/+$/, "") + "/v1/m2m_tokens", scheme: parsed.scheme, host: parsed.host };
}

/** ReadM2MConfig: the per-caller environment, DEV_M2M_SIGNING_KEY_FILE and CLERK_API_BASE_URL, then validation. */
function readM2MConfig(env: Env, sharedSecret: string, introspectionSecret: string, io: ConfigIo): RawM2M & { clerkTokensUrl: string } {
  const callers = M2M_CALLERS.map((c) => ({
    name: c.name,
    secret: env[`M2M_CALLER_SECRET_${c.envSuffix}`] ?? "",
    machineKey: env[`M2M_MACHINE_KEY_${c.envSuffix}`] ?? "",
  }));
  let devSigningKeyPem = "";
  const devPath = env.DEV_M2M_SIGNING_KEY_FILE ?? "";
  if (devPath !== "") {
    let pem: string;
    try {
      pem = io.readFile(devPath).toString("utf8");
    } catch (err) {
      throw new ConfigError(`DEV_M2M_SIGNING_KEY_FILE: cannot read ${devPath}: ${readProblem(err)}`);
    }
    if (goTrimSpace(pem).length === 0) throw new ConfigError(`DEV_M2M_SIGNING_KEY_FILE (${devPath}) is empty`);
    devSigningKeyPem = pem;
  }
  const clerk = clerkTokensUrlFromEnv(env.CLERK_API_BASE_URL ?? "");
  if (clerk !== undefined && devSigningKeyPem === "") {
    // Clerk mode only (the dev key mints locally). Scheme and host only: never a path, and the validation already refused credentials.
    io.log(`CLERK_API_BASE_URL is set: minting via ${clerk.scheme}://${clerk.host} instead of api.clerk.com`);
  }
  validateM2MConfig(callers, devSigningKeyPem !== "", sharedSecret, introspectionSecret);
  return { callers, devSigningKeyPem, clerkTokensUrl: clerk?.url ?? "" };
}

/** logM2MCallers: which callers can mint, and from what, by name only. */
function logM2MCallers(callers: readonly M2MCallerConfig[], devKeySet: boolean, log: Logger): void {
  const source = devKeySet ? "the local dev key (DEV_M2M_SIGNING_KEY_FILE)" : "Clerk";
  let enabled = 0;
  for (const c of callers) {
    if (c.secret !== "") {
      enabled++;
      log(`POST /auth/v1/m2m-token: ${c.name} mints via ${source}`);
    }
  }
  if (enabled === 0) log("no M2M_CALLER_SECRET_* is set: POST /auth/v1/m2m-token will reject every caller");
}

const defaultIo = (log: Logger): ConfigIo => ({ readFile: (path) => readFileSync(path), log });

export function loadConfig(env: Env, log: Logger, io: ConfigIo = defaultIo(log)): Config {
  const clerkKeyText = requireClerkJwtKeyText(env, io);
  const sharedSecret = env.AUTH_SERVICE_SHARED_SECRET ?? "";
  if (sharedSecret === "") throw new ConfigError("AUTH_SERVICE_SHARED_SECRET must be set");
  // Deliberately not required: an unset AUTH_INTROSPECTION_SECRET is a running service with a route that rejects everyone.
  const introspectionSecret = readIntrospectionSecret(env, sharedSecret);
  if (introspectionSecret === "") {
    io.log("AUTH_INTROSPECTION_SECRET is not set: POST /auth/v1/introspect will reject every caller");
  }
  // A mis-set mint table IS fatal; unset caller secrets are not (they disable the caller).
  const clerkIssuer = env.CLERK_ISSUER ?? "";
  const m2m = readM2MConfig(env, sharedSecret, introspectionSecret, io);
  logM2MCallers(m2m.callers, m2m.devSigningKeyPem !== "", io.log);

  // SetUpRouter: the verifier's key, then (newM2MHandler) the dev signing key.
  const clerkJwtKey = parseRsaPublicKey(clerkKeyText);
  if (clerkJwtKey === null) throw new ConfigError("CLERK_JWT_KEY (or CLERK_JWT_KEY_FILE) is not a PEM-encoded RSA public key");
  let devSigningKey: KeyObject | undefined;
  if (m2m.devSigningKeyPem !== "") {
    devSigningKey = parseRsaPrivateKey(m2m.devSigningKeyPem) ?? undefined;
    if (devSigningKey === undefined) throw new ConfigError("DEV_M2M_SIGNING_KEY_FILE is not an RSA private key");
    // Not fatal: pointing CLERK_JWT_KEY at a real Clerk dev instance to drive the UI is a supported local setup.
    if (!samePublicKey(devSigningKey, clerkJwtKey)) {
      io.log("DEV_M2M_SIGNING_KEY_FILE does not match the verification key: machine tokens minted here will not introspect as active");
    }
  }

  return {
    port: parsePort(getEnv(env, "PORT", DEFAULT_PORT)),
    sqlitePath: getEnv(env, "SQLITE_DB_PATH", DEFAULT_SQLITE_PATH),
    gatewayProxyUrl: getEnv(env, "ST_GATEWAY_URL", DEFAULT_GATEWAY_URL) + "/proxy",
    corsAllowedOrigin: getEnv(env, "CORS_ALLOWED_ORIGIN", DEFAULT_CORS_ORIGIN),
    clerkJwtKey,
    clerkIssuer,
    sharedSecret,
    introspectionSecret,
    m2m: { callers: m2m.callers, devSigningKey, issuer: clerkIssuer, clerkTokensUrl: m2m.clerkTokensUrl },
  };
}
