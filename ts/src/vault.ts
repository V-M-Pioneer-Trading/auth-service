/**
 * @file The vault's routes without the HTTP framework, ported from the Go service's src/api/routes.go and auth.go:
 *
 *  - `GET /auth/v1/token`: st-gateway's only way to the agent token (decision 5), behind the shared secret, never
 *    behind Clerk and never under /api/auth at any method (decision 9: no public route for the credential).
 *  - `POST /api/auth/v1/agent-token` (Restore Token) and `POST /api/auth/v1/register` (Reset Agent), behind a Clerk
 *    session carrying `agent:reset`, verified in-process by the very verifier `POST /auth/v1/introspect` answers with
 *    (decision 21: one verification code path; auth-service never calls itself over HTTP).
 *
 * What each answers, byte for byte where the contract pins it, is the contract README's notes 9, 12, 21 to 28. The
 * controllers (controllers/vault.controller.ts, operator.controller.ts) only wire these to routes.
 *
 * No credential is ever written to the log or into an error message from here: the token is answered only in the
 * 200 of the token route, and the request body of the operator routes is never logged.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { DatabaseSync } from "node:sqlite";

import { NoCredentialConfigured, sqliteVaultStore, type Credential, type VaultStore } from "./db/credential";
import { decodeFirst, firstValueComplete, GoJsonError, type Decoded, type Shape } from "./goJson";
import { readBody } from "./http/body";
import { parseQuery } from "./http/goForm";
import { TextAnswer } from "./http/json";
import { firstHeader } from "./introspection";
import type { Verifier } from "./jwt/verify";
import type { Logger } from "./log";
import { Poller } from "./poller";
import { describeError, spaceTradersClient, UpstreamError, type RegisterResult } from "./spacetraders/client";

/** The header st-gateway presents to `GET /auth/v1/token`. */
export const VAULT_SECRET_HEADER = "X-Auth-Service-Secret";
/** The one scope this service enforces: Restore Token and Reset Agent. */
export const SCOPE_AGENT_RESET = "agent:reset";

export const SHARED_SECRET_REQUIRED = "invalid or missing shared secret";
export const BEARER_REQUIRED = "a bearer token is required";
export const INVALID_SESSION = "invalid or expired session";
export const SCOPE_REQUIRED = "this action requires a scope this session does not carry";

/**
 * How much of an operator route's body is read. Go reads the first JSON value without a cap; a body is a few hundred
 * bytes, and this bound only refuses a first value that does not end within it (a deliberate difference, CLAUDE.md).
 */
export const MAX_OPERATOR_BODY = 1 << 20;

export interface VaultDeps {
  /** AUTH_SERVICE_SHARED_SECRET, st-gateway's alone. Empty refuses every caller (config.ts never lets it be empty). */
  readonly sharedSecret: string;
  readonly store: VaultStore;
  readonly poller: Pick<Poller, "pollNow" | "tick" | "register" | "exclusive">;
  /** The service log: failures of best-effort steps, never a credential. */
  readonly log: Logger;
}

/** An answer in the `{"error":{"message":…}}` envelope, always `no-store` (writeAuthError). */
export interface AuthRefusal {
  readonly status: 401 | 403;
  readonly message: string;
}

const sha256 = (bytes: Buffer): Buffer => createHash("sha256").update(bytes).digest();

/**
 * requireSharedSecret, in constant time (Go compared with `!=`; decision 23 accepts the change, the status stays 403).
 * The SHA-256 of each side is compared, so the length is no shortcut either. The first header of the name counts
 * (Go's Header.Get; Node would join repeats), its surrounding spaces and tabs already trimmed by Node's parser as by
 * Go's. An empty configured secret matches nothing.
 */
export function vaultSecretOk(configured: string, presented: string | undefined): boolean {
  if (configured === "") return false;
  return timingSafeEqual(sha256(Buffer.from(configured, "utf8")), sha256(Buffer.from(presented ?? "", "latin1")));
}

/** `r.URL.Query().Get("afterUnauthorized") == "true"`: the first value, errors in the query ignored. */
export function afterUnauthorized(url: string): boolean {
  const q = url.indexOf("?");
  return q >= 0 && parseQuery(url.slice(q + 1)).values.get("afterUnauthorized")?.[0] === "true";
}

/**
 * `GET /auth/v1/token`. A forced poll runs before the answer, and only for a caller who passed the secret; its failure
 * is logged and the stored token answered. 503 when there is no row or its token is empty, in every state
 * (APP_TOKEN_EXPIRED included).
 */
export async function getToken(req: IncomingMessage, deps: VaultDeps): Promise<{ refusal: AuthRefusal } | { agentToken: string }> {
  if (!vaultSecretOk(deps.sharedSecret, firstHeader(req, VAULT_SECRET_HEADER))) return { refusal: { status: 403, message: SHARED_SECRET_REQUIRED } };
  if (afterUnauthorized(req.url ?? "")) {
    try {
      await deps.poller.pollNow();
    } catch (err) {
      deps.log(`forced poll after 401 failed: ${describeError(err)}`);
    }
  }
  let credential: Credential | undefined;
  try {
    credential = deps.store.get();
  } catch (err) {
    throw new TextAnswer(500, `failed to load credential: ${describeError(err)}`);
  }
  if (credential === undefined || credential.agentToken === "") throw new TextAnswer(503, "no agent token configured");
  return { agentToken: credential.agentToken };
}

// ---------------------------------------------------------------------------------------------------------------------
// The Clerk session gate on the operator routes.

/**
 * The bearer token of an `Authorization` value, as clerk-client's `bearerFrom` reads it (the owner's decision on
 * auth-service#15, 2026-10-03): trimmed, split on runs of whitespace, exactly two parts, the scheme `bearer` in any
 * case. `"Bearer"`, `"Bearer a b"`, `"Basic …"` and a bare token are no credential. Node hands the header over as
 * latin1, one char per byte, and JavaScript's `\s` splits it, where Go's `strings.Fields` splits the UTF-8 runes: so
 * a lone byte 0xA0 separates here and not in Go, and a UTF-8 NO-BREAK SPACE, NEXT LINE or other non-ASCII space
 * (C2 A0, C2 85, E2 80 83, ...) separates in Go and not here. ASCII whitespace is the same in both. Accepted by the owner.
 */
export function bearerFrom(header: string | undefined): string | null {
  if (header === undefined) return null;
  const parts = header.trim().split(/\s+/);
  if (parts.length !== 2) return null;
  const [scheme, token] = parts as [string, string];
  if (scheme.toLowerCase() !== "bearer") return null;
  return token.length > 0 ? token : null;
}

/** A scope string split as every introspection client splits it (fixture v6, clerk-client 2.0.1): runs of SP, TAB, CR, LF. */
export const splitScopes = (scope: string): string[] => scope.split(/[ \t\r\n]+/).filter((s) => s.length > 0);

/**
 * verify + requireScope: a well-formed, correctly signed, unexpired Clerk session carrying `scope`. The first
 * `Authorization` header counts (Go's Header.Get; contract README note 11). Why a token failed is never said: it is a
 * probing oracle, and the remedy is the same.
 */
export async function sessionGate(req: IncomingMessage, verifier: Verifier, nowMs: number, scope: string): Promise<AuthRefusal | null> {
  const token = bearerFrom(firstHeader(req, "Authorization"));
  if (token === null) return { status: 401, message: BEARER_REQUIRED };
  const verified = await verifier(token, nowMs);
  if (verified === null) return { status: 401, message: INVALID_SESSION };
  if (!splitScopes(verified.scope).includes(scope)) return { status: 403, message: SCOPE_REQUIRED };
  return null;
}

// ---------------------------------------------------------------------------------------------------------------------
// The operator routes' bodies.

/**
 * `json.NewDecoder(r.Body).Decode(&body)` into `shape`: the first JSON value, what follows never looked at, no content
 * type required. Read only after the session gate. A first value that does not end within MAX_OPERATOR_BODY is refused.
 */
async function decodeBody<S extends Shape>(req: IncomingMessage, shape: S, typeName: string): Promise<Decoded<S>> {
  const { bytes, exceeded } = await readBody(req, MAX_OPERATOR_BODY);
  if (exceeded && !firstValueComplete(bytes)) throw new TextAnswer(400, "invalid request body: http: request body too large");
  try {
    return decodeFirst(bytes, shape, typeName);
  } catch (err) {
    if (err instanceof GoJsonError) throw new TextAnswer(400, `invalid request body: ${err.message}`);
    throw err;
  }
}

const RESTORE_SHAPE = { agentToken: "string" } as const;
const REGISTER_SHAPE = { accountToken: "string", symbol: "string", faction: "string", email: "string" } as const;

/**
 * Restore Token (decision 8): a regenerated agent token for the EXISTING agent, the only recovery from
 * APP_TOKEN_EXPIRED. Only the agent token changes, verbatim; the flag clears; no upstream call.
 */
export async function restoreToken(req: IncomingMessage, deps: VaultDeps, nowMs: number): Promise<{ status: "restored" }> {
  const body = await decodeBody(req, RESTORE_SHAPE, "api.restoreTokenRequest");
  if (body.agentToken === "") throw new TextAnswer(400, "agentToken is required");
  // On the poll queue: a forced poll in flight would otherwise raise the expired flag again after this clears it.
  await deps.poller.exclusive(() => {
    try {
      deps.store.updateAgentToken(body.agentToken, nowMs);
    } catch (err) {
      if (err instanceof NoCredentialConfigured) throw new TextAnswer(409, err.message);
      throw new TextAnswer(500, describeError(err));
    }
    try {
      deps.store.appendHistory(nowMs, "token_restored", "");
    } catch (err) {
      deps.log(`failed to record token_restored: ${describeError(err)}`);
    }
  });
  return { status: "restored" };
}

/**
 * Reset Agent (decision 7): registers with the account token, stores the credential wholesale (the reserved call sign
 * is what later automatic re-registrations reuse; the flag and the dates are cleared), then one best-effort poll so
 * the status has dates at once. The answer's `agentSymbol` is SpaceTraders'. Upstream's 4xx/5xx is passed through with
 * its raw body (writeIfError); anything else that fails upstream is 502.
 */
export async function registerAgent(req: IncomingMessage, deps: VaultDeps, nowMs: () => number): Promise<{ agentSymbol: string; status: "registered" }> {
  const body = await decodeBody(req, REGISTER_SHAPE, "api.registerRequest");
  if (body.accountToken === "" || body.symbol === "" || body.faction === "") throw new TextAnswer(400, "accountToken, symbol and faction are required");

  // Registration and the write, on the poll queue: a re-registration in flight would otherwise write the OLD account
  // back over this one.
  const result = await deps.poller.exclusive(() => registerAndStore(body, deps, nowMs));
  try {
    await deps.poller.tick(false);
  } catch (err) {
    deps.log(`post-registration poll failed: ${describeError(err)}`);
  }
  return { agentSymbol: result.agentSymbol, status: "registered" };
}

async function registerAndStore(body: Decoded<typeof REGISTER_SHAPE>, deps: VaultDeps, nowMs: () => number): Promise<RegisterResult> {
  let result: RegisterResult;
  try {
    result = await deps.poller.register(body.accountToken, body.symbol, body.faction, body.email);
  } catch (err) {
    if (err instanceof UpstreamError) {
      const status = err.status >= 400 && err.status <= 599 ? err.status : 502;
      throw new TextAnswer(status, "", err.answer);
    }
    throw new TextAnswer(502, describeError(err));
  }

  const now = nowMs();
  try {
    deps.store.upsert(
      { accountToken: body.accountToken, agentToken: result.agentToken, agentSymbol: result.agentSymbol, faction: body.faction, email: body.email, resetDate: null, nextPredictedReset: null, tokenExpired: false },
      now,
    );
  } catch (err) {
    throw new TextAnswer(500, `registered but failed to persist credential: ${describeError(err)}`);
  }
  try {
    deps.store.appendHistory(now, "registered", "manual registration via POST /register");
  } catch (err) {
    deps.log(`failed to record registered: ${describeError(err)}`);
  }
  return result;
}

// ---------------------------------------------------------------------------------------------------------------------
// Wiring.

/** The vault of an app built without one (tests of other routes): every caller refused, nothing stored, no poll. */
export const CLOSED_VAULT: VaultDeps = {
  sharedSecret: "",
  store: {
    get: () => undefined,
    upsert: () => undefined,
    updateAgentToken: () => {
      throw new NoCredentialConfigured();
    },
    updateResetInfo: () => undefined,
    setTokenExpired: () => undefined,
    appendHistory: () => undefined,
  },
  poller: {
    pollNow: () => Promise.resolve(),
    tick: () => Promise.resolve(),
    register: () => Promise.reject(new Error("no vault configured")),
    exclusive: (work) => Promise.resolve().then(work),
  },
  log: () => undefined,
};

export interface VaultSettings {
  readonly sharedSecret: string;
  /** `{ST_GATEWAY_URL}/proxy`. */
  readonly gatewayProxyUrl: string;
  readonly log: Logger;
}

/** The production vault over the service's one database: the store, the SpaceTraders client, the poller, started. */
export function startVault(db: DatabaseSync, settings: VaultSettings): { deps: VaultDeps; stop: () => Promise<void> } {
  const store = sqliteVaultStore(db);
  const poller = new Poller({ store, upstream: spaceTradersClient({ baseUrl: settings.gatewayProxyUrl }), log: settings.log });
  poller.start();
  return { deps: { sharedSecret: settings.sharedSecret, store, poller, log: settings.log }, stop: () => poller.stop() };
}
