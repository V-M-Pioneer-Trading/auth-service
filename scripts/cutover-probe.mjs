#!/usr/bin/env node
// Production probe for the Go -> TypeScript cutover of auth-service
// (auth-service#17, meta#103, auth-design.md decision 23, "Cutover is probe-gated"). Built on agent-service's
// scripts/cutover-probe.mjs, which ran the same procedure once (agent-service#51).
//
// Run it from any machine with Node 18+ (Git Bash or PowerShell 7 on Windows is fine), against the public domain,
// AFTER the PR tip's image has been deployed by sha and BEFORE the PR is merged:
//
//   OPERATOR_TOKEN=<signed-in Clerk session token> node scripts/cutover-probe.mjs --strict
//   node scripts/cutover-probe.mjs --dry-run        # lists the checks and what is configured, calls nothing
//
// Environment (the only inputs; no flag takes a secret):
//   BASE_URL              default https://spacetraders.radomskyi.com
//   OPERATOR_TOKEN        a signed-in operator's session token (carries fleet:control). Required (except --dry-run).
//                         It is sent to the CALLER services' routes (agent, fleet, automation, navigation), never to
//                         auth-service's own operator routes: that session may well carry agent:reset.
//   NO_RESET_TOKEN        optional: a signed-in session token that does NOT carry agent:reset (a second Clerk user, or a
//                         session minted without that scope). It is the only valid session ever sent to
//                         POST /api/auth/v1/register and /agent-token, and the probe decodes its `scope` claim first
//                         and refuses to send it if agent:reset is there. Without it the 403 case is SKIPPED.
//   EXPECT_AGENT_SYMBOL   optional: the agent symbol GET /api/auth/v1/status showed BEFORE the cutover deploy (the deploy
//                         script prints it). The check that the SQLite state survived: the same symbol after.
//   SINCE                 ISO time. The automation check looks only at events at or after it. Set it to when
//                         automation-service was RESTARTED after the rc deploy (cutover-deploy-rc.ps1 prints it), so the
//                         event it requires comes from a token auth-service minted after the cutover, not from a 24 h token
//                         Go minted before it. Default: 20 minutes ago.
//
// Flags: --dry-run, --strict, --allow-skip=NAME[,NAME], --help. NAME is one of NO_RESET_TOKEN, EXPECT_AGENT_SYMBOL.
// Exit status: 0 every check passed (or was skipped without --strict), 1 a check failed, 2 bad usage, 3 the probe crashed.
// The automation cycle check is a HARD gate (it cannot be skipped): see "the mint path" below.
//
// Run it with --strict and name every skip you accept: a skipped check then counts as a failure unless you allowed it.
//
// IMAGE IDENTITY. Nothing here can tell the Go image from the TypeScript one: the contract suite pins both to the same
// behaviour, CloudFront routes only /api/<service>/..., and the TypeScript service deliberately sends no header of its
// own (no X-Powered-By, no ETag) and serves no Swagger page. So a run against the Go image is green on every public
// check. The mandatory gate is on the host: `docker inspect auth-service` prints the image tag sha-<tip of the cutover
// PR> (the PR's deploy script prints it). The probe prints that item last.
//
// WHAT IS NEVER DONE, and what is never printed:
//   * no bearer, no token, no token fragment and no body is ever printed. Output is status codes, content types, JSON
//     member NAMES, array lengths, event type names and timestamps, plus the two public values of GET
//     /api/auth/v1/status (the state and the agent symbol). Every line passes through redact(), which also removes the
//     configured tokens (and their JWT segments) should one ever reach a message by accident. Nothing is written to a file.
//   * GET /auth/v1/token, POST /auth/v1/m2m-token and POST /auth/v1/introspect are never called: they are not public
//     (CloudFront does not route them), they carry the game credential or a machine token, and call() refuses them.
//   * POST /api/auth/v1/register and /api/auth/v1/agent-token reset the game account when a session with agent:reset
//     reaches them. They are called ONLY with no header, a garbage bearer, a forged alg=none JWT, a Basic header, and the
//     NO_RESET_TOKEN whose scope claim was read first. call() refuses any other token for those two paths. A 2xx there
//     fails the run and says to look at the production vault at once.
//   * the write path of the callers is probed with an EMPTY JSON body only: with a session that holds fleet:control the
//     handler answers 400 (validation runs after auth and before any gateway call or SQL), so a 400 proves the token went
//     through introspection with its scope intact while nothing could move. A 2xx fails the check.
//   * automation-service's state-changing routes (arm, pause, abort, knobs, replan) are never called with a valid token.
//     POST /events gets no header, a garbage bearer, and the operator's session with an empty body (a session without
//     events:write is refused 403 before the handler; with it, the empty body is a 400).
//   * the 503 with auth-service down is covered by the contract suite and is not probed.
//
// THE MINT PATH. automation-service caches its machine token for 24 h and refreshes it at 12 h, so a probe that runs while
// it still holds a token Go minted proves nothing about the TypeScript mint. The procedure restarts automation-service
// after the rc deploy (its cache is empty, its next call mints through POST /auth/v1/m2m-token), and the cycle check
// requires a planner_shadow_assignment at or after SINCE (the restart): each one follows an M2M-authenticated read of
// agent-service, i.e. a token this auth-service minted AND introspected active. The host checklist's hard gate adds the
// mint count and the absence of any 401/403/503 in automation-service's log since the restart.
//
// NOT probed: ai-service (parked, not deployed; its M2M path is automation-service's, which the cycle check and the host
// checklist cover).

import { pathToFileURL } from "node:url";

const DEFAULT_BASE = "https://spacetraders.radomskyi.com";
const TIMEOUT_MS = 20_000;
const GARBAGE = "probe-garbage-not-a-token";
// An unsigned, alg=none token shaped like a JWT: a verifier that trusts the header would let it in.
const FORGED = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJwcm9iZSIsInNjb3BlIjoiYWdlbnQ6cmVzZXQifQ.";
const PROBE_ID = "PROBE-NOT-A-REAL-ID";
const RESET_SCOPE = "agent:reset";
// What a healthy automation cycle leaves in its public event log. The autopilot runs armed in SHADOW mode for the cutover,
// where planner_shadow_assignment is the proof (each one follows an M2M-authenticated read of agent-service).
// agent_credits_snapshot is written only in live mode and is not what this probe waits for.
const CYCLE_EVENT = "planner_shadow_assignment";
// Event types that mean the cycle broke (the *_error types) or an action failed.
const ERROR_TYPES = new Set(["mining_tick_error", "contract_discovery_error", "observation_write_error"]);
const WARN_TYPES = new Set(["mining_task_failed"]);
const STATES = new Set(["UNCONFIGURED", "HEALTHY", "WIPE_IMMINENT", "APP_TOKEN_EXPIRED"]);
const STATUS_MEMBERS = new Set(["state", "agentSymbol", "resetDate", "nextPredictedReset"]);
const ALLOWED_SKIPS = ["NO_RESET_TOKEN", "EXPECT_AGENT_SYMBOL"];

// Paths this script never requests, whoever asks (see "WHAT IS NEVER DONE").
const NEVER_CALLED = /\/auth\/v1\/(token|m2m-token|introspect)(?:[/?#]|$)/;
// The two routes that reset the game account for a session holding agent:reset.
const RESET_ROUTES = /^\/api\/auth\/v1\/(register|agent-token)(?:[?#]|$)/;

// The operator's session is attached ONLY to the caller services' routes. Anything else (auth-service's own routes
// included, whatever the spelling of the path) is refused before a request is built.
const OPERATOR_PATHS = /^\/api\/(agent|fleet|automation|navigation)\//;

/**
 * The guards of "WHAT IS NEVER DONE", for one request, before it is built. Throws when it must not be sent. The path is
 * checked as written AND percent-decoded, so `/api/auth/v1/%72egister` is the register route for every guard.
 */
export function checkRequest(method, path, token, { operator = "", noReset = "", noResetSafe = false } = {}) {
  let decoded;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    throw new Error(`refused: ${path} is not a decodable path`);
  }
  if (/(^|\/)\.\.(\/|\?|#|$)/.test(decoded)) throw new Error(`refused: ${path} has a dot-dot segment`);
  if (NEVER_CALLED.test(path) || NEVER_CALLED.test(decoded)) throw new Error(`refused: ${path} is never called by this script`);
  const reset = RESET_ROUTES.test(path) || RESET_ROUTES.test(decoded);
  if (reset) {
    if (method !== "POST" && method !== "OPTIONS") throw new Error(`refused: ${method} ${path}`);
    if (token !== undefined && token !== GARBAGE && token !== FORGED && !(noReset !== "" && token === noReset && noResetSafe)) {
      throw new Error(`refused: ${path} gets no session token but a verified agent:reset-less NO_RESET_TOKEN`);
    }
  }
  if (operator !== "" && token === operator && !(OPERATOR_PATHS.test(path) && OPERATOR_PATHS.test(decoded))) {
    throw new Error(`refused: OPERATOR_TOKEN is only ever sent to /api/(agent|fleet|automation|navigation)/ routes, not ${path}`);
  }
  if (noReset !== "" && token === noReset && !reset) throw new Error(`refused: NO_RESET_TOKEN is only ever sent to the reset routes, not ${path}`);
}

class Skip extends Error {
  constructor(message, name) {
    super(message);
    this.skipName = name;
  }
}

/** Splits a JWT into its segments if it is shaped like one, else []. */
function segmentsOf(token) {
  return /^[\w-]+\.[\w-]+\.[\w-]*$/.test(token) ? token.split(".").filter((s) => s.length >= 6) : [];
}

/** The payload of a JWT (never printed), or null for an opaque token. */
function payloadOf(token) {
  if (segmentsOf(token).length === 0) return null;
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    return payload !== null && typeof payload === "object" && !Array.isArray(payload) ? payload : null;
  } catch {
    return null;
  }
}

/** Claim NAMES of a JWT's payload (never values), plus whether it has expired. null for an opaque token. */
function claimNames(token) {
  const payload = payloadOf(token);
  if (payload === null) return null;
  const exp = typeof payload.exp === "number" ? payload.exp : null;
  return { names: Object.keys(payload).sort(), expired: exp !== null && exp * 1000 < Date.now() };
}

/** The scopes a token's `scope` claim holds, as auth-service reads it (a string split on space, tab, CR, LF; or an array). null if unreadable. */
function scopesOf(token) {
  const payload = payloadOf(token);
  if (payload === null) return null;
  const claim = payload.scope;
  if (claim === undefined || claim === null) return [];
  if (typeof claim === "string") return claim.split(/[ \t\r\n]+/).filter(Boolean);
  if (Array.isArray(claim)) return claim.filter((s) => typeof s === "string").flatMap((s) => s.split(/[ \t\r\n]+/)).filter(Boolean);
  return null;
}

export async function run(argv, env, write = (line) => process.stdout.write(line + "\n")) {
  const flags = new Set(argv);
  const unknown = argv.filter((a) => !["--dry-run", "--strict", "--help", "-h"].includes(a) && !/^--allow-skip=[A-Z_,]+$/.test(a));
  const secrets = [env.OPERATOR_TOKEN, env.NO_RESET_TOKEN].filter((s) => typeof s === "string" && s !== "").flatMap((t) => [t, ...segmentsOf(t)]);
  const redact = (text) => {
    let out = String(text);
    for (const s of secrets) out = out.split(s).join("[redacted]");
    return out.replace(/\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/g, "Bearer [redacted]");
  };
  const say = (line = "") => write(redact(line));

  if (unknown.length > 0 || flags.has("--help") || flags.has("-h")) {
    say("usage: [OPERATOR_TOKEN=... NO_RESET_TOKEN=... EXPECT_AGENT_SYMBOL=... BASE_URL=... SINCE=...] node scripts/cutover-probe.mjs [--dry-run] [--strict] [--allow-skip=NAME[,NAME]]");
    say(`NAME is one of ${ALLOWED_SKIPS.join(", ")}. See the header of this file for what every variable means and what the probe never does.`);
    return unknown.length > 0 ? 2 : 0;
  }
  const allowed = new Set(argv.filter((a) => a.startsWith("--allow-skip=")).flatMap((a) => a.slice(13).split(",")).filter(Boolean));
  const badAllow = [...allowed].filter((n) => !ALLOWED_SKIPS.includes(n));
  if (badAllow.length > 0) {
    say(`--allow-skip: unknown name ${badAllow.join(", ")} (use ${ALLOWED_SKIPS.join(", ")})`);
    return 2;
  }

  let base;
  try {
    const url = new URL(env.BASE_URL || DEFAULT_BASE);
    url.username = "";
    url.password = "";
    base = url.origin;
  } catch {
    say("BASE_URL is not a URL");
    return 2;
  }
  const sinceMs = env.SINCE ? Date.parse(env.SINCE) : Date.now() - 20 * 60_000;
  if (Number.isNaN(sinceMs)) {
    say("SINCE is not a time (use ISO 8601, e.g. 2026-10-06T12:30:00Z)");
    return 2;
  }
  const operator = env.OPERATOR_TOKEN || "";
  const noReset = env.NO_RESET_TOKEN || "";
  const expectSymbol = env.EXPECT_AGENT_SYMBOL || "";
  const dry = flags.has("--dry-run");
  if (operator === "" && !dry) {
    say("OPERATOR_TOKEN is not set. Export a signed-in operator's session token, or use --dry-run to list the checks.");
    return 2;
  }

  // ---- HTTP -------------------------------------------------------------------------------------

  /** One request. Returns what the checks need; nothing here is printed except through a check's own line. */
  async function call(method, path, { token, rawAuth, body, origin } = {}) {
    // The guards of "WHAT IS NEVER DONE". They run before any request is built, for every caller of call().
    checkRequest(method, path, token, { operator, noReset, noResetSafe: noReset !== "" && noResetIsSafe() });
    const headers = { Accept: "application/json" };
    if (rawAuth !== undefined) headers.Authorization = rawAuth;
    else if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (origin) {
      headers.Origin = origin;
      headers["Access-Control-Request-Method"] = "POST";
      headers["Access-Control-Request-Headers"] = "authorization, content-type";
    }
    const res = await fetch(base + path, { method, headers, body, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) });
    const type = (res.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    const text = await res.text();
    let json;
    if (type === "application/json") {
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
    }
    return { status: res.status, type, text, json, headers: res.headers };
  }

  /** True when NO_RESET_TOKEN's `scope` claim was read and agent:reset is not in it. */
  function noResetIsSafe() {
    const scopes = scopesOf(noReset);
    return scopes !== null && !scopes.includes(RESET_SCOPE);
  }

  // ---- checks -----------------------------------------------------------------------------------

  const checks = [];
  const check = (group, name, fn, { needs = [] } = {}) => checks.push({ group, name, fn, needs });
  const fail = (msg) => {
    throw new Error(msg);
  };
  const expectStatus = (res, want, extra = "") => {
    const wants = Array.isArray(want) ? want : [want];
    if (!wants.includes(res.status)) fail(`status ${res.status}, wanted ${wants.join(" or ")}${extra}`);
  };
  /** CloudFront answers 200 text/html (the dashboard) for any path its origins 404: JSON must be JSON. */
  const expectJson = (res) => {
    if (res.type === "text/html") fail("got text/html: CloudFront's dashboard fallback, the route is not routed or does not exist");
    if (res.type !== "application/json" || res.json === undefined) fail(`content-type ${res.type || "(none)"}, wanted parseable application/json`);
  };
  const shape = (json) => (Array.isArray(json) ? `array(${json.length})` : json !== null && typeof json === "object" ? `members: ${Object.keys(json).sort().join(",")}` : typeof json);
  /** The `{error:{message}}` envelope of a refused session, by member names only. */
  const expectEnvelope = (res) => {
    expectJson(res);
    if (typeof res.json?.error?.message !== "string") fail(`no {error:{message}} envelope, got ${shape(res.json)}`);
  };
  const hint = (res) => (res.status === 503 ? " (503: auth-service could not be asked, or the new image cannot be reached)" : res.status === 401 ? " (401: the token is expired or auth-service rejected it)" : "");

  const needsOperator = ["OPERATOR_TOKEN"];
  const needsNoReset = ["NO_RESET_TOKEN"];

  // [auth-service's public routes]
  check("auth-service, public routes", "GET /api/auth/health, anonymous", async () => {
    const res = await call("GET", "/api/auth/health");
    expectStatus(res, 200);
    expectJson(res);
    if (res.json?.status !== "ok") fail(`wanted {status:"ok"}, got ${shape(res.json)}`);
    return `200 json ${shape(res.json)}`;
  });
  let seenSymbol = "";
  check("auth-service, public routes", "GET /api/auth/v1/status, anonymous: state and agent symbol, never a token", async () => {
    const res = await call("GET", "/api/auth/v1/status");
    expectStatus(res, 200);
    expectJson(res);
    const members = Object.keys(res.json ?? {});
    const extra = members.filter((m) => !STATUS_MEMBERS.has(m));
    if (extra.length > 0) fail(`unexpected member(s) ${extra.join(",")}: the status answer must never carry anything but ${[...STATUS_MEMBERS].join(",")}`);
    if (!STATES.has(res.json.state)) fail(`state is not one of ${[...STATES].join(" ")}`);
    const symbol = res.json.agentSymbol;
    if (symbol !== undefined && (typeof symbol !== "string" || !/^[A-Za-z0-9_-]{1,40}$/.test(symbol))) fail("agentSymbol is not a plain symbol");
    seenSymbol = typeof symbol === "string" ? symbol : "";
    return `200 json members: ${members.sort().join(",")}; state=${res.json.state}; agentSymbol=${seenSymbol || "(none)"} (RECORD THIS: it must be the same before and after the cutover)`;
  });
  check(
    "auth-service, public routes",
    "the agent symbol equals EXPECT_AGENT_SYMBOL (the SQLite state survived the image change)",
    async () => {
      if (seenSymbol === "") fail("status shows no agentSymbol: the credential row is gone or the service is UNCONFIGURED");
      if (seenSymbol !== expectSymbol) fail("status shows a different agent symbol than EXPECT_AGENT_SYMBOL: the /data volume or the schema is not what the Go image left");
      return "same agent symbol as before the deploy";
    },
    { needs: ["EXPECT_AGENT_SYMBOL"] },
  );
  check("auth-service, public routes", "OPTIONS /api/auth/v1/register allows Authorization (CORS preflight, no handler runs)", async () => {
    const res = await call("OPTIONS", "/api/auth/v1/register", { origin: base });
    expectStatus(res, [200, 204]);
    const allowed = (res.headers.get("access-control-allow-headers") || "").toLowerCase();
    if (!allowed.split(/\s*,\s*/).includes("authorization")) fail("Access-Control-Allow-Headers does not list Authorization");
    if (!res.headers.get("access-control-allow-origin")) fail("no Access-Control-Allow-Origin");
    return `${res.status}, Authorization allowed`;
  });

  // [auth-service's operator routes]: refusals only. Nothing here can reset the account.
  for (const route of ["register", "agent-token"]) {
    const path = `/api/auth/v1/${route}`;
    const group = "auth-service, operator routes refuse without agent:reset (refusal shapes only)";
    check(group, `POST ${path}: no header is a 401 with the error envelope`, async () => {
      const res = await call("POST", path, { body: "{}" });
      expectResetRefusal(res, 401);
      return "401 json members: error";
    });
    check(group, `POST ${path}: a garbage bearer is a 401`, async () => {
      const res = await call("POST", path, { token: GARBAGE, body: "{}" });
      expectResetRefusal(res, 401, hint(res));
      return "401 json members: error";
    });
    check(group, `POST ${path}: a forged alg=none JWT is a 401`, async () => {
      const res = await call("POST", path, { token: FORGED, body: "{}" });
      expectResetRefusal(res, 401);
      return "401 json members: error";
    });
    check(group, `POST ${path}: a non-Bearer header is a 401`, async () => {
      const res = await call("POST", path, { rawAuth: `Basic ${Buffer.from("probe:probe").toString("base64")}`, body: "{}" });
      expectResetRefusal(res, 401);
      return "401 json members: error";
    });
    check(
      group,
      `POST ${path}: a valid session WITHOUT agent:reset is a 403 with the error envelope`,
      async () => {
        const scopes = scopesOf(noReset);
        if (scopes === null) fail("NO_RESET_TOKEN is not a readable JWT: its scope cannot be checked, so it is not sent");
        if (scopes.includes(RESET_SCOPE)) fail(`NO_RESET_TOKEN carries ${RESET_SCOPE}: NOT SENT, it would reset the game account. Use a session without that scope`);
        const claims = claimNames(noReset);
        if (claims?.expired) fail("NO_RESET_TOKEN has expired (exp is in the past); sign in again");
        const res = await call("POST", path, { token: noReset, body: "{}" });
        expectResetRefusal(res, 403, res.status === 401 ? " (401: expired or rejected; sign in again)" : "");
        return "403 json members: error";
      },
      { needs: needsNoReset },
    );
  }
  /** A refusal of an operator route: the status, the envelope, and above all never a 2xx (that would be the account reset). */
  function expectResetRefusal(res, want, extra = "") {
    if (res.status >= 200 && res.status < 300) fail(`${res.status}: a reset route ANSWERED SUCCESS to a request that must be refused. Check the production vault (status, agent symbol) before anything else`);
    expectStatus(res, want, extra);
    expectEnvelope(res);
  }

  // [introspection caller: agent-service]
  const agentReads = ["current-agent", "agent", "ships", "contracts"];
  for (const path of agentReads) {
    check("introspection callers: agent-service reads", `GET /api/agent/v1/${path}: no header and a garbage bearer are 401`, async () => {
      const none = await call("GET", `/api/agent/v1/${path}`);
      const bad = await call("GET", `/api/agent/v1/${path}`, { token: GARBAGE });
      expectStatus(none, 401, " (no header)");
      expectStatus(bad, 401, ` (garbage bearer)${bad.status === 503 ? " (503: introspection is failing for a token auth-service should simply call inactive)" : ""}`);
      expectEnvelope(none);
      return "401, 401 json members: error";
    });
    check(
      "introspection callers: agent-service reads",
      `GET /api/agent/v1/${path} with the operator's session is a 200`,
      async () => {
        const res = await call("GET", `/api/agent/v1/${path}`, { token: operator });
        expectStatus(res, 200, hint(res));
        expectJson(res);
        return `200 json ${shape(res.json)}`;
      },
      { needs: needsOperator },
    );
  }
  check("introspection callers: agent-service reads", "GET /api/agent/v1/transactions?limit=1: anonymous 200, garbage bearer 401, operator 200", async () => {
    const anon = await call("GET", "/api/agent/v1/transactions?limit=1");
    const bad = await call("GET", "/api/agent/v1/transactions?limit=1", { token: GARBAGE });
    expectStatus(anon, 200, " (anonymous)");
    expectJson(anon);
    expectStatus(bad, 401, " (garbage bearer: a bad credential is never quietly downgraded to anonymous)");
    if (operator !== "") {
      const op = await call("GET", "/api/agent/v1/transactions?limit=1", { token: operator });
      expectStatus(op, 200, ` (operator)${hint(op)}`);
      return "200, 401, 200";
    }
    return "200, 401 (operator not set)";
  });
  // The scope path: the operator's fleet:control must survive auth-service's answer. Empty body: 400 before any gateway call or SQL.
  check("introspection callers: agent-service reads", "POST /api/agent/v1/ships/purchase with an empty body: no header and garbage are 401", async () => {
    const none = await call("POST", "/api/agent/v1/ships/purchase", { body: "{}" });
    const bad = await call("POST", "/api/agent/v1/ships/purchase", { token: GARBAGE, body: "{}" });
    expectStatus(none, 401, " (no header)");
    expectStatus(bad, 401, " (garbage bearer)");
    return "401, 401";
  });
  check(
    "introspection callers: agent-service reads",
    "POST /api/agent/v1/ships/purchase with an empty body: the operator's session (fleet:control) passes auth and stops at validation",
    async () => {
      const res = await call("POST", "/api/agent/v1/ships/purchase", { token: operator, body: "{}" });
      if (res.status === 403) fail("403: OPERATOR_TOKEN lacks fleet:control, or auth-service's answer lost the scope");
      if (res.status >= 200 && res.status < 300) fail(`${res.status}: an empty body was accepted. Validation did not run. Check the production database for a stray row before anything else`);
      expectStatus(res, 400, hint(res));
      if (res.type === "text/html") fail("got text/html: CloudFront's dashboard fallback");
      return `400 ${res.type} (validation, before any gateway call: the scope reached agent-service intact)`;
    },
    { needs: needsOperator },
  );

  // [introspection caller: fleet-service]
  check("introspection callers: fleet-service", "GET /api/fleet/v1/ships/{id}/cooldown: no header and garbage bearer are 401", async () => {
    const path = `/api/fleet/v1/ships/${PROBE_ID}/cooldown`;
    const none = await call("GET", path);
    const bad = await call("GET", path, { token: GARBAGE });
    expectStatus(none, 401, " (no header)");
    expectStatus(bad, 401, " (garbage bearer)");
    return "401, 401";
  });
  check(
    "introspection callers: fleet-service",
    "GET /api/fleet/v1/ships/{id}/cooldown: the operator's session passes fleet-service's introspection",
    async () => {
      const res = await call("GET", `/api/fleet/v1/ships/${PROBE_ID}/cooldown`, { token: operator });
      if ([401, 403, 503].includes(res.status)) fail(`status ${res.status}: fleet-service refused a valid session`);
      return `${res.status} (any answer but 401/403/503 means the session got through)`;
    },
    { needs: needsOperator },
  );

  // [introspection caller: automation-service]
  check("introspection callers: automation-service", "GET /api/automation/v1/autopilot/status and /events, anonymous", async () => {
    const status = await call("GET", "/api/automation/v1/autopilot/status");
    expectStatus(status, 200);
    expectJson(status);
    const events = await call("GET", "/api/automation/v1/autopilot/events?limit=1");
    expectStatus(events, 200);
    expectJson(events);
    return `200 ${shape(status.json)}; 200 ${shape(events.json)}`;
  });
  // Its public reads ignore a stale token by design, so the introspection path is probed on the gated route with an empty
  // body: auth answers first, and the handler (which would only log an ai_ event for a valid body) is never reached.
  check("introspection callers: automation-service", "POST /api/automation/v1/events with an empty body: no header and garbage bearer are 401", async () => {
    const none = await call("POST", "/api/automation/v1/events", { body: "{}" });
    const bad = await call("POST", "/api/automation/v1/events", { token: GARBAGE, body: "{}" });
    expectStatus(none, 401, " (no header)");
    expectStatus(bad, 401, " (garbage bearer)");
    return "401, 401";
  });
  check(
    "introspection callers: automation-service",
    "POST /api/automation/v1/events with an empty body: the operator's session is introspected (403 without events:write, 400 with it, never 401/503)",
    async () => {
      const res = await call("POST", "/api/automation/v1/events", { token: operator, body: "{}" });
      if (res.status >= 200 && res.status < 300) fail(`${res.status}: an empty body was accepted by the event log`);
      expectStatus(res, [400, 403], hint(res));
      return `${res.status} (the token was introspected active; the handler did not run)`;
    },
    { needs: needsOperator },
  );

  // [introspection caller: navigation-service]
  const wp = "/api/navigation/v1/waypoints/X1-PROBE-A1";
  check("introspection callers: navigation-service", "GET a waypoint: no header is a visitor, a garbage bearer is a 401 (auth-service is asked once)", async () => {
    const none = await call("GET", wp);
    const bad = await call("GET", wp, { token: GARBAGE });
    if (none.status >= 500) fail(`no header: status ${none.status}`);
    expectStatus(bad, 401, ` (garbage bearer)${bad.status === 503 ? " (503: navigation-service could not ask auth-service)" : ""}`);
    return `${none.status} (visitor: cache only), 401`;
  });
  check(
    "introspection callers: navigation-service",
    "GET a waypoint with the operator's session: auth-service verifies it (any answer but 401/403/503)",
    async () => {
      const res = await call("GET", wp, { token: operator });
      if ([401, 403, 503].includes(res.status)) fail(`status ${res.status}: navigation-service refused a valid session, or could not ask auth-service`);
      return `${res.status} (a live fetch of an unknown waypoint is an upstream 4xx; the session got through)`;
    },
    { needs: needsOperator },
  );

  // [st-gateway]: its lane deriver never rejects, so no outside caller can see it. What can be seen is that the services
  // that forward the session verbatim (agent, fleet, navigation above) work, and that the gateway is up.
  check("st-gateway", "GET /api/st-gateway/health, anonymous (the lane deriver never rejects: its introspection calls are counted on the host)", async () => {
    const res = await call("GET", "/api/st-gateway/health");
    expectStatus(res, 200);
    expectJson(res);
    return `200 json ${shape(res.json)}`;
  });
  check(
    "st-gateway",
    "the token fetch: a signed-in GET /api/agent/v1/agent is a 200 (without the vault's agent token st-gateway answers 503)",
    async () => {
      const res = await call("GET", "/api/agent/v1/agent", { token: operator });
      expectStatus(res, 200, res.status === 503 ? " (503: st-gateway could not get the agent token from auth-service GET /auth/v1/token)" : hint(res));
      return "200: GET /auth/v1/token served st-gateway";
    },
    { needs: needsOperator },
  );

  // [neighbours]
  for (const svc of ["agent", "fleet", "automation", "navigation"]) {
    check("neighbours, health", `GET /api/${svc}/health, anonymous`, async () => {
      const res = await call("GET", `/api/${svc}/health`);
      expectStatus(res, 200);
      expectJson(res);
      return `200 json ${shape(res.json)}`;
    });
  }

  // [one healthy automation cycle], from automation-service's public event log. Names and times only. Its M2M token is
  // minted by auth-service (POST /auth/v1/m2m-token), and every read it makes of agent-service is introspected by it.
  check("automation cycle (M2M mint + introspection)", "HARD GATE: automation-service (restarted at SINCE) is armed and logs a planner_shadow_assignment since SINCE: its freshly minted M2M token was introspected active", async () => {
    const status = await call("GET", "/api/automation/v1/autopilot/status");
    expectStatus(status, 200);
    expectJson(status);
    const lifecycle = typeof status.json.status === "string" ? status.json.status : "(no status member)";
    const mode = typeof status.json.mode === "string" ? status.json.mode : "none";
    if (lifecycle !== "armed") fail(`autopilot is ${lifecycle}, not armed, so no cycle runs and the mint path is unproven: arm it in SHADOW mode (the owner's call, with the fleet:control token) before the probe`);
    const res = await call("GET", "/api/automation/v1/autopilot/events?limit=200");
    expectStatus(res, 200);
    expectJson(res);
    const events = Array.isArray(res.json?.events) ? res.json.events : fail("no events array in the answer");
    const recent = events.filter((e) => typeof e?.type === "string" && Date.parse(e.occurredAt) >= sinceMs);
    const count = {};
    for (const e of recent) count[e.type] = (count[e.type] ?? 0) + 1;
    const summary = Object.entries(count).sort().map(([t, n]) => `${t}x${n}`).join(" ") || "(none)";
    const errors = recent.filter((e) => ERROR_TYPES.has(e.type));
    if (errors.length > 0) fail(`error events since SINCE: ${summary}`);
    const proof = recent.filter((e) => e.type === CYCLE_EVENT);
    if (proof.length === 0) {
      fail(`armed (${mode}) but no ${CYCLE_EVENT} since ${new Date(sinceMs).toISOString()} (SINCE must be the automation-service restart time): ${summary}. Wait for a planner cycle, then run again`);
    }
    const warn = recent.filter((e) => WARN_TYPES.has(e.type)).length;
    return `armed (${mode}); events since SINCE: ${summary}${warn > 0 ? `; NOTE ${warn} action failure event(s): read them on the host` : ""}`;
  }, { needs: [] });

  // ---- the owner's checklist: what no outside caller can see -------------------------------------

  const checklist = [
    "On the host (SSM, AWS-RunShellScript; the PR's cutover-hostcheck.ps1 runs items 2-6), the checks no outside caller can make:",
    "  1. MANDATORY GATE, the outside checks cannot prove it: the running image is the one under test:  docker inspect auth-service --format '{{.Config.Image}}'   (must print ghcr.io/v-m-pioneer-trading/auth-service:sha-<tip of the cutover PR>; the TypeScript image also logs 'auth-service listening on :3005' at start and the Go one does not; a Go image anywhere makes every outside check above meaningless)",
    "  2. not restarting, no OOM, the memory cap in force, RSS recorded:  docker inspect auth-service --format 'restarts={{.RestartCount}} oom={{.State.OOMKilled}} mem={{.HostConfig.Memory}}'; docker stats --no-stream auth-service   (the infrastructure PR's --memory must be applied BEFORE the rc deploy)",
    "  3. the auth-service log since the deploy has no failure line (no 'failed', 'upstream error', 'poller tick'); it never holds a secret or a token:  docker logs --since <SINCE> auth-service 2>&1 | grep -ciE 'failed|upstream error|poller tick'",
    "  4. HARD GATE, the mint path: after the rc deploy, `docker restart automation-service` (the deploy script does it and prints RESTARTED_AT = SINCE); then m2m_token_posts > 0 and m2m_mint_failures = 0 in auth-service's log since then, and zero 401/403/503 in automation-service's log since the restart (cutover-hostcheck.ps1 fails on any of them). ai-service: NOT PROBED (parked, not deployed).",
    "  5. st-gateway's token fetch (GET /auth/v1/token): the signed-in GET /api/agent/v1/agent above returning 200 proves it. The lane deriver's introspection calls show as 'POST request: to /auth/v1/introspect' lines in auth-service's log (count them: more than zero).",
    "  6. the SQLite state is preserved: GET /api/auth/v1/status shows the SAME agent symbol before the deploy and after (EXPECT_AGENT_SYMBOL); record the symbol, never a token.",
    "  7. not probed from outside, by design: GET /auth/v1/token, POST /auth/v1/introspect, POST /auth/v1/m2m-token (secret-gated, not routed by CloudFront), and register / agent-token with a valid agent:reset session (they reset the game account). The contract suite covers them on every CI build.",
    "  8. rollback target, if any check is red: the last Go image, imageTag=sha-<40 hex> as written in the PR description (aws ssm send-command, document auth-service-bootstrap-<instance>).",
  ];

  // ---- run --------------------------------------------------------------------------------------

  const configured = (names) =>
    names.every((n) => (n === "OPERATOR_TOKEN" ? operator !== "" : n === "NO_RESET_TOKEN" ? noReset !== "" : n === "EXPECT_AGENT_SYMBOL" ? expectSymbol !== "" : true));
  const unconfigured = (names) => names.filter((n) => !configured([n]));
  say(`cutover probe: ${base}`);
  say(`OPERATOR_TOKEN: ${operator ? "set" : "unset"}; NO_RESET_TOKEN: ${noReset ? "set" : "unset"}; EXPECT_AGENT_SYMBOL: ${expectSymbol ? "set" : "unset"}; SINCE: ${new Date(sinceMs).toISOString()}`);
  say("Image identity: no outside check can tell the Go image from the TypeScript one. The host's `docker inspect` (checklist item 1) is the gate.");

  if (dry) {
    say("--dry-run: nothing is called. The checks:");
    let group = "";
    for (const c of checks) {
      if (c.group !== group) {
        group = c.group;
        say(`\n[${group}]`);
      }
      say(`  ${configured(c.needs) ? "run " : "SKIP"}  ${c.name}${configured(c.needs) ? "" : `   (needs ${unconfigured(c.needs).join(", ")})`}`);
    }
    say("");
    for (const line of checklist) say(line);
    return 0;
  }

  const tally = { pass: 0, fail: 0, skip: 0 };
  const skipped = []; // per skipped check: the names that would allow it
  let group = "";
  for (const c of checks) {
    if (c.group !== group) {
      group = c.group;
      say(`\n[${group}]`);
    }
    if (!configured(c.needs)) {
      tally.skip++;
      skipped.push(unconfigured(c.needs));
      say(`  SKIPPED  ${c.name}   (needs ${unconfigured(c.needs).join(", ")}, not set)`);
      continue;
    }
    try {
      const detail = await c.fn();
      tally.pass++;
      say(`  PASS     ${c.name} -> ${detail}`);
    } catch (err) {
      if (err instanceof Skip) {
        tally.skip++;
        skipped.push([err.skipName]);
        say(`  SKIPPED  ${c.name} -> ${err.message}`);
      } else {
        tally.fail++;
        const why = err instanceof Error ? (err.cause?.code ? `${err.message} (${err.cause.code})` : err.message) : "unknown error";
        say(`  FAIL     ${c.name} -> ${why}`);
      }
    }
  }
  say("");
  for (const line of checklist) say(line);
  say(`\n${tally.pass} passed, ${tally.fail} failed, ${tally.skip} skipped.`);
  if (tally.skip > 0) say("SKIPPED checks proved nothing: read each one above before calling the cutover green.");
  const unallowed = skipped.filter((n) => !n.some((x) => allowed.has(x)));
  const failed = tally.fail > 0 || (flags.has("--strict") && unallowed.length > 0);
  if (flags.has("--strict") && unallowed.length > 0) say(`--strict: ${unallowed.length} skipped check(s) not covered by --allow-skip count as failures.`);
  say(failed ? "RESULT: RED" : "RESULT: GREEN");
  return failed ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run(process.argv.slice(2), process.env).then(
    // exitCode, not process.exit(): exiting with fetch handles still closing crashes Node on Windows.
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`probe crashed: ${err instanceof Error ? err.name : "error"}\n`);
      process.exitCode = 3;
    },
  );
}
