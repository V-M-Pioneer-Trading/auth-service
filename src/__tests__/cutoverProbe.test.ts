import { execFile } from "node:child_process";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";

// scripts/cutover-probe.mjs against a stub that plays the public domain. It pins what matters about a probe that runs
// against production with real session tokens: it passes against a correct service, it fails when the service
// misbehaves, no token ever reaches its output, and (the one that protects the game account) it never calls the
// secret-gated routes and never sends a session that may carry agent:reset to register or agent-token.

const script = path.join(__dirname, "..", "..", "scripts", "cutover-probe.mjs");
const part = (o: object): string => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload: object): string => `${part({ alg: "RS256" })}.${part(payload)}.signature-part-EEEEEEEEEEEE`;
// The operator holds agent:reset as well as fleet:control, as Max's own session does: it must never reach the reset routes.
const OPERATOR = jwt({ sub: "user_VALUE_MUST_NOT_PRINT", scope: "fleet:control agent:reset", iat: 1, exp: 4102444800 });
const NO_RESET = jwt({ sub: "user_OTHER_MUST_NOT_PRINT", scope: "fleet:control", iat: 1, exp: 4102444800 });
const SYMBOL = "PROBE_AGENT-1";

type Quirk =
  | "none"
  | "reset-answers-200"
  | "html-fallback"
  | "validation-skipped"
  | "status-leaks"
  | "other-symbol"
  | "no-cycle"
  | "shadow-cycle"
  | "disarmed"
  | "scope-lost";

interface Seen {
  paths: string[];
  resetAuths: (string | undefined)[];
}

interface Reply {
  status: number;
  body?: unknown;
  html?: string;
  headers?: Record<string, string>;
}
const ok = (body: unknown): Reply => ({ status: 200, body });
const refused = (status: number, message: string): Reply => ({ status, body: { error: { message } } });

function stub(quirk: Quirk, seen: Seen): Promise<http.Server> {
  const route = (method: string, p: string, auth: string | undefined): Reply => {
    const who = auth === undefined ? "none" : auth === `Bearer ${OPERATOR}` ? "operator" : auth === `Bearer ${NO_RESET}` ? "noreset" : "bad";
    const refuse = (): Reply => refused(401, "a bearer token is required");
    if (method === "OPTIONS") {
      return { status: 204, headers: { "access-control-allow-headers": "Content-Type, Authorization, X-Auth-Service-Secret", "access-control-allow-origin": "*" } };
    }
    if (/^\/api\/[a-z-]+\/health$/.test(p)) return ok({ status: "ok" });
    if (p === "/api/auth/v1/status") {
      return ok({
        state: "HEALTHY",
        agentSymbol: quirk === "other-symbol" ? "SOMEONE_ELSE" : SYMBOL,
        resetDate: "2026-10-01T00:00:00Z",
        ...(quirk === "status-leaks" ? { agentToken: "x" } : {}),
      });
    }
    if (method === "POST" && (p === "/api/auth/v1/register" || p === "/api/auth/v1/agent-token")) {
      seen.resetAuths.push(auth);
      if (quirk === "reset-answers-200" || who === "operator") return ok({ registered: true }); // the account would be reset: the probe must never get here with the operator
      if (who === "noreset") return refused(403, "this action requires a scope this session does not carry");
      return refuse();
    }
    if (p === "/api/agent/v1/transactions") {
      if (who === "bad") return refuse();
      return quirk === "html-fallback" ? { status: 200, html: "<html>dashboard</html>" } : ok([]);
    }
    if (/^\/api\/agent\/v1\/(current-agent|agent|ships|contracts)$/.test(p)) {
      if (who === "none" || who === "bad") return refuse();
      return ok(p.endsWith("current-agent") ? { agent: {} } : []);
    }
    if (method === "POST" && p.startsWith("/api/agent/v1/")) {
      if (who === "none" || who === "bad") return refuse();
      if (quirk === "scope-lost") return refused(403, "missing scope");
      return quirk === "validation-skipped" ? { status: 201, body: {} } : refused(400, "shipType is required");
    }
    if (p === "/api/automation/v1/autopilot/status") return ok({ status: quirk === "disarmed" ? "disarmed" : "armed", mode: quirk === "shadow-cycle" ? "shadow" : "live" });
    if (p === "/api/automation/v1/autopilot/events") {
      const type = quirk === "no-cycle" ? "planner_assignment" : quirk === "shadow-cycle" ? "planner_shadow_assignment" : "agent_credits_snapshot";
      return ok({ events: [{ type, occurredAt: new Date().toISOString(), detail: { secret: OPERATOR } }] });
    }
    if (p === "/api/automation/v1/events") return who === "operator" ? refused(403, "no events:write") : refuse();
    if (p.startsWith("/api/fleet/v1/")) return who === "none" || who === "bad" ? refuse() : refused(404, "no such ship");
    if (p.startsWith("/api/navigation/v1/")) return who === "bad" ? refuse() : { status: 404, body: {} };
    return { status: 404, html: "404 page not found" };
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://stub");
    seen.paths.push(`${req.method ?? "?"} ${url.pathname}`);
    const reply = route(req.method ?? "GET", url.pathname, req.headers.authorization);
    if (reply.html !== undefined) {
      res.writeHead(reply.status, { "content-type": reply.status === 404 ? "text/plain" : "text/html" });
      res.end(reply.html);
      return;
    }
    res.writeHead(reply.status, { ...(reply.body === undefined ? {} : { "content-type": "application/json" }), ...reply.headers });
    res.end(reply.body === undefined ? undefined : JSON.stringify(reply.body));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve(server);
    });
  });
}

function probe(env: Record<string, string>, args: string[] = []): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [script, ...args], { env: { PATH: process.env.PATH ?? "", ...env }, timeout: 60_000 }, (err, stdout, stderr) => {
      const code = err === null ? 0 : typeof (err as { code?: unknown }).code === "number" ? (err as { code: number }).code : 99;
      resolve({ code, out: stdout + stderr });
    });
  });
}

const open: http.Server[] = [];
afterAll(() => Promise.all(open.map((s) => new Promise((r) => s.close(r)))));
const serve = async (q: Quirk): Promise<{ base: string; seen: Seen }> => {
  const seen: Seen = { paths: [], resetAuths: [] };
  const s = await stub(q, seen);
  open.push(s);
  return { base: `http://127.0.0.1:${String((s.address() as AddressInfo).port)}`, seen };
};
const full = (base: string): Record<string, string> => ({ BASE_URL: base, OPERATOR_TOKEN: OPERATOR, NO_RESET_TOKEN: NO_RESET, EXPECT_AGENT_SYMBOL: SYMBOL });

describe("scripts/cutover-probe.mjs", () => {
  it("is green against a correct service, prints neither token, and records the agent symbol", async () => {
    const { base } = await serve("none");
    const { code, out } = await probe(full(base), ["--strict"]);
    expect(out).toContain("RESULT: GREEN");
    expect(code).toBe(0);
    expect(out).not.toMatch(/FAIL\s/);
    for (const secret of [OPERATOR, NO_RESET, ...OPERATOR.split("."), ...NO_RESET.split(".")]) expect(out).not.toContain(secret);
    expect(out).not.toMatch(/Bearer\s+\S{16,}/);
    expect(out).not.toContain("user_VALUE_MUST_NOT_PRINT");
    expect(out).not.toContain("user_OTHER_MUST_NOT_PRINT");
    expect(out).toContain(`agentSymbol=${SYMBOL}`);
    expect(out).toContain("same agent symbol as before the deploy");
    expect(out).toContain("MANDATORY GATE");
  });

  it("never calls a secret-gated route and never sends the operator's session (agent:reset) to the reset routes", async () => {
    const { base, seen } = await serve("none");
    const { code } = await probe(full(base), ["--strict"]);
    expect(code).toBe(0);
    for (const forbidden of ["/auth/v1/token", "/auth/v1/m2m-token", "/auth/v1/introspect"]) {
      expect(seen.paths.filter((p) => p.includes(forbidden))).toEqual([]);
    }
    // register and agent-token were reached (so the guard is exercised), and only without a session, with a garbage or forged
    // bearer, with a Basic header, or with the session that has no agent:reset.
    expect(seen.resetAuths.length).toBeGreaterThanOrEqual(10);
    expect(seen.resetAuths).not.toContain(`Bearer ${OPERATOR}`);
    for (const a of seen.resetAuths) {
      expect([undefined, `Bearer ${NO_RESET}`].includes(a) || /^(Bearer probe-garbage-not-a-token|Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0\.\S+|Basic \S+)$/.test(a ?? "")).toBe(true);
    }
    expect(seen.paths).not.toContain("GET /api/auth/v1/register");
  });

  it("refuses to send a NO_RESET_TOKEN whose scope holds agent:reset, and fails", async () => {
    const { base, seen } = await serve("none");
    const { code, out } = await probe({ ...full(base), NO_RESET_TOKEN: OPERATOR }, ["--strict"]);
    expect(code).toBe(1);
    expect(out).toContain("NOT SENT");
    expect(seen.resetAuths).not.toContain(`Bearer ${OPERATOR}`);
    expect(out).not.toContain(OPERATOR);
  });

  it("refuses to send an unreadable NO_RESET_TOKEN: its scope cannot be checked", async () => {
    const { base, seen } = await serve("none");
    const { code, out } = await probe({ ...full(base), NO_RESET_TOKEN: "opaque-session-token-CCCCCCCCCCCCCCCC" });
    expect(code).toBe(1);
    expect(out).toContain("not sent");
    expect(seen.resetAuths.some((a) => a?.includes("opaque-session"))).toBe(false);
  });

  it("fails loudly when a reset route answers success to a request that must be refused", async () => {
    const { base } = await serve("reset-answers-200");
    const { code, out } = await probe(full(base));
    expect(code).toBe(1);
    expect(out).toContain("ANSWERED SUCCESS");
    expect(out).toContain("RESULT: RED");
  });

  it("fails when the status answer carries a member that is not one of the four", async () => {
    const { base } = await serve("status-leaks");
    const { code, out } = await probe(full(base));
    expect(code).toBe(1);
    expect(out).toContain("unexpected member(s) agentToken");
  });

  it("fails when the agent symbol differs from EXPECT_AGENT_SYMBOL (the SQLite state did not survive)", async () => {
    const { base } = await serve("other-symbol");
    const { code, out } = await probe(full(base));
    expect(code).toBe(1);
    expect(out).toContain("different agent symbol");
  });

  it("skips, loudly, what it cannot check, and --strict turns that into a failure unless allowed by name", async () => {
    const { base } = await serve("none");
    const env = { BASE_URL: base, OPERATOR_TOKEN: OPERATOR };
    const lax = await probe(env);
    expect(lax.code).toBe(0);
    expect(lax.out).toMatch(/SKIPPED .*WITHOUT agent:reset.*NO_RESET_TOKEN/);
    expect(lax.out).toContain("SKIPPED checks proved nothing");
    expect((await probe(env, ["--strict"])).code).toBe(1);
    expect((await probe(env, ["--strict", "--allow-skip=NO_RESET_TOKEN"])).code).toBe(1); // EXPECT_AGENT_SYMBOL too
    expect((await probe(env, ["--strict", "--allow-skip=NO_RESET_TOKEN,EXPECT_AGENT_SYMBOL"])).code).toBe(0);
    expect((await probe(env, ["--allow-skip=NOPE"])).code).toBe(2);
  });

  it("accepts planner_shadow_assignment as the proof of a shadow-mode cycle, and fails on neither event", async () => {
    const shadow = await serve("shadow-cycle");
    const ok = await probe(full(shadow.base), ["--strict"]);
    expect(ok.code).toBe(0);
    expect(ok.out).toContain("armed (shadow)");
    const none = await serve("no-cycle");
    const bad = await probe(full(none.base));
    expect(bad.code).toBe(1);
    expect(bad.out).toContain("planner_shadow_assignment");
  });

  it("treats a disarmed autopilot as a skip that --strict only allows by name", async () => {
    const { base } = await serve("disarmed");
    expect((await probe(full(base), ["--strict"])).code).toBe(1);
    expect((await probe(full(base), ["--strict", "--allow-skip=AUTOMATION_CYCLE"])).code).toBe(0);
  });

  it("fails when an empty-body write is accepted, or when the operator's scope did not reach agent-service", async () => {
    const accepted = await serve("validation-skipped");
    const a = await probe(full(accepted.base));
    expect(a.code).toBe(1);
    expect(a.out).toContain("Validation did not run");
    expect(a.out).not.toContain(OPERATOR);
    const lost = await serve("scope-lost");
    const l = await probe(full(lost.base));
    expect(l.code).toBe(1);
    expect(l.out).toContain("lost the scope");
  });

  it("fails on CloudFront's dashboard fallback instead of reading it as a 200", async () => {
    const { base } = await serve("html-fallback");
    const { code, out } = await probe(full(base));
    expect(code).toBe(1);
    expect(out).toContain("text/html");
  });

  it("fails when nothing answers", async () => {
    const { code, out } = await probe({ BASE_URL: "http://127.0.0.1:9", OPERATOR_TOKEN: OPERATOR });
    expect(code).toBe(1);
    expect(out).toContain("FAIL");
  });

  it("--dry-run lists the checks, calls nothing and needs no token", async () => {
    const { base, seen } = await serve("none");
    const { code, out } = await probe({ BASE_URL: base, OPERATOR_TOKEN: OPERATOR }, ["--dry-run"]);
    expect(code).toBe(0);
    expect(out).toContain("--dry-run: nothing is called");
    expect(out).toContain("POST /api/auth/v1/register");
    expect(out).not.toContain(OPERATOR);
    expect((await probe({ BASE_URL: base }, ["--dry-run"])).code).toBe(0);
    expect(seen.paths).toEqual([]);
  });

  it("refuses to run without OPERATOR_TOKEN", async () => {
    const { code, out } = await probe({ BASE_URL: "http://127.0.0.1:9" });
    expect(code).toBe(2);
    expect(out).toContain("OPERATOR_TOKEN is not set");
  });
});
