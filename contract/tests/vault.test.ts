// The vault routes: GET /auth/v1/token (the only route that can return the game
// credential), the two status routes, and the operator routes behind a Clerk
// session carrying agent:reset (POST /api/auth/v1/agent-token and /register).
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { nowSeconds } from "../lib/crypto.ts";
import { expectAuthError, expectJson, expectText } from "../lib/expect.ts";
import { send } from "../lib/http.ts";
import { Lab } from "../lib/lab.ts";
import type { Api } from "../lib/lab.ts";

let lab: Lab;
let api: Api;

const REGISTER = { accountToken: "account-token-1", symbol: "CONTRACT-1", faction: "COSMIC" };

before(async () => {
  lab = await Lab.create();
});
after(async () => {
  await lab?.close();
});

/** A fresh service with an empty database for each describe's scenario. */
async function fresh(): Promise<Api> {
  if (api) await api.stop();
  lab.st.reset();
  api = await lab.start();
  return api;
}

describe("GET /auth/v1/token", () => {
  beforeEach(fresh);

  it("rejects a wrong or missing shared secret with 403, the envelope and no-store", async () => {
    expectAuthError(await api.agentToken("wrong"), 403, "invalid or missing shared secret");
    expectAuthError(await api.agentToken(null), 403, "invalid or missing shared secret");
    expectAuthError(await api.agentToken(""), 403, "invalid or missing shared secret");
    expectAuthError(await api.agentToken(lab.secrets.shared.toUpperCase()), 403, "invalid or missing shared secret");
    expectAuthError(await api.agentToken(`${lab.secrets.shared}x`), 403, "invalid or missing shared secret");
  });

  it("does not accept the introspection secret, a caller secret, or a Clerk session in place of the shared secret", async () => {
    expectAuthError(await api.agentToken(lab.secrets.introspection), 403, "invalid or missing shared secret");
    expectAuthError(await api.agentToken(lab.secrets.callerAi), 403, "invalid or missing shared secret");
    const r = await send(api.port, { path: "/auth/v1/token", headers: { authorization: `Bearer ${lab.token()}` } });
    expectAuthError(r, 403, "invalid or missing shared secret");
  });

  it("ignores a secret passed in the query string", async () => {
    const r = await send(api.port, { path: `/auth/v1/token?secret=${lab.secrets.shared}&x-auth-service-secret=${lab.secrets.shared}` });
    expectAuthError(r, 403, "invalid or missing shared secret");
  });

  it("is 503 with a plain-text body while no credential is configured", async () => {
    expectText(await api.agentToken(), 503, "no agent token configured\n");
  });

  it("ignores surrounding whitespace in the secret header value", async () => {
    const r = await send(api.port, { path: "/auth/v1/token", headers: { "x-auth-service-secret": `  ${lab.secrets.shared}\t` } });
    expectText(r, 503, "no agent token configured\n"); // authenticated, then unconfigured
  });

  it("returns the agent token, and only that, once registered; Cache-Control is absent today and no-store would also be accepted", async () => {
    assert.equal((await api.register(REGISTER)).status, 200);
    const r = await api.agentToken();
    const noStore = r.header("cache-control") === "no-store";
    expectJson(r, 200, { agentToken: "agent-token-1" }, { noStore });
    assert.ok(r.header("cache-control") === undefined || noStore, "Cache-Control, if present, must be no-store");
  });

  it("is 503 again if the stored agent token is empty", async () => {
    lab.st.register = () => ({ status: 201, body: { data: { token: "", agent: { symbol: "EMPTY", credits: 0 } } } });
    assert.equal((await api.register(REGISTER)).status, 200);
    expectText(await api.agentToken(), 503, "no agent token configured\n");
  });

  it("is not mounted under /api/auth (decision 9: no public route for the token, at any method) [net-http-text]", async () => {
    for (const method of ["GET", "POST"]) {
      expectText(await send(api.port, { method, path: "/api/auth/v1/token", headers: { "x-auth-service-secret": lab.secrets.shared } }), 404, "404 page not found\n", {
        cors: false,
      });
    }
  });
});

describe("GET /auth/v1/status and /api/auth/v1/status", () => {
  beforeEach(fresh);
  const both = ["/auth/v1/status", "/api/auth/v1/status"];

  it("is public and says only UNCONFIGURED before registration", async () => {
    for (const path of both) expectJson(await api.status(path), 200, { state: "UNCONFIGURED" });
  });

  it("reports HEALTHY with the symbol and RFC 3339 dates once registered, and never a token", async () => {
    assert.equal((await api.register({ ...REGISTER, email: "pilot@example.com" })).status, 200);
    for (const path of both) {
      const r = await api.status(path);
      expectJson(r, 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1", resetDate: "2026-09-01T00:00:00Z", nextPredictedReset: "2099-01-01T00:00:00Z" });
      assert.doesNotMatch(r.text, /agent-token|account-token|pilot@example/);
    }
  });

  it("is WIPE_IMMINENT inside the 24 h before the predicted reset, and HEALTHY outside it", async () => {
    const inH = (h: number) => new Date(Date.now() + h * 3600_000).toISOString().replace(/\.\d+Z$/, "Z");
    lab.st.setRoot("2026-09-01", inH(23));
    assert.equal((await api.register(REGISTER)).status, 200);
    assert.equal(((await api.status()).json() as { state: string }).state, "WIPE_IMMINENT");
    lab.st.setRoot("2026-09-01", inH(25));
    assert.equal((await api.register(REGISTER)).status, 200);
    assert.equal(((await api.status()).json() as { state: string }).state, "HEALTHY");
  });

  it("stays WIPE_IMMINENT after the predicted reset has passed", async () => {
    lab.st.setRoot("2026-09-01", "2020-01-01T00:00:00Z");
    assert.equal((await api.register(REGISTER)).status, 200);
    expectJson(await api.status(), 200, { state: "WIPE_IMMINENT", agentSymbol: "CONTRACT-1", resetDate: "2026-09-01T00:00:00Z", nextPredictedReset: "2020-01-01T00:00:00Z" });
  });

  it("formats dates the way Go's RFC 3339 does: offsets kept, fractions dropped, date-only read as midnight UTC", async () => {
    lab.st.setRoot("2026-09-01T08:30:00+02:00", "2099-03-04T05:06:07.891+05:30");
    assert.equal((await api.register(REGISTER)).status, 200);
    expectJson(await api.status(), 200, {
      state: "HEALTHY",
      agentSymbol: "CONTRACT-1",
      resetDate: "2026-09-01T08:30:00+02:00",
      nextPredictedReset: "2099-03-04T05:06:07+05:30",
    });
  });

  it("omits a date it cannot parse instead of failing", async () => {
    lab.st.setRoot("not-a-date", "2099/01/01");
    assert.equal((await api.register(REGISTER)).status, 200);
    expectJson(await api.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1" });
  });

  it("omits both dates when the root carries neither", async () => {
    lab.st.setRoot(undefined, undefined);
    assert.equal((await api.register(REGISTER)).status, 200);
    expectJson(await api.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1" });
  });

  it("ignores the query string", async () => {
    expectJson(await api.get("/auth/v1/status?state=HEALTHY&x=1"), 200, { state: "UNCONFIGURED" });
  });
});

describe("health", () => {
  before(fresh);
  it("answers {status:ok} on both paths, with CORS and no Cache-Control", async () => {
    for (const path of ["/health", "/api/auth/health"]) {
      const r = await api.get(path);
      expectJson(r, 200, { status: "ok" });
    }
  });
  it("needs no credentials and ignores them", async () => {
    expectJson(await api.get("/health", { authorization: "Bearer garbage", "x-auth-service-secret": "wrong" }), 200, { status: "ok" });
  });
});

describe("the session gate on the operator routes", () => {
  before(fresh);
  const paths = ["/api/auth/v1/agent-token", "/api/auth/v1/register"];
  const body = JSON.stringify({ agentToken: "x", ...REGISTER });
  const post = (path: string, authorization?: string | string[], query = "") =>
    send(api.port, {
      method: "POST",
      path: path + query,
      headers: authorization === undefined ? { "content-type": "application/json" } : Array.isArray(authorization) ? ["host", `127.0.0.1:${api.port}`, "content-type", "application/json", ...authorization.flatMap((a) => ["authorization", a])] : { "content-type": "application/json", authorization },
      body,
    });

  it("401 'a bearer token is required' when there is no usable bearer credential", async () => {
    for (const path of paths) {
      for (const authorization of [undefined, "", "Bearer", "Bearer ", "Basic dXNlcjpwYXNz", "Token abc", "Bearer a b", "abc", lab.token()]) {
        expectAuthError(await post(path, authorization), 401, "a bearer token is required");
      }
    }
  });

  it("401 'invalid or expired session' for anything that does not verify, naming no reason", async () => {
    const claims = { sub: "user_x", scope: "agent:reset" };
    const bad = [
      "garbage",
      lab.token({ ...claims, exp: nowSeconds() - 3600 }),
      lab.token(claims, lab.foreignKey),
      lab.token({ scope: "agent:reset", sub: undefined }),
    ];
    for (const path of paths) {
      for (const token of bad) expectAuthError(await post(path, `Bearer ${token}`), 401, "invalid or expired session");
    }
  });

  it("403 'requires a scope this session does not carry' for a valid session without agent:reset", async () => {
    const msg = "this action requires a scope this session does not carry";
    for (const path of paths) {
      for (const scope of [undefined, "", "fleet:control", "agent:resetx", "agent:rese", "AGENT:RESET", "agent:reset:read", null, 5]) {
        expectAuthError(await post(path, `Bearer ${lab.token({ scope })}`), 403, msg);
      }
    }
  });

  it("does not take the token from the query string", async () => {
    for (const path of paths) expectAuthError(await post(path, undefined, `?token=${lab.token()}&access_token=${lab.token()}`), 401, "a bearer token is required");
  });

  it("decides on the first of two Authorization headers", async () => {
    const good = `Bearer ${lab.token()}`;
    const r1 = await post("/api/auth/v1/agent-token", [good, "Bearer garbage"]);
    assert.notEqual(r1.status, 401, "first header is valid: must get past the gate");
    expectAuthError(await post("/api/auth/v1/agent-token", ["Bearer garbage", good]), 401, "invalid or expired session");
  });

  it("accepts the scheme in any case and any run of spaces, and a scope anywhere in a multi-value or array claim", async () => {
    const token = lab.token({ scope: "fleet:control agent:reset  universe:refresh" });
    for (const authorization of [`bearer ${token}`, `BEARER ${token}`, `Bearer   ${token}`, `Bearer\t${token}`]) {
      const r = await post("/api/auth/v1/agent-token", authorization);
      assert.notEqual(r.status, 401, authorization.slice(0, 12));
      assert.notEqual(r.status, 403);
    }
    const arrayScoped = lab.token({ scope: ["fleet:control", "agent:reset"] });
    assert.notEqual((await post("/api/auth/v1/agent-token", `Bearer ${arrayScoped}`)).status, 403);
  });

  it("splits the scope on runs of space, tab, CR and LF and on nothing else (fixture v6)", async () => {
    const msg = "this action requires a scope this session does not carry";
    for (const scope of ["fleet:control\tagent:reset", "fleet:control\r\nagent:reset", "  agent:reset  "]) {
      const r = await post("/api/auth/v1/agent-token", `Bearer ${lab.token({ scope })}`);
      assert.notEqual(r.status, 401, JSON.stringify(scope));
      assert.notEqual(r.status, 403, JSON.stringify(scope));
    }
    for (const joiner of ["\u000b", "\u000c", "\u0085", "\u00a0", "\u2003", "\u3000", "\ufeff"]) {
      const token = lab.token({ scope: `fleet:control${joiner}agent:reset` });
      expectAuthError(await post("/api/auth/v1/agent-token", `Bearer ${token}`), 403, msg);
    }
  });

  it("authenticates before it reads the body", async () => {
    const r = await send(api.port, { method: "POST", path: "/api/auth/v1/register", headers: { "content-type": "application/json" }, body: "{not json" });
    expectAuthError(r, 401, "a bearer token is required");
  });

  it("is not mounted without the /api/auth prefix", async () => {
    for (const path of ["/auth/v1/agent-token", "/auth/v1/register", "/agent-token", "/register", "/api/v1/register"]) {
      const r = await send(api.port, { method: "POST", path, headers: { authorization: `Bearer ${lab.token()}` }, body: body });
      assert.ok(r.status === 404 || r.status === 405, `${path} -> ${r.status}`);
    }
  });
});

describe("POST /api/auth/v1/agent-token (Restore Token)", () => {
  beforeEach(fresh);

  it("is 409 while no credential exists", async () => {
    expectText(await api.restore({ agentToken: "restored" }), 409, "no credential configured to restore a token onto\n");
  });

  it("replaces only the agent token", async () => {
    assert.equal((await api.register({ ...REGISTER, email: "p@example.com" })).status, 200);
    const before = (await api.status()).json();
    expectJson(await api.restore({ agentToken: "restored-1" }), 200, { status: "restored" });
    expectJson(await api.agentToken(), 200, { agentToken: "restored-1" });
    assert.deepEqual((await api.status()).json(), before);
    assert.equal(lab.st.registerCalls().length, 1, "restoring must not call SpaceTraders");
  });

  it("rejects a missing or empty agentToken with 400", async () => {
    assert.equal((await api.register(REGISTER)).status, 200);
    for (const body of [{}, { agentToken: "" }, { agentToken: null }, { other: "x" }, "null"]) {
      expectText(await api.restore(body), 400, "agentToken is required\n");
    }
    expectJson(await api.agentToken(), 200, { agentToken: "agent-token-1" });
  });

  it("rejects a body that is not a JSON object of the right shape with 400 ", async () => {
    assert.equal((await api.register(REGISTER)).status, 200);
    // The text after the prefix is the decoder's own message (Go's encoding/json): only the prefix is the contract.
    for (const body of ["", "{", "not json", "[]", '"a string"', "42", '{"agentToken": 5}', '{"agentToken": {"a":1}}', '{"agentToken": ["x"]}']) {
      const r = await api.restore(body);
      expectText(r, 400, /^invalid request body: /);
    }
    expectJson(await api.agentToken(), 200, { agentToken: "agent-token-1" });
  });

  it("decodes like Go's encoding/json: key case ignored, unknown keys ignored, last duplicate wins, trailing data ignored", async () => {
    assert.equal((await api.register(REGISTER)).status, 200);
    expectJson(await api.restore('{"AGENTTOKEN":"upper"}'), 200, { status: "restored" });
    expectJson(await api.agentToken(), 200, { agentToken: "upper" });
    expectJson(await api.restore('{"agenttoken":"lower","unknown":{"a":[1,2]}}'), 200, { status: "restored" });
    expectJson(await api.agentToken(), 200, { agentToken: "lower" });
    expectJson(await api.restore('{"agentToken":"first","agentToken":"second"}'), 200, { status: "restored" });
    expectJson(await api.agentToken(), 200, { agentToken: "second" });
    expectJson(await api.restore('{"agentToken":"trailing"} this is never read'), 200, { status: "restored" });
    expectJson(await api.agentToken(), 200, { agentToken: "trailing" });
  });

  it("does not require a JSON content type", async () => {
    assert.equal((await api.register(REGISTER)).status, 200);
    const r = await send(api.port, {
      method: "POST",
      path: "/api/auth/v1/agent-token",
      headers: { authorization: `Bearer ${lab.token()}`, "content-type": "text/plain" },
      body: '{"agentToken":"as-text"}',
    });
    expectJson(r, 200, { status: "restored" });
  });

  it("stores the token verbatim, whitespace and all", async () => {
    assert.equal((await api.register(REGISTER)).status, 200);
    expectJson(await api.restore({ agentToken: "  spaced token\t" }), 200, { status: "restored" });
    expectJson(await api.agentToken(), 200, { agentToken: "  spaced token\t" });
  });
});
