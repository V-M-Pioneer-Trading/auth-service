// POST /api/auth/v1/register (Reset Agent): mints a new agent through
// st-gateway's /proxy/register and persists the credential. Everything the
// service sends upstream, and how it maps upstream failures, is contract.
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { expectJson, expectText } from "../lib/expect.ts";
import { Lab } from "../lib/lab.ts";
import type { Api } from "../lib/lab.ts";

let lab: Lab;
let api: Api;
const BODY = { accountToken: "account-token-1", symbol: "CONTRACT-1", faction: "COSMIC" };

before(async () => {
  lab = await Lab.create();
});
after(async () => {
  await lab?.close();
});

beforeEach(async () => {
  if (api) await api.stop();
  lab.st.reset();
  api = await lab.start();
});

describe("what it asks of the caller", () => {
  it("requires accountToken, symbol and faction, each of them, as non-empty strings", async () => {
    for (const body of [{}, { symbol: "A", faction: "B" }, { accountToken: "t", faction: "B" }, { accountToken: "t", symbol: "A" }, { accountToken: "", symbol: "A", faction: "B" }, { accountToken: "t", symbol: "", faction: "B" }, { accountToken: "t", symbol: "A", faction: "" }, { accountToken: null, symbol: "A", faction: "B" }]) {
      expectText(await api.register(body), 400, "accountToken, symbol and faction are required\n");
    }
    assert.equal(lab.st.calls.length, 0, "a rejected request must not reach SpaceTraders");
  });

  it("rejects a malformed or wrongly typed body with 400 'invalid request body: …'", async () => {
    for (const body of ["", "{", "[]", '{"accountToken": 1, "symbol": "A", "faction": "B"}', '{"symbol": ["A"]}', '{"email": 5, "accountToken":"t","symbol":"A","faction":"B"}']) {
      expectText(await api.register(body), 400, /^invalid request body: /);
    }
    assert.equal(lab.st.calls.length, 0);
  });

  it("decodes like Go's encoding/json: key case ignored, unknown keys ignored, trailing data ignored", async () => {
    expectText(await api.register("null"), 400, "accountToken, symbol and faction are required\n");
    const r = await api.register('{"ACCOUNTTOKEN":"t","Symbol":"mixed","FACTION":"F","unknown":[1],"x":null} trailing');
    expectJson(r, 200, { agentSymbol: "mixed", status: "registered" });
  });
});

describe("what it sends to SpaceTraders", () => {
  it("POSTs {symbol,faction} to /proxy/register with the account token as the bearer", async () => {
    expectJson(await api.register(BODY), 200, { agentSymbol: "CONTRACT-1", status: "registered" });
    const [call] = lab.st.registerCalls();
    assert.ok(call);
    assert.equal(call.headers.authorization, "Bearer account-token-1");
    assert.match(String(call.headers["content-type"]), /^application\/json/);
    assert.deepEqual(JSON.parse(call.body), { symbol: "CONTRACT-1", faction: "COSMIC" });
  });

  it("includes email when given, and leaves the key out entirely when it is empty or absent", async () => {
    await api.register({ ...BODY, email: "pilot@example.com" });
    await api.register({ ...BODY, email: "" });
    await api.register(BODY);
    const bodies = lab.st.registerCalls().map((c) => JSON.parse(c.body));
    assert.deepEqual(bodies, [
      { symbol: "CONTRACT-1", faction: "COSMIC", email: "pilot@example.com" },
      { symbol: "CONTRACT-1", faction: "COSMIC" },
      { symbol: "CONTRACT-1", faction: "COSMIC" },
    ]);
  });

  it("passes the strings through untouched", async () => {
    await api.register({ accountToken: "spaced tok en", symbol: "ünï", faction: "x y" });
    const [call] = lab.st.registerCalls();
    assert.equal(call?.headers.authorization, "Bearer spaced tok en");
    assert.deepEqual(JSON.parse(call?.body ?? ""), { symbol: "ünï", faction: "x y" });
  });

  it("then polls the unauthenticated root once, with no Authorization header, so status is populated at once", async () => {
    await api.register(BODY);
    const roots = lab.st.rootCalls();
    assert.equal(roots.length, 1);
    assert.equal(roots[0]?.headers.authorization, undefined);
    assert.deepEqual(lab.st.strayCalls(), []);
    expectJson(await api.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1", resetDate: "2026-09-01T00:00:00Z", nextPredictedReset: "2099-01-01T00:00:00Z" });
  });

  it("still succeeds when that follow-up poll fails, leaving the dates unset", async () => {
    lab.st.root = { status: 500, body: "boom" };
    expectJson(await api.register(BODY), 200, { agentSymbol: "CONTRACT-1", status: "registered" });
    expectJson(await api.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1" });
  });
});

describe("what it stores and answers", () => {
  it("answers with the symbol SpaceTraders reports, not the one requested", async () => {
    lab.st.register = () => ({ status: 201, body: { data: { token: "t-up", agent: { symbol: "UPSTREAM-SYMBOL", credits: 1 } } } });
    expectJson(await api.register(BODY), 200, { agentSymbol: "UPSTREAM-SYMBOL", status: "registered" });
    expectJson(await api.agentToken(), 200, { agentToken: "t-up" });
    assert.equal(((await api.status()).json() as { agentSymbol: string }).agentSymbol, "UPSTREAM-SYMBOL");
  });

  it("accepts any 2xx from upstream and ignores extra fields", async () => {
    lab.st.register = () => ({ status: 200, body: { data: { token: "t-200", extra: [1], agent: { symbol: "S", credits: 9, more: {} } }, meta: {} } });
    expectJson(await api.register(BODY), 200, { agentSymbol: "S", status: "registered" });
  });

  it("replaces an existing credential wholesale, including the history of reset dates", async () => {
    await api.register(BODY);
    lab.st.setRoot(undefined, undefined);
    expectJson(await api.register({ accountToken: "account-token-2", symbol: "SECOND", faction: "VOID" }), 200, { agentSymbol: "SECOND", status: "registered" });
    expectJson(await api.agentToken(), 200, { agentToken: "agent-token-2" });
    expectJson(await api.status(), 200, { state: "HEALTHY", agentSymbol: "SECOND" });
  });

  it("stores an empty token as 'no token' (it answers 200 but /auth/v1/token is then 503)", async () => {
    lab.st.register = () => ({ status: 201, body: { data: { agent: { symbol: "NOTOKEN" } } } });
    expectJson(await api.register(BODY), 200, { agentSymbol: "NOTOKEN", status: "registered" });
    expectText(await api.agentToken(), 503, "no agent token configured\n");
  });
});

describe("how upstream failures map to responses", () => {
  const failing = (status: number, body: string) => {
    lab.st.register = () => ({ status, body });
  };

  it("passes any upstream 4xx/5xx status through, with 'POST /register: <upstream body>' as text", async () => {
    for (const [status, body] of [
      [400, '{"error":{"message":"bad"}}'],
      [401, "nope"],
      [409, '{"error":{"code":4111,"message":"Symbol taken"}}'],
      [422, ""],
      [429, '{"error":{"message":"slow down"}}'],
      [500, "oops"],
      [503, "<html>down</html>"],
    ] as const) {
      failing(status, body);
      expectText(await api.register(BODY), status, `POST /register: ${body}\n`);
    }
  });

  it("answers 502 for an upstream 2xx whose body is not the expected JSON ", async () => {
    for (const body of ["", "not json", "[", "<html></html>"]) {
      failing(200, body);
      const r = await api.register(BODY);
      expectText(r, 502, /^/);
    }
  });

  it("answers 502 when upstream is unreachable or hangs up", async () => {
    lab.st.register = () => ({ destroy: true });
    expectText(await api.register(BODY), 502, /^/);
  });

  it("leaves the stored credential untouched when registration fails", async () => {
    await api.register(BODY);
    failing(500, "boom");
    expectText(await api.register({ accountToken: "other", symbol: "OTHER", faction: "X" }), 500, "POST /register: boom\n");
    expectJson(await api.agentToken(), 200, { agentToken: "agent-token-1" });
    assert.equal(((await api.status()).json() as { agentSymbol: string }).agentSymbol, "CONTRACT-1");
  });
});
