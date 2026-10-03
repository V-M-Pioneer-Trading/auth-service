// POST /auth/v1/m2m-token, production mode: tokens are minted by Clerk's Backend
// API (here a stub on CLERK_API_BASE_URL) with each caller's own Machine Secret
// Key, cached per caller, minted once however many requests arrive, refreshed at
// half their lifetime, and backed off for 10 s after a failure.
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { jwtPayload, nowSeconds, signJwt } from "../lib/crypto.ts";
import { expectJson } from "../lib/expect.ts";
import { send, sleep } from "../lib/http.ts";
import { CALLERS, Lab } from "../lib/lab.ts";
import type { Api } from "../lib/lab.ts";

let lab: Lab;

before(async () => {
  lab = await Lab.create();
});
after(async () => {
  await lab?.close();
});
beforeEach(() => {
  lab.clerk.clear();
  lab.healthyClerk();
});

const UNKNOWN = { error: "unknown caller" };
const FAILED = { error: "the token could not be minted" };
interface Minted {
  token: string;
  expires_at: number;
}

async function boot(): Promise<Api> {
  return lab.start({ m2m: "clerk" });
}

describe("what it asks Clerk", () => {
  it("POSTs /v1/m2m_tokens with the caller's own machine key and the caller's scopes, for 24 hours, as a JWT", async () => {
    const a = await boot();
    assert.equal((await a.m2m(lab.secrets.callerAutomation)).status, 200);
    assert.equal((await a.m2m(lab.secrets.callerAi)).status, 200);
    const [auto, ai] = lab.clerk.mintCalls();
    assert.ok(auto && ai);
    assert.equal(auto.headers.authorization, `Bearer ${lab.secrets.machineAutomation}`);
    assert.equal(ai.headers.authorization, `Bearer ${lab.secrets.machineAi}`);
    for (const call of [auto, ai]) assert.match(String(call.headers["content-type"]), /^application\/json/);
    assert.deepEqual(JSON.parse(auto.body), { token_format: "jwt", claims: { scope: CALLERS.automation.scope }, seconds_until_expiration: 86400 });
    assert.deepEqual(JSON.parse(ai.body), { token_format: "jwt", claims: { scope: CALLERS.ai.scope }, seconds_until_expiration: 86400 });
    assert.equal(lab.clerk.calls.length, 2);
    await a.stop();
  });

  it("serves Clerk's token verbatim with expires_at taken from its exp, and it introspects as the machine Clerk named", async () => {
    const a = await boot();
    const r = await a.m2m(lab.secrets.callerAi);
    const { token, expires_at } = r.json() as Minted;
    expectJson(r, 200, { token, expires_at }, { noStore: true });
    const claims = jwtPayload(token) as { exp: number; sub: string };
    assert.equal(expires_at, claims.exp);
    assert.equal(token, lab.lastMintedToken);
    expectJson(await a.introspect(token), 200, { active: true, sub: "mch_stub_machine", scope: CALLERS.ai.scope, exp: expires_at, kind: "machine" }, { noStore: true });
    await a.stop();
  });

  it("does not take the secret in the query string or the other secret headers", async () => {
    const a = await boot();
    expectJson(await a.m2m(lab.secrets.machineAutomation), 401, UNKNOWN, { noStore: true });
    expectJson(await a.m2m(null), 401, UNKNOWN, { noStore: true });
    assert.equal(lab.clerk.calls.length, 0, "a rejected caller must never cost a Clerk call");
    await a.stop();
  });
});

describe("single flight and the cache", () => {
  it("N concurrent requests from one caller cost exactly one Clerk call and all get the same token", async () => {
    lab.healthyClerk({ delayMs: 1200 });
    const a = await boot();
    const replies = await Promise.all(Array.from({ length: 25 }, () => a.m2m(lab.secrets.callerAutomation)));
    assert.deepEqual(new Set(replies.map((r) => r.status)), new Set([200]));
    assert.equal(new Set(replies.map((r) => JSON.stringify(r.json()))).size, 1, "every waiter got the same answer");
    assert.equal(lab.clerk.mintCalls().length, 1);
    await a.stop();
  });

  it("callers do not share a flight or a cache: two callers, two calls, however many requests", async () => {
    lab.healthyClerk({ delayMs: 600 });
    const a = await boot();
    const replies = await Promise.all([
      ...Array.from({ length: 10 }, () => a.m2m(lab.secrets.callerAutomation)),
      ...Array.from({ length: 10 }, () => a.m2m(lab.secrets.callerAi)),
    ]);
    assert.ok(replies.every((r) => r.status === 200));
    assert.equal(lab.clerk.mintCalls().length, 2);
    const scopes = new Set(replies.map((r) => (jwtPayload((r.json() as Minted).token) as { scope: string }).scope));
    assert.deepEqual(scopes, new Set([CALLERS.automation.scope, CALLERS.ai.scope]));
    await a.stop();
  });

  it("serves later requests from memory until half the lifetime has passed", async () => {
    const a = await boot();
    const first = await a.m2m(lab.secrets.callerAi);
    for (let i = 0; i < 5; i++) assert.deepEqual((await a.m2m(lab.secrets.callerAi)).json(), first.json());
    await sleep(1200);
    assert.deepEqual((await a.m2m(lab.secrets.callerAi)).json(), first.json());
    assert.equal(lab.clerk.mintCalls().length, 1);
    await a.stop();
  });

  it("a caller that gave up does not cancel the mint: its retry finds the token", async () => {
    lab.healthyClerk({ delayMs: 1500 });
    const a = await boot();
    await assert.rejects(send(a.port, { method: "POST", path: "/auth/v1/m2m-token", headers: { "x-m2m-caller-secret": lab.secrets.callerAi }, timeoutMs: 300 }));
    const r = await a.m2m(lab.secrets.callerAi);
    assert.equal(r.status, 200);
    assert.equal(lab.clerk.mintCalls().length, 1, "the retry joined or found the first mint");
    await a.stop();
  });
});

describe("what makes a minted token unusable (503, nothing cached, one Clerk call)", () => {
  const stamp = (claims: Record<string, unknown>) => (lab: Lab) => signJwt(claims, { key: lab.clerkKey.privateKey });
  const now = () => nowSeconds();
  const bad: Array<[string, (lab: Lab) => { status?: number; body?: unknown; headers?: Record<string, string>; destroy?: boolean }]> = [
    ["Clerk answers 500", () => ({ status: 500, body: { errors: [{ message: "boom with a secret-looking value" }] } })],
    ["Clerk answers 401", () => ({ status: 401, body: { errors: [] } })],
    ["Clerk answers 429", () => ({ status: 429, body: "slow down" })],
    ["a 3xx, which is never followed", () => ({ status: 307, headers: { location: "/v1/somewhere-else" }, body: "" })],
    ["a 2xx without a body", () => ({ status: 204 })],
    ["a body that is not JSON", () => ({ status: 200, body: "<html>" })],
    ["no token field", () => ({ status: 200, body: {} })],
    ["an empty token", () => ({ status: 200, body: { token: "" } })],
    ["a token that is not a JWT", () => ({ status: 200, body: { token: "not-a-jwt" } })],
    ["a token with two segments", () => ({ status: 200, body: { token: "aaa.bbb" } })],
    ["a token whose payload is not base64url JSON", (l) => ({ status: 200, body: { token: `${l.stubMachineToken("x").split(".")[0]}.!!!.sig` } })],
    ["a token with no iat", (l) => ({ status: 200, body: { token: stamp({ sub: "mch", exp: now() + 3600 })(l) } })],
    ["a token with no exp", (l) => ({ status: 200, body: { token: stamp({ sub: "mch", iat: now() })(l) } })],
    ["a lifetime of 59 s, under the 60 s minimum", (l) => ({ status: 200, body: { token: l.stubMachineToken("x", 59) } })],
    ["a lifetime of 7 days and a second, over the maximum", (l) => ({ status: 200, body: { token: l.stubMachineToken("x", 7 * 86400 + 1) } })],
    ["a token already expired", (l) => ({ status: 200, body: { token: l.stubMachineToken("x", 3600, -7200) } })],
    ["a token already past its own refresh point", (l) => ({ status: 200, body: { token: l.stubMachineToken("x", 100, -60) } })],
    ["an exp beyond 2^53", (l) => ({ status: 200, body: { token: stamp({ sub: "mch", iat: now(), exp: 2 ** 54 })(l) } })],
    ["a negative iat", (l) => ({ status: 200, body: { token: stamp({ sub: "mch", iat: -5, exp: now() + 3600 })(l) } })],
    ["exp as a string", (l) => ({ status: 200, body: { token: stamp({ sub: "mch", iat: now(), exp: String(now() + 3600) })(l) } })],
    ["Clerk hanging up without an answer", () => ({ destroy: true })],
  ];
  for (const [label, reply] of bad) {
    it(label, async () => {
      lab.clerk.handler = () => reply(lab);
      const a = await boot();
      const r = await a.m2m(lab.secrets.callerAutomation);
      expectJson(r, 503, FAILED, { noStore: true });
      assert.equal(lab.clerk.mintCalls().length, 1);
      assert.equal(lab.clerk.calls.length, 1, "no redirect, no retry");
      assert.doesNotMatch(r.text, /boom|secret/i, "nothing from Clerk's reply reaches the caller");
      await a.stop();
    });
  }

  it("accepts the shortest and longest lifetimes allowed, and any 2xx", async () => {
    for (const [lifetime, status] of [[60, 200], [7 * 86400, 201]] as const) {
      lab.clerk.clear();
      lab.clerk.handler = () => ({ status, body: { token: lab.stubMachineToken("x", lifetime) } });
      const a = await boot();
      assert.equal((await a.m2m(lab.secrets.callerAutomation)).status, 200, `${lifetime} s via ${status}`);
      await a.stop();
    }
  });

  it("does not follow a redirect, so the machine key is never re-sent anywhere", async () => {
    const elsewhere = lab.clerk;
    lab.clerk.handler = (call) =>
      call.path === "/v1/m2m_tokens" ? { status: 302, headers: { location: `/v1/stolen` }, body: "" } : { status: 200, body: {} };
    const a = await boot();
    expectJson(await a.m2m(lab.secrets.callerAutomation), 503, FAILED, { noStore: true });
    assert.deepEqual(elsewhere.calls.map((c) => c.path), ["/v1/m2m_tokens"]);
    await a.stop();
  });
});
