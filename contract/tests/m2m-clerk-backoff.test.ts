// POST /auth/v1/m2m-token, production mode: the 10 s backoff after a failed mint, and the 10 s mint timeout. Split from m2m-clerk.test.ts only so the slow tests run in parallel.
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { expectJson } from "../lib/expect.ts";
import { send, sleep } from "../lib/http.ts";
import { Lab } from "../lib/lab.ts";
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

const FAILED = { error: "the token could not be minted" };
async function boot(): Promise<Api> {
  return lab.start({ m2m: "clerk" });
}

describe("the 10 s backoff after a failed mint", () => {
  it("answers 503 without calling Clerk again for 10 s, then tries again, per caller", async () => {
    let failing = true;
    lab.clerk.handler = (call) => {
      if (failing) return { status: 500, body: "down" };
      const asked = JSON.parse(call.body || "{}") as { claims?: { scope?: string } };
      return { status: 200, body: { token: lab.stubMachineToken(asked.claims?.scope ?? "") } };
    };
    const a = await boot();
    const t0 = Date.now();
    expectJson(await a.m2m(lab.secrets.callerAutomation), 503, FAILED, { noStore: true });
    assert.equal(lab.clerk.mintCalls().length, 1);

    for (let i = 0; i < 4; i++) {
      expectJson(await a.m2m(lab.secrets.callerAutomation), 503, FAILED, { noStore: true });
    }
    assert.equal(lab.clerk.mintCalls().length, 1, "inside the window nothing reaches Clerk");

    // The other caller has its own window.
    failing = false;
    assert.equal((await a.m2m(lab.secrets.callerAi)).status, 200);
    assert.equal(lab.clerk.mintCalls().length, 2);
    // ...while the first is still held off even though Clerk has recovered.
    expectJson(await a.m2m(lab.secrets.callerAutomation), 503, FAILED, { noStore: true });
    assert.equal(lab.clerk.mintCalls().length, 2);

    await sleep(Math.max(0, 10_600 - (Date.now() - t0)));
    assert.equal((await a.m2m(lab.secrets.callerAutomation)).status, 200);
    assert.equal(lab.clerk.mintCalls().length, 3, "after 10 s the next request mints again");
    await a.stop();
  });

  it("a failure inside a window restarts the window", async () => {
    lab.clerk.handler = () => ({ status: 500, body: "down" });
    const a = await boot();
    const t0 = Date.now();
    await a.m2m(lab.secrets.callerAutomation);
    await sleep(Math.max(0, 10_600 - (Date.now() - t0)));
    expectJson(await a.m2m(lab.secrets.callerAutomation), 503, FAILED, { noStore: true });
    assert.equal(lab.clerk.mintCalls().length, 2);
    expectJson(await a.m2m(lab.secrets.callerAutomation), 503, FAILED, { noStore: true });
    assert.equal(lab.clerk.mintCalls().length, 2, "the second failure opened a new 10 s window");
    await a.stop();
  });
});

describe("the mint timeout", () => {
  it("gives up on a Clerk that never answers after about 10 s: 503", async () => {
    lab.clerk.handler = () => ({ status: 200, delayMs: 14_000, body: { token: lab.stubMachineToken("x") } });
    const a = await boot();
    const t0 = Date.now();
    const r = await send(a.port, { method: "POST", path: "/auth/v1/m2m-token", headers: { "x-m2m-caller-secret": lab.secrets.callerAutomation }, timeoutMs: 20_000 });
    const took = Date.now() - t0;
    expectJson(r, 503, FAILED, { noStore: true });
    assert.ok(took >= 9_000 && took < 13_000, `mint timeout is 10 s, took ${took} ms`);
    await a.stop();
  });
});
