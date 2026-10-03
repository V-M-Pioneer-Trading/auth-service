// POST /auth/v1/m2m-token, production mode: refresh at half the token's lifetime. Split from m2m-clerk.test.ts only so the slow tests run in parallel.
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { jwtPayload, nowSeconds } from "../lib/crypto.ts";
import { sleep, waitFor } from "../lib/http.ts";
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

interface Minted {
  token: string;
  expires_at: number;
}

async function boot(): Promise<Api> {
  return lab.start({ m2m: "clerk" });
}

describe("refresh at half the lifetime", () => {
  it("keeps answering with the cached token while the refresh runs behind it, then switches; a failed refresh keeps the cached token", async () => {
    // A 60 s token minted with iat 25 s in the past: refresh point 5 s from now, expiry 35 s from now.
    let calls = 0;
    lab.clerk.handler = (call) => {
      calls++;
      const asked = JSON.parse(call.body || "{}") as { claims?: { scope?: string } };
      if (calls === 3) return { status: 500, body: "refresh failed" };
      return { status: 200, delayMs: calls === 2 ? 1500 : 0, body: { token: lab.stubMachineToken(asked.claims?.scope ?? "", 60, -25) } };
    };
    const a = await boot();
    const first = (await a.m2m(lab.secrets.callerAi)).json() as Minted;
    assert.equal(lab.clerk.mintCalls().length, 1);
    assert.equal(((await a.m2m(lab.secrets.callerAi)).json() as Minted).token, first.token, "before the refresh point: from memory");
    assert.equal(lab.clerk.mintCalls().length, 1);

    // Past the refresh point (about 5 s in). The slow refresh must not hold the caller up.
    await waitFor("the refresh point", () => nowSeconds() >= jwtIat(first.token) + 31, 15_000, 200);
    await sleep(300);
    const t1 = Date.now();
    const during = (await a.m2m(lab.secrets.callerAi)).json() as Minted;
    assert.equal(during.token, first.token, "the old token, at once");
    assert.ok(Date.now() - t1 < 1000, `must not wait for the refresh (took ${Date.now() - t1} ms)`);
    const alsoDuring = (await a.m2m(lab.secrets.callerAi)).json() as Minted;
    assert.equal(alsoDuring.token, first.token);
    await waitFor("the refresh to have been requested", () => lab.clerk.mintCalls().length === 2);
    assert.equal(lab.clerk.mintCalls().length, 2, "concurrent requests share the one refresh");

    // The refresh lands: the new token replaces the old.
    await waitFor("the new token", async () => ((await a.m2m(lab.secrets.callerAi)).json() as Minted).token !== first.token, 5000, 200);
    const second = (await a.m2m(lab.secrets.callerAi)).json() as Minted;
    assert.notEqual(second.token, first.token);
    assert.equal(lab.clerk.mintCalls().length, 2);
    assert.equal(jwtPayload(second.token).scope, CALLERS.ai.scope);

    // The next refresh point comes 5 s later (iat is backdated again). That refresh fails (call 3):
    // the caller still gets the cached, unexpired token, and the failure opens the backoff window.
    // Keep asking until the refresh has been attempted: the service's clock may sit a moment behind ours,
    // and every answer on the way must still be the cached token.
    await waitFor("the second refresh point", () => nowSeconds() >= jwtIat(second.token) + 31, 15_000, 200);
    await waitFor(
      "the failing refresh",
      async () => {
        assert.equal(((await a.m2m(lab.secrets.callerAi)).json() as Minted).token, second.token);
        return lab.clerk.mintCalls().length === 3;
      },
      10_000,
      250,
    );
    await sleep(300);
    assert.equal(((await a.m2m(lab.secrets.callerAi)).json() as Minted).token, second.token, "a failed refresh never costs the caller its valid token");
    assert.equal(lab.clerk.mintCalls().length, 3, "and the failure opened the backoff window");
    await a.stop();
  });
});

function jwtIat(token: string): number {
  return (jwtPayload(token) as { iat: number }).iat;
}
