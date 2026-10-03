// POST /auth/v1/m2m-token, production mode: an expired cached token is never
// served. Split into its own file only so the 40 s wait runs in parallel.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { jwtPayload, nowSeconds } from "../lib/crypto.ts";
import { expectJson } from "../lib/expect.ts";
import { waitFor } from "../lib/http.ts";
import { Lab } from "../lib/lab.ts";

let lab: Lab;

before(async () => {
  lab = await Lab.create();
});
after(async () => {
  await lab?.close();
});

describe("a token past its exp", () => {
  it("is never served, even though Clerk is down and it was served moments earlier: 503", async () => {
    // One 60 s token minted with iat 25 s in the past (refresh point in 5 s, expiry in 35 s); every later mint fails.
    lab.clerk.handler = (call, nth) => {
      if (nth > 1) return { status: 500, body: "down" };
      const asked = JSON.parse(call.body || "{}") as { claims?: { scope?: string } };
      return { status: 200, body: { token: lab.stubMachineToken(asked.claims?.scope ?? "", 60, -25) } };
    };
    const a = await lab.start({ m2m: "clerk" });
    const first = await a.m2m(lab.secrets.callerAi);
    assert.equal(first.status, 200);
    const { token } = first.json() as { token: string };
    const exp = (jwtPayload(token) as { exp: number }).exp;

    // Still valid while the failed refresh is being retried behind it.
    await waitFor("a failed refresh attempt", async () => {
      assert.equal(((await a.m2m(lab.secrets.callerAi)).json() as { token: string }).token, token);
      return lab.clerk.mintCalls().length >= 2;
    }, 20_000, 500);

    // Two seconds past exp, to stay clear of clock drift between here and the service.
    await waitFor("exp to pass", () => nowSeconds() >= exp + 2, 60_000, 500);
    for (let i = 0; i < 3; i++) {
      const r = await a.m2m(lab.secrets.callerAi);
      expectJson(r, 503, { error: "the token could not be minted" }, { noStore: true });
      assert.ok(!r.text.includes(token));
    }
    await a.stop();
  });
});
