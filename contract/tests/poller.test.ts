// The poller state machine (auth-design.md decisions 7 and 8) as it is visible
// from outside: the forced poll behind GET /auth/v1/token?afterUnauthorized=true,
// its 10 s cooldown, wipe detection and automatic re-registration, the
// APP_TOKEN_EXPIRED flag, and what survives a restart on the same /data volume.
//
// The scheduled cadence (daily, hourly inside the 24 h before a predicted reset)
// is not observable in a test that lasts seconds; only the poll the service makes
// at startup is. See README.md, "Not covered".
import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
import { expectJson, expectText } from "../lib/expect.ts";
import { sleep, waitFor } from "../lib/http.ts";
import { Lab } from "../lib/lab.ts";
import type { Api } from "../lib/lab.ts";

let lab: Lab;
let api: Api | undefined;

const REGISTER = { accountToken: "account-token-1", symbol: "CONTRACT-1", faction: "COSMIC", email: "pilot@example.com" };
interface Status {
  state: string;
  agentSymbol?: string;
  resetDate?: string;
  nextPredictedReset?: string;
}
const status = async (a: Api) => (await a.status()).json() as Status;
const forced = (a: Api) => a.agentToken(undefined, "?afterUnauthorized=true");
const token = async (a: Api) => ((await a.agentToken()).json() as { agentToken: string }).agentToken;

before(async () => {
  lab = await Lab.create();
});
after(async () => {
  await lab?.close();
});
beforeEach(() => {
  lab.st.reset();
});
afterEach(async () => {
  await api?.stop();
  api = undefined;
});

async function boot(volume = lab.newVolume()): Promise<Api> {
  api = await lab.start({ volume });
  return api;
}

/** Registers, then forgets the calls that registration itself made. The token is agent-token-1. */
async function registered(a: Api): Promise<void> {
  assert.equal((await a.register(REGISTER)).status, 200);
  lab.st.clear();
}

describe("the forced poll: GET /auth/v1/token?afterUnauthorized=true", () => {
  it("with no credential does not call SpaceTraders and still answers 503", async () => {
    const a = await boot();
    expectText(await forced(a), 503, "no agent token configured\n");
    assert.equal(lab.st.calls.length, 0);
  });

  it("polls only for the exact value 'true'", async () => {
    const a = await boot();
    await registered(a);
    for (const query of ["?afterUnauthorized=false", "?afterUnauthorized=TRUE", "?afterUnauthorized=1", "?afterUnauthorized=", "?afterUnauthorized", "?AfterUnauthorized=true", "?afterunauthorized=true", "?x=afterUnauthorized%3Dtrue"]) {
      expectJson(await a.agentToken(undefined, query), 200, { agentToken: "agent-token-1" });
    }
    assert.equal(lab.st.calls.length, 0, "none of those may poll");
    assert.equal((await forced(a)).status, 200);
    assert.equal(lab.st.rootCalls().length, 1, "and the exact value does");
  });

  it("accepts the flag among other parameters and repeated: the first value counts", async () => {
    const a = await boot();
    await registered(a);
    await a.agentToken(undefined, "?x=1&afterUnauthorized=true&y=2");
    assert.equal(lab.st.rootCalls().length, 1);
  });

  it("polls only for a caller with the right secret", async () => {
    const a = await boot();
    await registered(a);
    assert.equal((await a.agentToken("wrong", "?afterUnauthorized=true")).status, 403);
    assert.equal((await a.agentToken(null, "?afterUnauthorized=true")).status, 403);
    assert.equal(lab.st.calls.length, 0, "an unauthenticated caller must not make the service call SpaceTraders");
  });

  it("calls GET /proxy/ with no Authorization header and nothing else", async () => {
    const a = await boot();
    await registered(a);
    await forced(a);
    assert.equal(lab.st.rootCalls().length, 1);
    assert.equal(lab.st.rootCalls()[0]?.headers.authorization, undefined);
    assert.deepEqual(lab.st.strayCalls(), []);
  });

  it("with an unchanged resetDate concludes the token is dead: APP_TOKEN_EXPIRED, the token still served", async () => {
    const a = await boot();
    await registered(a);
    expectJson(await forced(a), 200, { agentToken: "agent-token-1" });
    assert.equal(lab.st.registerCalls().length, 0);
    expectJson(await a.status(), 200, {
      state: "APP_TOKEN_EXPIRED",
      agentSymbol: "CONTRACT-1",
      resetDate: "2026-09-01T00:00:00Z",
      nextPredictedReset: "2099-01-01T00:00:00Z",
    });
  });

  it("outranks WIPE_IMMINENT: a dead token needs a human however close the reset is", async () => {
    lab.st.setRoot("2026-09-01", new Date(Date.now() + 3600_000).toISOString());
    const a = await boot();
    assert.equal((await a.register(REGISTER)).status, 200);
    assert.equal((await status(a)).state, "WIPE_IMMINENT");
    assert.equal((await forced(a)).status, 200);
    assert.equal((await status(a)).state, "APP_TOKEN_EXPIRED");
  });

  it("is cleared by Restore Token", async () => {
    const a = await boot();
    await registered(a);
    await forced(a);
    assert.equal((await status(a)).state, "APP_TOKEN_EXPIRED");
    expectJson(await a.restore({ agentToken: "restored" }), 200, { status: "restored" });
    assert.equal((await status(a)).state, "HEALTHY");
    assert.equal(await token(a), "restored");
  });

  it("is cleared by registering again", async () => {
    const a = await boot();
    await registered(a);
    await forced(a);
    assert.equal((await a.register(REGISTER)).status, 200);
    assert.equal((await status(a)).state, "HEALTHY");
  });

  it("when a root without resetDate comes back it still concludes the token is dead, and forgets the stored dates", async () => {
    const a = await boot();
    await registered(a);
    lab.st.setRoot(undefined, undefined);
    await forced(a);
    expectJson(await a.status(), 200, { state: "APP_TOKEN_EXPIRED", agentSymbol: "CONTRACT-1" });
  });
});

describe("wipe detection through the forced poll", () => {
  it("a changed resetDate is a wipe: re-registers with the stored account token, symbol, faction and email, and serves the NEW token", async () => {
    const a = await boot();
    await registered(a);
    lab.st.setRoot("2026-09-15", "2099-02-01T00:00:00Z");
    expectJson(await forced(a), 200, { agentToken: "agent-token-2" });
    const [call] = lab.st.registerCalls();
    assert.equal(lab.st.registerCalls().length, 1);
    assert.equal(call?.headers.authorization, "Bearer account-token-1");
    assert.deepEqual(JSON.parse(call?.body ?? ""), { symbol: "CONTRACT-1", faction: "COSMIC", email: "pilot@example.com" });
    // Not a dead token: the reset explains the 401, so the flag stays down and the new dates are adopted.
    expectJson(await a.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1", resetDate: "2026-09-15T00:00:00Z", nextPredictedReset: "2099-02-01T00:00:00Z" });
  });

  it("keeps the stored symbol even if SpaceTraders answers a different one", async () => {
    const a = await boot();
    await registered(a);
    lab.st.setRoot("2026-09-15", "2099-02-01T00:00:00Z");
    lab.st.register = () => ({ status: 201, body: { data: { token: "reregistered", agent: { symbol: "SOMEONE-ELSE", credits: 1 } } } });
    expectJson(await forced(a), 200, { agentToken: "reregistered" });
    assert.equal((await status(a)).agentSymbol, "CONTRACT-1");
  });

  it("a failed re-registration is not a dead token: the old token is served, the old dates kept, the flag stays down", async () => {
    const a = await boot();
    await registered(a);
    lab.st.setRoot("2026-09-15", "2099-02-01T00:00:00Z");
    lab.st.register = () => ({ status: 500, body: "boom" });
    expectJson(await forced(a), 200, { agentToken: "agent-token-1" });
    assert.equal(lab.st.registerCalls().length, 1);
    expectJson(await a.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1", resetDate: "2026-09-01T00:00:00Z", nextPredictedReset: "2099-01-01T00:00:00Z" });
  });

  it("a root that cannot be fetched or parsed changes nothing and does not flag the token", async () => {
    for (const root of [{ status: 500, body: "down" }, { status: 404, body: "" }, { status: 200, body: "<html>not json</html>" }, { destroy: true }]) {
      const a = await boot();
      await registered(a);
      lab.st.root = root;
      expectJson(await forced(a), 200, { agentToken: "agent-token-1" });
      expectJson(await a.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1", resetDate: "2026-09-01T00:00:00Z", nextPredictedReset: "2099-01-01T00:00:00Z" });
      await a.stop();
      lab.st.reset();
    }
  });
});

describe("the 10 s cooldown on forced polls", () => {
  it("lets one poll through and swallows the rest of a burst, answering every request normally", async () => {
    const a = await boot();
    await registered(a);
    const replies = await Promise.all(Array.from({ length: 12 }, () => forced(a)));
    assert.deepEqual(new Set(replies.map((r) => r.status)), new Set([200]));
    assert.equal(lab.st.rootCalls().length, 1);
    await forced(a);
    assert.equal(lab.st.rootCalls().length, 1, "still inside the window");
  });

  it("opens again after 10 s, and a failed poll starts the window like a successful one", async () => {
    const a = await boot();
    await registered(a);
    lab.st.root = { status: 500, body: "down" };
    const start = Date.now();
    await forced(a); // fails, still consumes the window
    lab.st.root = { status: 200, body: { resetDate: "2026-09-01", serverResets: { next: "2099-01-01T00:00:00Z" } } };
    await forced(a);
    assert.equal(lab.st.rootCalls().length, 1, "a failed forced poll must not be retried at once");
    await sleep(Math.max(0, 10_600 - (Date.now() - start)));
    await forced(a);
    assert.equal(lab.st.rootCalls().length, 2, "after 10 s the next forced poll goes through");
  });

  it("is started even by a forced poll with no credential, which then blocks the poll right after registration", async () => {
    const a = await boot();
    const start = Date.now();
    expectText(await forced(a), 503, "no agent token configured\n");
    assert.equal((await a.register(REGISTER)).status, 200);
    lab.st.clear();
    expectJson(await forced(a), 200, { agentToken: "agent-token-1" });
    assert.equal(lab.st.rootCalls().length, 0, "inside the window opened by the earlier credential-less poll");
    assert.equal((await status(a)).state, "HEALTHY");
    await sleep(Math.max(0, 10_600 - (Date.now() - start)));
    await forced(a);
    assert.equal(lab.st.rootCalls().length, 1);
    assert.equal((await status(a)).state, "APP_TOKEN_EXPIRED");
  });
});

describe("what survives a restart on the same /data volume", () => {
  it("carries the credential, the dates and the flag across a hard kill, and polls at startup", async () => {
    const volume = lab.newVolume();

    // 1. Nothing configured: nothing to poll.
    let a = await boot(volume);
    await sleep(1000);
    assert.equal(lab.st.calls.length, 0, "an unconfigured service must not call SpaceTraders at startup");
    expectJson(await a.status(), 200, { state: "UNCONFIGURED" });
    assert.equal((await a.register(REGISTER)).status, 200);
    await a.stop();

    // 2. Same root: the credential is back, startup polls once, no registration.
    lab.st.clear();
    a = await boot(volume);
    await waitFor("the startup poll", () => lab.st.rootCalls().length === 1);
    await sleep(300);
    assert.equal(lab.st.registerCalls().length, 0);
    assert.equal(await token(a), "agent-token-1");
    expectJson(await a.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1", resetDate: "2026-09-01T00:00:00Z", nextPredictedReset: "2099-01-01T00:00:00Z" });
    await a.stop();

    // 3. The reset date moved while it was down: the startup poll sees the wipe and re-registers.
    lab.st.clear();
    lab.st.setRoot("2026-10-01", "2099-03-01T00:00:00Z");
    a = await boot(volume);
    await waitFor("the automatic re-registration", () => lab.st.registerCalls().length === 1);
    const [call] = lab.st.registerCalls();
    assert.equal(call?.headers.authorization, "Bearer account-token-1");
    assert.deepEqual(JSON.parse(call?.body ?? ""), { symbol: "CONTRACT-1", faction: "COSMIC", email: "pilot@example.com" });
    await waitFor("the new token to be stored", async () => (await token(a)) === "agent-token-2");
    await waitFor("the new dates to be stored", async () => (await status(a)).resetDate === "2026-10-01T00:00:00Z");
    expectJson(await a.status(), 200, { state: "HEALTHY", agentSymbol: "CONTRACT-1", resetDate: "2026-10-01T00:00:00Z", nextPredictedReset: "2099-03-01T00:00:00Z" });
    await a.stop();

    // 4. SpaceTraders is down at startup: the service still comes up and serves what it has.
    lab.st.clear();
    lab.st.root = { status: 503, body: "down" };
    a = await boot(volume);
    await waitFor("the failed startup poll", () => lab.st.rootCalls().length === 1);
    assert.equal(await token(a), "agent-token-2");
    assert.equal((await status(a)).resetDate, "2026-10-01T00:00:00Z");

    // 5. A forced poll flags the token; the flag outlives a restart and a scheduled poll does not clear it.
    lab.st.root = { status: 200, body: { resetDate: "2026-10-01", serverResets: { next: "2099-03-01T00:00:00Z" } } };
    await forced(a);
    assert.equal((await status(a)).state, "APP_TOKEN_EXPIRED");
    await a.stop();
    lab.st.clear();
    a = await boot(volume);
    await waitFor("the startup poll", () => lab.st.rootCalls().length === 1);
    await sleep(300);
    assert.equal((await status(a)).state, "APP_TOKEN_EXPIRED");
    assert.equal(lab.st.registerCalls().length, 0);

    // 6. A restored token survives too.
    expectJson(await a.restore({ agentToken: "restored-then-restarted" }), 200, { status: "restored" });
    await a.stop();
    a = await boot(volume);
    assert.equal(await token(a), "restored-then-restarted");
    assert.equal((await status(a)).state, "HEALTHY");
  });

  it("starts empty on a fresh volume even if another volume holds a credential", async () => {
    const a = await boot();
    await registered(a);
    await a.stop();
    const b = await boot();
    expectJson(await b.status(), 200, { state: "UNCONFIGURED" });
  });
});
