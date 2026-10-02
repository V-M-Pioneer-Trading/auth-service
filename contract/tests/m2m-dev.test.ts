// POST /auth/v1/m2m-token, development mode: DEV_M2M_SIGNING_KEY_FILE set, so
// tokens are signed locally instead of minted by Clerk. The caller table, the
// secret gate and the response shape are the same in both modes; the Clerk-mode
// behaviours (single flight, backoff, refresh) are in m2m-clerk.test.ts.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { jwtHeader, jwtPayload, verifyRs256 } from "../lib/crypto.ts";
import { expectJson } from "../lib/expect.ts";
import { send, sleep } from "../lib/http.ts";
import { CALLERS, Lab } from "../lib/lab.ts";
import type { Api } from "../lib/lab.ts";

let lab: Lab;
let api: Api;

before(async () => {
  lab = await Lab.create();
  api = await lab.start({ m2m: "dev" });
});
after(async () => {
  await lab?.close();
});

const UNKNOWN = { error: "unknown caller" };
interface Minted {
  token: string;
  expires_at: number;
}
const mint = async (a: Api, secret: string): Promise<Minted> => {
  const r = await a.m2m(secret);
  expectJson(r, 200, r.json(), { noStore: true });
  return r.json() as Minted;
};

describe("the caller table", () => {
  const rows = [
    { who: CALLERS.automation, secret: () => lab.secrets.callerAutomation },
    { who: CALLERS.ai, secret: () => lab.secrets.callerAi },
  ];
  for (const { who, secret } of rows) {
    it(`${who.name} gets a token for ${who.scope}, signed by the dev key, naming mch_local_${who.name}`, async () => {
      const before = Math.floor(Date.now() / 1000);
      const { token, expires_at } = await mint(api, secret());
      const after = Math.floor(Date.now() / 1000);

      assert.deepEqual(jwtHeader(token), { alg: "RS256", kid: "dev-only-do-not-use", typ: "JWT" });
      const claims = jwtPayload(token) as { sub: string; scope: string; iat: number; exp: number };
      assert.deepEqual(Object.keys(claims).sort(), ["exp", "iat", "scope", "sub"]);
      assert.equal(claims.sub, `mch_local_${who.name}`);
      assert.equal(claims.scope, who.scope);
      assert.ok(claims.iat >= before && claims.iat <= after, "iat is the mint time");
      assert.equal(claims.exp, claims.iat + 86400, "24 hours, not Clerk's default hour");
      assert.equal(expires_at, claims.exp);
      assert.ok(verifyRs256(token, lab.clerkKey.publicKey), "signed with the configured dev key");
      assert.ok(!verifyRs256(token, lab.foreignKey.publicKey));
    });

    it(`${who.name}'s token introspects as an active machine with exactly its scope`, async () => {
      const { token, expires_at } = await mint(api, secret());
      expectJson(await api.introspect(token), 200, { active: true, sub: `mch_local_${who.name}`, scope: who.scope, exp: expires_at, kind: "machine" }, { noStore: true });
    });
  }

  it("answers the exact response shape: {token, expires_at} with a numeric expires_at, no-store and CORS", async () => {
    const r = await api.m2m(lab.secrets.callerAutomation);
    const body = r.json() as Record<string, unknown>;
    assert.deepEqual(Object.keys(body).sort(), ["expires_at", "token"]);
    assert.equal(typeof body.token, "string");
    assert.ok(Number.isInteger(body.expires_at));
    expectJson(r, 200, body, { noStore: true });
  });

  it("serves the same token again (cached, not re-signed) even a second later", async () => {
    const first = await mint(api, lab.secrets.callerAi);
    await sleep(1100);
    assert.deepEqual(await mint(api, lab.secrets.callerAi), first);
  });

  it("gives each caller its own token", async () => {
    const a = await mint(api, lab.secrets.callerAutomation);
    const b = await mint(api, lab.secrets.callerAi);
    assert.notEqual(a.token, b.token);
    assert.notEqual((jwtPayload(a.token) as { sub: string }).sub, (jwtPayload(b.token) as { sub: string }).sub);
  });

  it("lets a caller request nothing: body, query and extra headers cannot name a caller or a scope", async () => {
    const r = await send(api.port, {
      method: "POST",
      path: "/auth/v1/m2m-token?scope=fleet:admin&caller=ai-service",
      headers: { "x-m2m-caller-secret": lab.secrets.callerAutomation, "content-type": "application/json", "x-m2m-caller": "ai-service", "x-scope": "admin" },
      body: JSON.stringify({ scope: "everything", caller: "ai-service", name: "ai-service" }),
    });
    assert.equal((jwtPayload((r.json() as Minted).token) as { scope: string }).scope, "fleet:control");
    assert.equal((jwtPayload((r.json() as Minted).token) as { sub: string }).sub, "mch_local_automation-service");
  });
});

describe("the secret gate", () => {
  const post = (headers: Record<string, string>) => send(api.port, { method: "POST", path: "/auth/v1/m2m-token", headers });

  it("answers 401 {error:'unknown caller'} with no-store for an unknown, empty or missing secret", async () => {
    for (const secret of [lab.secrets.callerAutomation.slice(0, -1), `${lab.secrets.callerAutomation}x`, lab.secrets.callerAutomation.toUpperCase(), "", "nope"]) {
      expectJson(await api.m2m(secret), 401, UNKNOWN, { noStore: true });
    }
    expectJson(await api.m2m(null), 401, UNKNOWN, { noStore: true });
  });

  it("does not accept the vault, introspection or Clerk-machine secrets in a caller's place", async () => {
    for (const secret of [lab.secrets.shared, lab.secrets.introspection, lab.secrets.machineAutomation]) {
      expectJson(await api.m2m(secret), 401, UNKNOWN, { noStore: true });
    }
  });

  it("does not take the secret from the query string or from the other secrets' headers", async () => {
    expectJson(await post({}), 401, UNKNOWN, { noStore: true });
    expectJson(await send(api.port, { method: "POST", path: `/auth/v1/m2m-token?secret=${lab.secrets.callerAi}&x-m2m-caller-secret=${lab.secrets.callerAi}` }), 401, UNKNOWN, { noStore: true });
    for (const header of ["x-auth-service-secret", "x-introspection-secret", "authorization"]) {
      expectJson(await post({ [header]: lab.secrets.callerAi }), 401, UNKNOWN, { noStore: true });
    }
  });

  it("ignores surrounding whitespace in the header value and matches the name case-insensitively", async () => {
    const r = await post({ "X-M2M-CALLER-SECRET": `  ${lab.secrets.callerAi}  ` });
    assert.equal(r.status, 200);
  });

  it("never names a caller, a secret or a reason in the rejection", async () => {
    const r = await api.m2m("nope");
    assert.equal(r.text, '{"error":"unknown caller"}\n');
  });
});

describe("which callers are enabled", () => {
  it("a caller with no secret is disabled: only its own secret is missing, the other still mints", async () => {
    const only = await lab.start({ m2m: "dev", env: { M2M_CALLER_SECRET_AI_SERVICE: undefined } });
    assert.equal((await only.m2m(lab.secrets.callerAutomation)).status, 200);
    expectJson(await only.m2m(lab.secrets.callerAi), 401, UNKNOWN, { noStore: true });
    await only.stop();
  });

  it("with no caller secrets at all it boots and rejects every caller", async () => {
    const none = await lab.start({ m2m: "none" });
    for (const secret of ["", "anything", lab.secrets.callerAutomation]) expectJson(await none.m2m(secret), 401, UNKNOWN, { noStore: true });
    expectJson(await none.m2m(null), 401, UNKNOWN, { noStore: true });
    assert.equal((await none.get("/health")).status, 200);
    await none.stop();
  });

  it("a machine key with no caller secret leaves the caller disabled and the service up", async () => {
    const orphan = await lab.start({ m2m: "none", env: { M2M_MACHINE_KEY_AI_SERVICE: "machine-key-without-a-caller-secret" } });
    expectJson(await orphan.m2m("anything"), 401, UNKNOWN, { noStore: true });
    await orphan.stop();
  });
});

describe("tokens only introspect when the dev key is the verification key", () => {
  it("a dev key that is not CLERK_JWT_KEY's partner mints tokens that introspect as {active:false}", async () => {
    const mismatched = await lab.start({ m2m: "dev", files: { "dev-m2m.pem": lab.foreignKey.privatePem } });
    const { token } = await mint(mismatched, lab.secrets.callerAutomation);
    assert.ok(verifyRs256(token, lab.foreignKey.publicKey));
    expectJson(await mismatched.introspect(token), 200, { active: false }, { noStore: true });
    await mismatched.stop();
  });

  it("with CLERK_ISSUER set the token carries it as iss, and introspection (which then checks iss) accepts it", async () => {
    const ISS = "https://clerk.contract.example";
    const issued = await lab.start({ m2m: "dev", env: { CLERK_ISSUER: ISS } });
    const { token, expires_at } = await mint(issued, lab.secrets.callerAi);
    assert.equal((jwtPayload(token) as { iss?: string }).iss, ISS);
    expectJson(await issued.introspect(token), 200, { active: true, sub: "mch_local_ai-service", scope: "events:write planner:advise", exp: expires_at, kind: "machine" }, { noStore: true });
    await issued.stop();
  });

  it("without CLERK_ISSUER the token has no iss claim", async () => {
    const { token } = await mint(api, lab.secrets.callerAutomation);
    assert.equal("iss" in jwtPayload(token), false);
  });
});
