// Startup configuration: what the service refuses to start with, what it
// starts with in a degraded-but-safe state, and which spellings of a key it
// accepts. A refusal is a non-zero exit before anything listens; its message
// names environment variables and never a value.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { jwtPayload } from "../lib/crypto.ts";
import { expectAuthError, expectJson } from "../lib/expect.ts";
import { send } from "../lib/http.ts";
import { Lab } from "../lib/lab.ts";
import type { StartOptions } from "../lib/lab.ts";
import { mode } from "../lib/service.ts";

let lab: Lab;

before(async () => {
  lab = await Lab.create();
});
after(async () => {
  await lab?.close();
});

/** Every value that must never appear in output: all the secrets and both halves of the keys. */
function sensitive(): string[] {
  const keyBody = (pem: string) => pem.split("\n").filter((l) => l && !l.startsWith("-----"));
  return [
    ...Object.values(lab.secrets),
    ...keyBody(lab.clerkKey.privatePem),
    ...keyBody(lab.foreignKey.privatePem).slice(0, 3),
    "whitespace-secret-value",
  ];
}

async function refuses(opts: StartOptions, mentions: RegExp | undefined): Promise<void> {
  const { code, output } = await lab.startExpectingExit(opts);
  assert.ok(code !== 0 && code !== null, `expected a non-zero exit, got ${code}. Output:\n${output}`);
  if (mentions) assert.match(output, mentions, "the refusal should name the setting at fault");
  for (const value of sensitive()) assert.ok(!output.includes(value), "a refusal must never print a secret or key");
}

describe("required settings", () => {
  it("refuses to start without a Clerk verification key", async () => {
    await refuses({ env: { CLERK_JWT_KEY: undefined } }, /CLERK_JWT_KEY/);
  });
  it("refuses a Clerk verification key that is not a public key", async () => {
    await refuses({ env: { CLERK_JWT_KEY: "this is not a PEM" } }, undefined);
    await refuses({ env: { CLERK_JWT_KEY: lab.clerkKey.privatePem } }, undefined);
  });
  it("refuses CLERK_JWT_KEY_FILE that is missing, empty or not a key", async () => {
    await refuses({ env: { CLERK_JWT_KEY: undefined, CLERK_JWT_KEY_FILE: "/nonexistent/clerk.pem" } }, undefined);
    await refuses({ env: { CLERK_JWT_KEY: undefined, CLERK_JWT_KEY_FILE: "@file:clerk.pem" }, files: { "clerk.pem": "  \n" } }, /CLERK_JWT_KEY_FILE/);
    await refuses({ env: { CLERK_JWT_KEY: undefined, CLERK_JWT_KEY_FILE: "@file:clerk.pem" }, files: { "clerk.pem": "garbage" } }, undefined);
  });
  it("refuses to start without AUTH_SERVICE_SHARED_SECRET (an empty value counts as unset)", async () => {
    await refuses({ env: { AUTH_SERVICE_SHARED_SECRET: undefined } }, /AUTH_SERVICE_SHARED_SECRET/);
    await refuses({ env: { AUTH_SERVICE_SHARED_SECRET: "" } }, /AUTH_SERVICE_SHARED_SECRET/);
  });
  it("refuses an introspection secret equal to the vault's shared secret", async () => {
    await refuses({ env: { AUTH_INTROSPECTION_SECRET: lab.secrets.shared } }, /AUTH_INTROSPECTION_SECRET/);
  });
});

describe("the M2M mint table is validated at startup", () => {
  it("refuses two callers with the same secret", async () => {
    await refuses({ env: { M2M_CALLER_SECRET_AI_SERVICE: lab.secrets.callerAutomation } }, /M2M_CALLER_SECRET|caller secrets/);
  });
  it("refuses a caller secret equal to AUTH_SERVICE_SHARED_SECRET", async () => {
    await refuses({ env: { M2M_CALLER_SECRET_AUTOMATION_SERVICE: lab.secrets.shared } }, /AUTH_SERVICE_SHARED_SECRET/);
  });
  it("refuses a caller secret equal to AUTH_INTROSPECTION_SECRET (every service holds that one)", async () => {
    await refuses({ env: { M2M_CALLER_SECRET_AI_SERVICE: lab.secrets.introspection } }, /AUTH_INTROSPECTION_SECRET/);
  });
  it("has nothing to collide with when there is no introspection secret", async () => {
    const api = await lab.start({ env: { AUTH_INTROSPECTION_SECRET: undefined } });
    assert.equal((await api.m2m(lab.secrets.callerAi)).status, 200);
    await api.stop();
  });
  it("refuses a caller secret with leading or trailing whitespace, or only whitespace: no request could ever present it", async () => {
    for (const secret of [" whitespace-secret-value", "whitespace-secret-value ", "whitespace-secret-value\t", "   "]) {
      await refuses({ env: { M2M_CALLER_SECRET_AI_SERVICE: secret } }, /whitespace/);
    }
  });
  it("refuses an enabled caller with nothing to mint with", async () => {
    await refuses({ m2m: "none", env: { M2M_CALLER_SECRET_AUTOMATION_SERVICE: lab.secrets.callerAutomation } }, /M2M_MACHINE_KEY|DEV_M2M_SIGNING_KEY_FILE|mint/);
  });
  it("refuses two callers sharing one Clerk machine key", async () => {
    await refuses({ m2m: "clerk", env: { M2M_MACHINE_KEY_AI_SERVICE: lab.secrets.machineAutomation } }, /M2M_MACHINE_KEY/);
  });
  it("refuses a dev signing key next to a machine key: one trust anchor per process", async () => {
    await refuses({ m2m: "dev", env: { M2M_MACHINE_KEY_AI_SERVICE: lab.secrets.machineAi } }, /DEV_M2M_SIGNING_KEY_FILE|M2M_MACHINE_KEY/);
  });
  it("refuses a dev signing key that is missing, empty, or not an RSA private key", async () => {
    await refuses({ m2m: "dev", env: { DEV_M2M_SIGNING_KEY_FILE: "/nonexistent/dev.pem" } }, /DEV_M2M_SIGNING_KEY_FILE/);
    await refuses({ m2m: "dev", files: { "dev-m2m.pem": "\n" } }, /DEV_M2M_SIGNING_KEY_FILE/);
    await refuses({ m2m: "dev", files: { "dev-m2m.pem": "garbage" } }, /DEV_M2M_SIGNING_KEY_FILE/);
    await refuses({ m2m: "dev", files: { "dev-m2m.pem": lab.clerkKey.publicPem } }, /DEV_M2M_SIGNING_KEY_FILE/);
  });
});

describe("settings that leave the service running in a fail-closed state", () => {
  it("without AUTH_INTROSPECTION_SECRET the route is mounted and rejects every caller, empty header included", async () => {
    const api = await lab.start({ env: { AUTH_INTROSPECTION_SECRET: undefined } });
    for (const secret of [null, "", "anything", lab.secrets.shared, lab.secrets.callerAutomation]) {
      expectAuthError(await api.introspect(lab.token(), secret), 401, "a valid introspection secret is required");
    }
    assert.equal((await api.get("/health")).status, 200);
    assert.equal((await api.agentToken(null)).status, 403, "the vault is unaffected");
    await api.stop();
  });

  it("with an empty AUTH_INTROSPECTION_SECRET it is the same as unset", async () => {
    const api = await lab.start({ env: { AUTH_INTROSPECTION_SECRET: "" } });
    expectAuthError(await api.introspect(lab.token(), ""), 401, "a valid introspection secret is required");
    await api.stop();
  });

  it("with no M2M callers configured the mint route rejects everyone and the rest works", async () => {
    const api = await lab.start({ m2m: "none" });
    expectJson(await api.m2m("x"), 401, { error: "unknown caller" }, { noStore: true });
    assert.equal(((await api.introspect(lab.token())).json() as { active: boolean }).active, true);
    await api.stop();
  });
});

describe("accepted spellings of keys", () => {
  const exp = () => Math.floor(Date.now() / 1000) + 3600;
  const introspectsActive = async (opts: StartOptions) => {
    const api = await lab.start(opts);
    const r = await api.introspect(lab.token({ exp: exp() }));
    assert.equal((r.json() as { active: boolean }).active, true);
    await api.stop();
  };

  it("CLERK_JWT_KEY as a PKIX public key, a PKCS#1 public key, or one line with literal \\n separators", async () => {
    await introspectsActive({ env: { CLERK_JWT_KEY: lab.clerkKey.publicPem } });
    await introspectsActive({ env: { CLERK_JWT_KEY: lab.clerkKey.publicKey.export({ type: "pkcs1", format: "pem" }).toString() } });
    await introspectsActive({ env: { CLERK_JWT_KEY: lab.clerkKey.publicPem.trim().replaceAll("\n", "\\n") } });
  });

  it("CLERK_JWT_KEY_FILE, with the inline key winning when both are set", async () => {
    await introspectsActive({ env: { CLERK_JWT_KEY: undefined, CLERK_JWT_KEY_FILE: "@file:clerk.pem" }, files: { "clerk.pem": lab.clerkKey.publicPem } });
    const both = await lab.start({ env: { CLERK_JWT_KEY_FILE: "@file:clerk.pem" }, files: { "clerk.pem": lab.foreignKey.publicPem } });
    assert.equal(((await both.introspect(lab.token({ exp: exp() }))).json() as { active: boolean }).active, true, "inline wins");
    assert.equal(((await both.introspect(lab.token({ exp: exp() }, lab.foreignKey))).json() as { active: boolean }).active, false);
    await both.stop();
  });

  it("DEV_M2M_SIGNING_KEY_FILE as PKCS#8 or PKCS#1 private key", async () => {
    for (const pem of [lab.clerkKey.privatePem, lab.clerkKey.privateKey.export({ type: "pkcs1", format: "pem" }).toString()]) {
      const api = await lab.start({ m2m: "dev", files: { "dev-m2m.pem": pem } });
      const r = await api.m2m(lab.secrets.callerAi);
      assert.equal(r.status, 200);
      assert.equal(jwtPayload((r.json() as { token: string }).token).sub, "mch_local_ai-service");
      await api.stop();
    }
  });
});

describe("listening", () => {
  it("listens on PORT", async () => {
    const api = await lab.start({ env: { PORT: "8123" } });
    assert.equal((await api.get("/health")).status, 200);
    await api.stop();
  });

  it("listens on port 80 when PORT is unset (the image's EXPOSE)", { skip: mode === "bin" ? "a native run cannot bind port 80" : false }, async () => {
    const api = await lab.start({ env: { PORT: undefined } });
    assert.equal((await api.get("/health")).status, 200);
    await api.stop();
  });
});

describe("log hygiene", () => {
  it("never writes a secret, a key or a query-string token to the log", async () => {
    const api = await lab.start();
    const sentinel = lab.token({ sub: "user_logged_sentinel" });
    await send(api.port, { method: "POST", path: `/auth/v1/introspect?token=${sentinel}`, headers: { "x-introspection-secret": lab.secrets.introspection } });
    await api.introspect(sentinel);
    await api.agentToken();
    await api.m2m(lab.secrets.callerAutomation);
    await api.m2m("wrong-secret-sentinel");
    await api.register({ accountToken: "account-token-sentinel", symbol: "S", faction: "F" });
    await api.restore({ agentToken: "agent-token-sentinel" });
    const log = api.output();
    for (const value of [...sensitive(), sentinel, sentinel.split(".")[1] as string, "wrong-secret-sentinel", "account-token-sentinel", "agent-token-sentinel"]) {
      assert.ok(!log.includes(value), "a credential reached the log");
    }
    await api.stop();
  });
});
