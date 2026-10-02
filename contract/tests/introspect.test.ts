// POST /auth/v1/introspect: the one place a Clerk token is verified for the fleet.
// The security properties are the contract: anything unverifiable is
// {"active":false} (never an error that says why), the answer is never cacheable,
// the token travels in the body and never the query string, the secret gate
// comes first, and the body is capped.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { hs256Jwt, nowSeconds, signJwt, unsignedJwt } from "../lib/crypto.ts";
import { expectAuthError, expectJson, INACTIVE } from "../lib/expect.ts";
import { send } from "../lib/http.ts";
import { Lab } from "../lib/lab.ts";
import type { Api } from "../lib/lab.ts";

let lab: Lab;
let api: Api;
const REQUIRED = "a valid introspection secret is required";

before(async () => {
  lab = await Lab.create();
  api = await lab.start();
});
after(async () => {
  await lab?.close();
});

const active = (sub: string, scope: string, exp: number) => ({
  active: true,
  sub,
  scope,
  exp,
  kind: sub.startsWith("user_") ? "operator" : "machine",
});

describe("the caller secret gate", () => {
  it("rejects a wrong secret with 401, the error envelope and no-store", async () => {
    expectAuthError(await api.introspect(lab.token(), "not-the-secret"), 401, REQUIRED);
  });
  it("rejects a missing header", async () => {
    expectAuthError(await api.introspect(lab.token(), null), 401, REQUIRED);
  });
  it("rejects an empty header", async () => {
    expectAuthError(await api.introspect(lab.token(), ""), 401, REQUIRED);
  });
  it("rejects a prefix, an extension and a re-cased copy of the real secret", async () => {
    const s = lab.secrets.introspection;
    for (const wrong of [s.slice(0, -1), `${s}x`, `x${s}`, s.toUpperCase()]) {
      expectAuthError(await api.introspect(lab.token(), wrong), 401, REQUIRED);
    }
  });
  it("does not accept the vault's shared secret or a caller's mint secret", async () => {
    expectAuthError(await api.introspect(lab.token(), lab.secrets.shared), 401, REQUIRED);
    expectAuthError(await api.introspect(lab.token(), lab.secrets.callerAutomation), 401, REQUIRED);
  });
  it("answers the secret before it looks at the body, so a wrong secret never learns about the token", async () => {
    const r = await api.introspect(lab.token(), "wrong");
    assert.equal(r.status, 401);
    assert.doesNotMatch(r.text, /active/);
  });
  it("matches the header name case-insensitively and ignores surrounding whitespace in its value", async () => {
    for (const name of ["X-Introspection-Secret", "x-INTROSPECTION-secret"]) {
      const r = await send(api.port, {
        method: "POST",
        path: "/auth/v1/introspect",
        headers: { [name]: `  ${lab.secrets.introspection}  `, "content-type": "application/x-www-form-urlencoded" },
        body: `token=${lab.token()}`,
      });
      assert.equal(r.status, 200);
      assert.equal((r.json() as { active: boolean }).active, true);
    }
  });
  it("does not reject the shared secret placed in the vault header (separate secrets, separate headers)", async () => {
    const r = await send(api.port, {
      method: "POST",
      path: "/auth/v1/introspect",
      headers: { "x-auth-service-secret": lab.secrets.shared, "content-type": "application/x-www-form-urlencoded" },
      body: `token=${lab.token()}`,
    });
    expectAuthError(r, 401, REQUIRED);
  });
});

describe("where the token travels", () => {
  const form = { "content-type": "application/x-www-form-urlencoded", "x-introspection-secret": "" };
  const post = (path: string, body: string, headers: Record<string, string> = {}) =>
    send(api.port, {
      method: "POST",
      path,
      headers: { ...form, "x-introspection-secret": lab.secrets.introspection, ...headers },
      body,
    });

  it("ignores a token in the query string: a request with no token is {active:false}", async () => {
    expectJson(await post(`/auth/v1/introspect?token=${lab.token()}`, ""), 200, INACTIVE, { noStore: true });
  });
  it("ignores a query token even next to a body that carries a different, valid token", async () => {
    const queried = lab.token({ sub: "user_from_query" });
    const bodied = lab.token({ sub: "user_from_body" });
    const r = await post(`/auth/v1/introspect?token=${queried}`, `token=${bodied}`);
    assert.equal((r.json() as { sub: string }).sub, "user_from_body");
  });
  it("lets the body token fail even when the query token would have verified", async () => {
    expectJson(await post(`/auth/v1/introspect?token=${lab.token()}`, "token=garbage"), 200, INACTIVE, { noStore: true });
  });
  it("accepts the form content type with a charset parameter", async () => {
    const r = await post("/auth/v1/introspect", `token=${lab.token()}`, { "content-type": "application/x-www-form-urlencoded; charset=UTF-8" });
    assert.equal((r.json() as { active: boolean }).active, true);
  });
  it("does not read a token out of a JSON body", async () => {
    const r = await post("/auth/v1/introspect", JSON.stringify({ token: lab.token() }), { "content-type": "application/json" });
    expectJson(r, 200, INACTIVE, { noStore: true });
  });
  it("does not read a form body that declares no content type", async () => {
    const r = await send(api.port, {
      method: "POST",
      path: "/auth/v1/introspect",
      headers: { "x-introspection-secret": lab.secrets.introspection },
      body: `token=${lab.token()}`,
    });
    expectJson(r, 200, INACTIVE, { noStore: true });
  });
  it("answers {active:false} when the form body is malformed anywhere, even if a valid token came first", async () => {
    const good = lab.token();
    for (const body of [`token=${good}&bad=%zz`, `token=${good}&%=1`, `bad=%zz&token=${good}`]) {
      expectJson(await post("/auth/v1/introspect", body), 200, INACTIVE, { noStore: true });
    }
  });
  it("uses the first of several token parameters", async () => {
    const exp = nowSeconds() + 3600;
    const good = lab.token({ sub: "user_first", exp });
    expectJson(await post("/auth/v1/introspect", `token=${good}&token=garbage`), 200, active("user_first", "agent:reset", exp), { noStore: true });
    expectJson(await post("/auth/v1/introspect", `token=garbage&token=${good}`), 200, INACTIVE, { noStore: true });
  });
  it("answers inactive for an absent, empty or whitespace-only token", async () => {
    for (const body of ["", "token=", "other=1", "token=%20"]) {
      expectJson(await post("/auth/v1/introspect", body), 200, INACTIVE, { noStore: true });
    }
  });
  it("is POST-only: a GET is 405 so a token can never travel in a URL", async () => {
    const r = await send(api.port, { path: `/auth/v1/introspect?token=${lab.token()}`, headers: { "x-introspection-secret": lab.secrets.introspection } });
    assert.equal(r.status, 405);
    assert.equal(r.text, "");
  });
});

describe("the 8 KiB body cap", () => {
  const CAP = 8 * 1024;
  const padded = (total: number) => {
    const head = `token=${encodeURIComponent(lab.token())}&pad=`;
    return head + "a".repeat(total - head.length);
  };
  const post = (body: string) =>
    send(api.port, {
      method: "POST",
      path: "/auth/v1/introspect",
      headers: { "content-type": "application/x-www-form-urlencoded", "x-introspection-secret": lab.secrets.introspection },
      body,
    });

  it("accepts a body of exactly 8192 bytes", async () => {
    const body = padded(CAP);
    assert.equal(Buffer.byteLength(body), CAP);
    assert.equal(((await post(body)).json() as { active: boolean }).active, true);
  });
  it("answers {active:false}, not an error, for 8193 bytes, even though the token is valid and first", async () => {
    const body = padded(CAP + 1);
    assert.equal(Buffer.byteLength(body), CAP + 1);
    expectJson(await post(body), 200, INACTIVE, { noStore: true });
  });
  it("answers {active:false} for a 1 MiB body", async () => {
    expectJson(await post(padded(1024 * 1024)), 200, INACTIVE, { noStore: true });
  });
  it("answers {active:false} for a single oversized token", async () => {
    expectJson(await post(`token=${"a".repeat(CAP)}`), 200, INACTIVE, { noStore: true });
  });
});

describe("what verifies, and what is {active:false}", () => {
  const now = () => nowSeconds();
  const inactive = async (label: string, token: string) => {
    try {
      expectJson(await api.introspect(token), 200, INACTIVE, { noStore: true });
    } catch (err) {
      throw new Error(`token ${label} must introspect as {"active":false}: ${(err as Error).message}`);
    }
  };

  it("answers the exact shape for a good operator token and leaks no other claim", async () => {
    const exp = now() + 3600;
    const token = lab.token({
      sub: "user_abc",
      scope: "agent:reset fleet:control",
      exp,
      email: "someone@example.com",
      azp: "https://app.example",
      sid: "sess_123",
      org_id: "org_1",
      extra: { nested: true },
    });
    expectJson(await api.introspect(token), 200, active("user_abc", "agent:reset fleet:control", exp), { noStore: true });
  });

  it("derives kind from the sub prefix: user_ is operator, anything else machine, case-sensitively", async () => {
    const exp = now() + 3600;
    for (const sub of ["user_x", "user_", "mch_x", "user", "USER_x", "usr_x", "x", " user_x"]) {
      expectJson(await api.introspect(lab.token({ sub, exp })), 200, active(sub, "agent:reset", exp), { noStore: true });
    }
  });

  it("returns scope verbatim: irregular whitespace and odd characters are not normalised", async () => {
    const exp = now() + 3600;
    for (const scope of ["a  b\tc ", " lead", "trail ", "UPPER lower", "ünï:cøde", "x".repeat(2000)]) {
      expectJson(await api.introspect(lab.token({ scope, exp })), 200, active("user_contract_operator", scope, exp), { noStore: true });
    }
  });

  it("joins an array scope with single spaces, dropping non-strings", async () => {
    const exp = now() + 3600;
    const cases: Array<[unknown, string]> = [
      [["a:b", "c:d"], "a:b c:d"],
      [[], ""],
      [["only"], "only"],
      [["a", 1, null, "b", { x: 1 }, true], "a b"],
      [["a b", "c"], "a b c"],
    ];
    for (const [scope, want] of cases) {
      expectJson(await api.introspect(lab.token({ scope, exp })), 200, active("user_contract_operator", want, exp), { noStore: true });
    }
  });

  it("always sends scope, as an empty string when the claim is absent, null, a number or an object", async () => {
    const exp = now() + 3600;
    for (const claims of [{ scope: undefined }, { scope: null }, { scope: 7 }, { scope: { a: 1 } }, { scope: true }]) {
      const r = await api.introspect(lab.token({ ...claims, exp }));
      const body = r.json() as Record<string, unknown>;
      assert.ok("scope" in body, `scope key missing for ${JSON.stringify(claims)}`);
      expectJson(r, 200, active("user_contract_operator", "", exp), { noStore: true });
    }
  });

  it("reports exp as an integer, truncating a fractional claim", async () => {
    const whole = now() + 3600;
    const r = await api.introspect(lab.token({ exp: whole + 0.9 }));
    expectJson(r, 200, active("user_contract_operator", "agent:reset", whole), { noStore: true });
    assert.ok(Number.isInteger((r.json() as { exp: number }).exp));
  });

  it("accepts a token that expired inside the 60 s leeway and refuses one that expired outside it", async () => {
    const lapsed = now() - 30;
    expectJson(await api.introspect(lab.token({ exp: lapsed })), 200, active("user_contract_operator", "agent:reset", lapsed), { noStore: true });
    await inactive("expired 90 s ago", lab.token({ exp: now() - 90 }));
    await inactive("expired long ago", lab.token({ exp: now() - 86400 }));
  });

  it("applies the same leeway to nbf", async () => {
    const exp = now() + 3600;
    expectJson(await api.introspect(lab.token({ nbf: now() + 30, exp })), 200, active("user_contract_operator", "agent:reset", exp), { noStore: true });
    await inactive("nbf 120 s ahead", lab.token({ nbf: now() + 120 }));
  });

  it("does not check iat, aud, azp or typ", async () => {
    const exp = now() + 3600;
    const token = signJwt(
      { sub: "user_x", scope: "s", iat: now() + 7200, aud: "someone-else", azp: "https://elsewhere", exp },
      { key: lab.clerkKey.privateKey, header: { typ: "at+jwt", kid: "unrelated" } },
    );
    expectJson(await api.introspect(token), 200, active("user_x", "s", exp), { noStore: true });
  });

  it("answers {active:false} for tokens that are not acceptable", async () => {
    const exp = now() + 3600;
    const key = lab.clerkKey.privateKey;
    const claims = { sub: "user_x", scope: "agent:reset", exp };
    const bad: Record<string, string> = {
      "empty token": "",
      "garbage": "not-a-jwt",
      "two segments": "aaa.bbb",
      "four segments": `${lab.token()}.extra`,
      "foreign signature": lab.token(claims, lab.foreignKey),
      "alg none": unsignedJwt(claims),
      "HS256 keyed with the public key PEM": hs256Jwt(claims, lab.clerkKey.publicPem),
      "RS384 (alg is pinned to RS256)": signJwt(claims, { key, alg: "RS384" }),
      "RS512": signJwt(claims, { key, alg: "RS512" }),
      "PS256": signJwt(claims, { key, alg: "PS256" }),
      "no exp": signJwt({ sub: "user_x" }, { key }),
      "exp as a string": signJwt({ sub: "user_x", exp: String(exp) }, { key }),
      "no sub": signJwt({ scope: "agent:reset", exp }, { key }),
      "empty sub": signJwt({ sub: "", exp }, { key }),
      "numeric sub": signJwt({ sub: 42, exp }, { key }),
      "null sub": signJwt({ sub: null, exp }, { key }),
      "array sub": signJwt({ sub: ["user_x"], exp }, { key }),
      "tampered payload": (() => {
        const [h, , s] = lab.token(claims).split(".");
        return `${h}.${Buffer.from(JSON.stringify({ ...claims, sub: "user_admin" })).toString("base64url")}.${s}`;
      })(),
    };
    for (const [label, token] of Object.entries(bad)) {
      const r = await api.introspect(token);
      assert.deepEqual({ label, status: r.status, body: r.text }, { label, status: 200, body: '{"active":false}\n' });
      expectJson(r, 200, INACTIVE, { noStore: true });
    }
  });

  it("never says why: every failure is the same answer, byte for byte", async () => {
    const a = await api.introspect(lab.token({ exp: now() - 86400 }));
    const b = await api.introspect(lab.token({}, lab.foreignKey));
    const c = await api.introspect("garbage");
    assert.equal(a.text, b.text);
    assert.equal(b.text, c.text);
  });
});

describe("with CLERK_ISSUER set", () => {
  const ISS = "https://clerk.contract.example";
  let issued: Api;
  before(async () => {
    issued = await lab.start({ env: { CLERK_ISSUER: ISS } });
  });
  it("accepts a token whose iss matches", async () => {
    const exp = nowSeconds() + 3600;
    expectJson(await issued.introspect(lab.token({ iss: ISS, exp })), 200, active("user_contract_operator", "agent:reset", exp), { noStore: true });
  });
  it("refuses a missing iss and a different iss", async () => {
    expectJson(await issued.introspect(lab.token({})), 200, INACTIVE, { noStore: true });
    expectJson(await issued.introspect(lab.token({ iss: "https://evil.example" })), 200, INACTIVE, { noStore: true });
    expectJson(await issued.introspect(lab.token({ iss: `${ISS}/` })), 200, INACTIVE, { noStore: true });
  });
  it("does not check iss when CLERK_ISSUER is unset (the default lab)", async () => {
    const exp = nowSeconds() + 3600;
    expectJson(await api.introspect(lab.token({ iss: "https://anything.example", exp })), 200, active("user_contract_operator", "agent:reset", exp), {
      noStore: true,
    });
  });
});
