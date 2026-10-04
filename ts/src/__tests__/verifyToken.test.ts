/**
 * The verifier held to the Go service's own verifyToken: every token of src/testSupport/jwtCases.ts (signed with keys
 * made for this run) answered exactly as Go answered it (recorded in fixtures/go-verdicts.json, "jwt"), except the
 * named deviations, where Go is active and this service is not. Then the rejection classes one by one, readably.
 */
import { createHmac, createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";

import { CLOCK_SKEW_LEEWAY_SECONDS, createVerifier, goExpiryValid, kindOf, scopeString, type Verifier } from "../jwt/verify";
import { JWT_CASES_ISSUER, JWT_CASES_NOW_MS, jwtCaseKeys, jwtCases, type JwtCaseKey } from "../testSupport/jwtCases";
import verdicts from "./fixtures/go-verdicts.json";

const keys = jwtCaseKeys();
const cases = jwtCases(keys);
const goAnswers = verdicts.jwt.answers as Record<string, string>;

const verifiers = new Map<string, Verifier>();
function verifierFor(key: JwtCaseKey, issuer: string): Verifier {
  const id = `${key} ${issuer}`;
  let v = verifiers.get(id);
  if (v === undefined) {
    v = createVerifier({ key: createPublicKey(keys[key]), issuer });
    verifiers.set(id, v);
  }
  return v;
}

/** The introspection body this service answers for a token, as an object. */
async function answer(token: string, key: JwtCaseKey = "main", issuer = "", nowMs = JWT_CASES_NOW_MS): Promise<Record<string, unknown>> {
  const verified = await verifierFor(key, issuer)(token, nowMs);
  if (verified === null) return { active: false };
  return { active: true, sub: verified.subject, scope: verified.scope, exp: verified.expiry, kind: kindOf(verified.subject) };
}

describe("every recorded token, against Go's verifyToken", () => {
  it("was recorded at the clock the cases are built for", () => {
    expect(verdicts.jwt.nowMs).toBe(JWT_CASES_NOW_MS);
  });

  it("has a recorded Go answer for every case, and no stale one", () => {
    expect(Object.keys(goAnswers).sort()).toEqual(cases.map((c) => c.name).sort());
  });

  it("covers both verdicts generously", () => {
    const active = Object.values(goAnswers).filter((a) => (JSON.parse(a) as { active: boolean }).active).length;
    expect(active).toBeGreaterThan(70);
    expect(cases.length - active).toBeGreaterThan(80);
  });

  it.each(cases.filter((c) => c.deviation === undefined).map((c) => [c.name, c] as const))("%s: answered as Go answers it", async (_name, c) => {
    expect(await answer(c.token, c.key, c.issuer)).toEqual(JSON.parse(goAnswers[c.name] ?? "null"));
  });

  it.each(cases.filter((c) => c.deviation !== undefined).map((c) => [c.name, c] as const))("%s: a named deviation, inactive where Go is active", async (_name, c) => {
    expect((JSON.parse(goAnswers[c.name] ?? "null") as { active: boolean }).active).toBe(true);
    expect(await answer(c.token, c.key, c.issuer)).toEqual({ active: false });
  });

  it("deviates in exactly these cases, every one fail-closed", () => {
    expect(cases.filter((c) => c.deviation !== undefined).map((c) => c.name)).toEqual([
      "payload-invalid-utf8-in-sub",
      "nbf-plus-60.5",
      "nbf-1e300",
      "iat-string",
      "iat-null",
      "small-key-1024-bit",
      "crit-unknown-extension",
      "crit-unknown-absent-parameter",
      "crit-empty-array",
      "crit-a-string",
      "crit-b64-false",
    ]);
  });
});

// Readable versions of the classes the issue names, each from a token built here.
const N = Math.floor(JWT_CASES_NOW_MS / 1000);
const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");
function token(claims: Record<string, unknown>, opts: { key?: KeyObject; header?: Record<string, unknown> } = {}): string {
  const input = `${b64u(JSON.stringify({ alg: "RS256", typ: "JWT", ...opts.header }))}.${b64u(JSON.stringify(claims))}`;
  return `${input}.${b64u(sign("sha256", Buffer.from(input), opts.key ?? keys.main))}`;
}
const good = { sub: "user_x", scope: "agent:reset", exp: N + 3600 };
const inactive = { active: false };

describe("the rejection classes", () => {
  it("accepts the good token, so that every refusal below is about its one change", async () => {
    expect(await answer(token(good))).toEqual({ active: true, sub: "user_x", scope: "agent:reset", exp: N + 3600, kind: "operator" });
  });

  it("refuses the wrong algorithm: none, and HS256 keyed with the public key's PEM", async () => {
    const claims = b64u(JSON.stringify(good));
    expect(await answer(`${b64u(JSON.stringify({ alg: "none" }))}.${claims}.`)).toEqual(inactive);
    const pem = createPublicKey(keys.main).export({ type: "spki", format: "pem" }).toString();
    const input = `${b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${claims}`;
    expect(await answer(`${input}.${b64u(createHmac("sha256", pem).update(input).digest())}`)).toEqual(inactive);
  });

  it("refuses the wrong key, whatever key material the header carries", async () => {
    expect(await answer(token(good, { key: keys.foreign }))).toEqual(inactive);
    const jwk = createPublicKey(keys.foreign).export({ format: "jwk" });
    expect(await answer(token(good, { key: keys.foreign, header: { jwk } }))).toEqual(inactive);
    expect(await answer(token(good, { key: keys.foreign, header: { jku: "https://evil.example/jwks.json" } }))).toEqual(inactive);
  });

  it("refuses an exp and an nbf beyond the 60 s leeway, and accepts them inside it", async () => {
    expect(CLOCK_SKEW_LEEWAY_SECONDS).toBe(60);
    expect((await answer(token({ ...good, exp: N - 30 }))).active).toBe(true);
    expect(await answer(token({ ...good, exp: N - 90 }))).toEqual(inactive);
    expect((await answer(token({ ...good, nbf: N + 30 }))).active).toBe(true);
    expect(await answer(token({ ...good, nbf: N + 90 }))).toEqual(inactive);
  });

  it("refuses a token with no exp, or a non-numeric one", async () => {
    expect(await answer(token({ sub: "user_x" }))).toEqual(inactive);
    expect(await answer(token({ sub: "user_x", exp: String(N + 3600) }))).toEqual(inactive);
  });

  it("refuses a wrong or missing issuer when CLERK_ISSUER is set, and ignores iss when it is not", async () => {
    expect((await answer(token({ ...good, iss: JWT_CASES_ISSUER }), "main", JWT_CASES_ISSUER)).active).toBe(true);
    expect(await answer(token({ ...good, iss: "https://evil.example" }), "main", JWT_CASES_ISSUER)).toEqual(inactive);
    expect(await answer(token(good), "main", JWT_CASES_ISSUER)).toEqual(inactive);
    expect((await answer(token({ ...good, iss: "https://evil.example" }))).active).toBe(true);
  });

  it("refuses a malformed token", async () => {
    for (const bad of ["", "garbage", "a.b", "a.b.c", `${token(good)}.x`, ` ${token(good)}`, token(good).replace(/\.[^.]+$/, ".AAAA")]) {
      expect(await answer(bad)).toEqual(inactive);
    }
  });

  it("refuses a non-empty-string sub", async () => {
    for (const sub of [undefined, "", 42, null, ["user_x"]]) expect(await answer(token({ ...good, sub }))).toEqual(inactive);
  });

  it("refuses an unknown crit header (decision 23: Go accepts it; this is the accepted deviation)", async () => {
    expect(await answer(token(good, { header: { crit: ["x-unknown"], "x-unknown": 1 } }))).toEqual(inactive);
    expect(await answer(token(good, { header: { crit: ["exp"], exp: 1 } }))).toEqual(inactive);
  });

  it("refuses every token when the configured key is under 2048 bits (jose's floor; Go has none)", async () => {
    const small = generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey;
    const v = createVerifier({ key: createPublicKey(small), issuer: "" });
    expect(await v(token(good, { key: small }), JWT_CASES_NOW_MS)).toBeNull();
  });

  it("never throws: a verifier error is a null", async () => {
    const v = createVerifier({ key: createPublicKey(keys.main), issuer: "" });
    await expect(v(token(good), Number.NaN)).resolves.toBeNull();
  });
});

describe("pieces", () => {
  it("derives kind from the sub prefix, case-sensitively", () => {
    expect(kindOf("user_")).toBe("operator");
    expect(kindOf("user_abc")).toBe("operator");
    for (const sub of ["user", "USER_x", " user_x", "mch_x", ""]) expect(kindOf(sub)).toBe("machine");
  });

  it("joins an array scope with single spaces, dropping non-strings, and passes a string through", () => {
    expect(scopeString("a  b\tc ")).toBe("a  b\tc ");
    expect(scopeString(["a", 1, null, "b", { c: 1 }])).toBe("a b");
    expect(scopeString(["a b", " c"])).toBe("a b  c");
    for (const v of [undefined, null, 7, true, { a: 1 }]) expect(scopeString(v)).toBe("");
  });

  it("judges exp with Go's whole seconds and its 60 s leeway", () => {
    const now = N * 1000 + 500;
    expect(goExpiryValid(N - 59, now)).toBe(N - 59);
    expect(goExpiryValid(N - 60, now)).toBeNull();
    expect(goExpiryValid(N - 59.5, now)).toBeNull();
    expect(goExpiryValid(N + 0.9, now)).toBe(N);
    expect(goExpiryValid(0, now)).toBeNull();
    expect(goExpiryValid("1", now)).toBeNull();
    expect(goExpiryValid(2 ** 63, now)).toBeNull();
  });
});
