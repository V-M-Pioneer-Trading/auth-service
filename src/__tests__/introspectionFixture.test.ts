/**
 * Conformance against meta/fixtures/introspection.json, vendored verbatim into contract/fixtures/ (provenance and the sha256 pin
 * in contract/fixtures/SOURCE.txt): the port of the Go service's src/api/introspection_fixture_test.go, case for case.
 *
 * The fixture's `cases` and `gatewayCases` describe what a CALLING SERVICE answers its own caller, which this service
 * does not implement: it is the center. What binds it is the `contract` block (path, method, content type, body
 * template, the secret header's spelling, the env var names) and every `center` object inside every case: those
 * bodies are literally this service's own output. So every case in both groups is walked, and the real route (the
 * real verifier, a real signed token) is driven for each center answer the center can produce; the answer is compared
 * with the fixture's own body, structurally (same keys, same values). Cases whose `center` is client-side transport (a
 * delay, a dead socket, a 500, an HTML body) are classified, counted, and the classification itself is asserted, so a
 * case added to meta that this file does not understand fails the run instead of quietly checking less.
 */
import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import request from "supertest";

import { createVerifier, kindOf } from "../jwt/verify";
import { INTROSPECTION_SECRET_HEADER } from "../introspection";
import { createTestApp, NOW } from "../testSupport/createTestApp";

interface FixtureCase {
  name: string;
  request: { authorization?: unknown };
  center: { notCalled?: boolean; status?: number; body?: string; delayMs?: number; transport?: string };
}
interface Fixture {
  version: number;
  contract: {
    endpoint: { method: string; path: string; contentType: string; bodyTemplate: string; secretHeader: string };
    env: { url: string; secret: string };
  };
  cases: FixtureCase[];
  gatewayCases: FixtureCase[];
}
interface CenterBody {
  active: boolean;
  sub?: string;
  scope?: string;
  exp?: number;
  kind?: string;
}

// The one copy in the repository is the contract suite's (contract/fixtures): its sha256 pin is in SOURCE.txt beside it.
const FIXTURES = join(__dirname, "..", "..", "contract", "fixtures");
const raw = readFileSync(join(FIXTURES, "introspection.json"));
const fixture = JSON.parse(raw.toString("utf8")) as Fixture;

const SECRET = "fixture-introspection-secret";
const key = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const app = createTestApp(undefined, { introspection: { secret: SECRET, verifier: createVerifier({ key: createPublicKey(key), issuer: "" }) } });
const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");

/** What the Go test's signTestToken writes: sub, scope (always present), iat, exp. */
function signToken(sub: string, scope: string, exp: number): string {
  const claims = { sub, scope, iat: Math.floor(NOW / 1000), exp };
  const input = `${b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${b64u(JSON.stringify(claims))}`;
  return `${input}.${b64u(sign("sha256", Buffer.from(input), key))}`;
}

async function introspect(token: string, secret: string, path = fixture.contract.endpoint.path): Promise<request.Response> {
  return request(app).post(path).set("Content-Type", "application/x-www-form-urlencoded").set(INTROSPECTION_SECRET_HEADER, secret).send(new URLSearchParams({ token }).toString());
}

/** Structural equality of two JSON documents; the answer may carry no key the expectation does not. */
function expectBodyEquals(got: string, want: string): void {
  expect(JSON.parse(got)).toStrictEqual(JSON.parse(want));
}

type CenterClass = "notApplicable" | "active" | "inactive" | "callerSecret" | "clientOnly" | "activeNoScopeKey" | "ambiguousKeys";

/** request.authorization: a string is one header line, null/absent none, an array (version 4) one per line. Anything else fails. */
function authorizationLines(a: unknown): string[] {
  if (a === undefined || a === null) return [];
  if (typeof a === "string") return [a];
  if (Array.isArray(a) && a.every((x) => typeof x === "string")) return a;
  throw new Error(`request.authorization is neither a string, null nor an array of strings: ${JSON.stringify(a)}`);
}

/** The raw top-level members of a JSON object body, in order, repeats included (JSON.parse would collapse them). */
function topLevelMembers(body: string): [string, string][] | null {
  const members: [string, string][] = [];
  let i = 0;
  const ws = (): void => {
    while (/\s/.test(body[i] ?? "")) i++;
  };
  /** The end of the JSON value starting at i (strings, nesting). */
  const skipValue = (): void => {
    let depth = 0;
    let inString = false;
    for (; i < body.length; i++) {
      const c = body[i];
      if (inString) {
        if (c === "\\") i++;
        else if (c === '"') inString = false;
        if (!inString && depth === 0) {
          i++;
          return;
        }
        continue;
      }
      if (c === '"') inString = true;
      else if (c === "{" || c === "[") depth++;
      else if (c === "}" || c === "]") {
        if (depth === 0) return;
        depth--;
        if (depth === 0) {
          i++;
          return;
        }
      } else if (c === "," && depth === 0) return;
    }
  };
  ws();
  if (body[i] !== "{") return null;
  i++;
  for (;;) {
    ws();
    if (body[i] === "}") return members;
    if (body[i] !== '"') return null;
    const keyStart = i;
    skipValue();
    const key = JSON.parse(body.slice(keyStart, i)) as string;
    ws();
    if (body[i] !== ":") return null;
    i++;
    ws();
    const valueStart = i;
    skipValue();
    members.push([key, body.slice(valueStart, i).trim()]);
    ws();
    if (body[i] === ",") i++;
  }
}

const CONTRACT_KEYS = new Set(["active", "sub", "scope", "exp", "kind"]);

/** The first top-level key a client must refuse the body over: a repeat ignoring case, or a contract key miscased. */
function ambiguousTopLevelKey(body: string): string | null {
  const members = topLevelMembers(body);
  if (members === null) return null;
  const seen = new Set<string>();
  for (const [k] of members) {
    const folded = k.toLowerCase();
    if (seen.has(folded) || (CONTRACT_KEYS.has(folded) && k !== folded)) return k;
    seen.add(folded);
  }
  return null;
}

/** The well-formed twin: the first occurrence of each key ignoring case kept, a miscased contract key respelled, values as written. */
function unambiguousTwin(body: string): string {
  const members = topLevelMembers(body);
  if (members === null) throw new Error(`body is not a JSON object: ${body}`);
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const [k, v] of members) {
    const folded = k.toLowerCase();
    if (seen.has(folded)) continue;
    seen.add(folded);
    parts.push(`${JSON.stringify(CONTRACT_KEYS.has(folded) ? folded : k)}:${v}`);
  }
  return `{${parts.join(",")}}`;
}

/** Go's json.Unmarshal into the contract struct, which matches keys case-insensitively, keeps the last, and ignores the rest. */
function decodeCenterBody(body: string): CenterBody | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const out: Record<string, unknown> = { active: false };
  for (const [k, v] of topLevelMembers(body) ?? []) {
    const folded = k.toLowerCase();
    if (CONTRACT_KEYS.has(folded)) out[folded] = JSON.parse(v) as unknown;
  }
  return out as unknown as CenterBody;
}

function classify(c: FixtureCase): [CenterClass, CenterBody | null] {
  if (c.center.notCalled === true) return ["notApplicable", null];
  if ((c.center.transport ?? "") !== "" || (c.center.delayMs ?? 0) > 0) return ["clientOnly", null];
  if (c.center.status === 401) return ["callerSecret", null];
  if (c.center.status !== 200) return ["clientOnly", null];
  const body = decodeCenterBody(c.center.body ?? "");
  if (body === null) return ["clientOnly", null];
  if (ambiguousTopLevelKey(c.center.body ?? "") !== null) return ["ambiguousKeys", body];
  if (!body.active) return ["inactive", null];
  const keys = JSON.parse(c.center.body ?? "{}") as Record<string, unknown>;
  if (!("scope" in keys)) return ["activeNoScopeKey", body];
  return ["active", body];
}

const all = [...fixture.cases, ...fixture.gatewayCases];

describe("the vendored fixture is the exact copy it claims to be", () => {
  it("hashes to the sha256 recorded in contract/fixtures/SOURCE.txt", () => {
    const source = readFileSync(join(FIXTURES, "SOURCE.txt"), "utf8");
    const recorded = /^\s*sha256:\s*([0-9a-f]{64})\s*$/m.exec(source)?.[1];
    expect(recorded).toMatch(/^[0-9a-f]{64}$/);
    // A CRLF checkout would hash differently: .gitattributes keeps it -text.
    expect(raw.includes("\r\n")).toBe(false);
    expect(createHash("sha256").update(raw).digest("hex")).toBe(recorded);
  });

  it("is version 6", () => {
    expect(fixture.version).toBe(6);
  });

  it("has exactly the case names this file was written against", () => {
    expect(all.map((c) => c.name).sort()).toEqual(
      [
        "active-machine-kind", "active-with-irregular-scope-whitespace", "active-with-multi-value-scope", "active-with-non-separators-in-scope",
        "active-with-only-spaces-in-scope", "active-with-required-scope", "active-with-scope-differing-only-in-case",
        "active-with-scope-that-is-a-prefix-of-required", "active-without-required-scope", "bearer-with-empty-token", "bearer-with-internal-whitespace",
        "center-rejects-our-caller-secret", "center-returns-500", "center-returns-case-variant-duplicate-key", "center-returns-contract-key-in-another-case",
        "center-returns-duplicate-key", "center-returns-malformed-json", "center-times-out", "center-unreachable", "gateway-active-machine",
        "gateway-active-operator", "gateway-active-operator-lacking-scope-key", "gateway-bearer-with-empty-token",
        "gateway-center-rejects-our-caller-secret", "gateway-center-returns-case-variant-duplicate-key", "gateway-center-returns-duplicate-key",
        "gateway-center-unreachable", "gateway-inactive-token", "gateway-kind-machine-with-user-subject", "gateway-kind-operator-with-machine-subject",
        "gateway-no-header", "gateway-non-bearer-scheme", "gateway-two-authorization-lines", "head-on-guarded-route-with-no-header",
        "head-on-guarded-route-with-valid-token", "head-on-public-get", "inactive-token-on-guarded-route", "inactive-token-on-public-get",
        "kind-disagrees-with-sub-prefix", "lowercase-bearer-scheme", "lowercase-route-method", "mutating-route-with-no-declared-scope",
        "mutating-route-with-no-declared-scope-and-inactive-token", "mutating-route-with-no-declared-scope-and-no-header", "no-header-on-guarded-route",
        "non-bearer-scheme-on-guarded-route", "operator-on-public-get", "options-on-guarded-route-with-no-header", "options-with-no-declared-scope",
        "scope-joined-by-em-space", "scope-joined-by-form-feed", "scope-joined-by-no-break-space", "scope-joined-by-several-spaces",
        "scope-joined-by-tab", "scope-joined-by-vertical-tab", "scoped-route-with-token-lacking-scope-key", "session-route-with-inactive-token",
        "session-route-with-no-header", "session-route-with-scopeless-token", "session-route-with-token-lacking-scope-key",
        "token-on-public-get-while-center-is-down", "two-authorization-lines", "two-authorization-lines-on-public-get",
        "two-authorization-lines-second-empty", "visitor-on-public-get",
      ].sort(),
    );
  });
});

describe("the fixture's contract names are the route's", () => {
  it("method, header, content type, body template, env var, and the path (by using it)", async () => {
    const e = fixture.contract.endpoint;
    expect(e.method).toBe("POST");
    expect(e.secretHeader).toBe(INTROSPECTION_SECRET_HEADER);
    expect(e.contentType).toBe("application/x-www-form-urlencoded");
    expect(e.bodyTemplate).toBe("token=<jwt>");
    expect(fixture.contract.env.secret).toBe("AUTH_INTROSPECTION_SECRET");
    const res = await introspect(signToken("user_x", "agent:reset", 4102444800), SECRET, e.path);
    expect((JSON.parse(res.text) as { active: boolean }).active).toBe(true);
  });
});

describe("the center produces every fixture response it can", () => {
  const counts: Record<CenterClass, number> = { notApplicable: 0, active: 0, inactive: 0, callerSecret: 0, clientOnly: 0, activeNoScopeKey: 0, ambiguousKeys: 0 };
  let multiLine = 0;
  const runs: [string, () => Promise<void>][] = [];

  expect(fixture.cases).toHaveLength(51);
  expect(fixture.gatewayCases).toHaveLength(14);

  for (const c of all) {
    const [cls, want] = classify(c);
    counts[cls]++;
    const lines = authorizationLines(c.request.authorization);
    if (lines.length > 1) {
      multiLine++;
      // More than one Authorization line is no credential: the client never calls the center.
      if (cls !== "notApplicable") throw new Error(`case ${c.name} sends ${String(lines.length)} Authorization lines but the fixture says the center answers`);
    }
    const status = c.center.status ?? 0;
    const body = c.center.body ?? "";
    switch (cls) {
      case "notApplicable":
      case "clientOnly":
        break;
      case "activeNoScopeKey":
        // Unproducible by construction (version 3): the center always sends `scope`. For the same token its real
        // answer is the fixture body plus "scope":"".
        runs.push([`${c.name}/active-center-adds-scope-key`, async () => {
          const doc = JSON.parse(body) as Record<string, unknown>;
          expect("scope" in doc).toBe(false);
          const res = await introspect(signToken(want?.sub ?? "", "", want?.exp ?? 0), SECRET);
          expect(res.status).toBe(status);
          expectBodyEquals(res.text, JSON.stringify({ ...doc, scope: "" }));
        }]);
        break;
      case "ambiguousKeys":
        // Unproducible by construction (versions 5 and 6): the center marshals a fixed shape. For a token carrying the
        // twin's claims its answer is the twin.
        runs.push([`${c.name}/center-produces-the-well-formed-twin`, async () => {
          const twin = unambiguousTwin(body);
          expect(twin).not.toBe(body);
          expect(ambiguousTopLevelKey(twin)).toBeNull();
          const first = JSON.parse(twin) as CenterBody;
          expect(first.active && (first.sub ?? "") !== "").toBe(true);
          const res = await introspect(signToken(first.sub ?? "", first.scope ?? "", first.exp ?? 0), SECRET);
          expect(res.status).toBe(status);
          expectBodyEquals(res.text, twin);
        }]);
        break;
      case "inactive":
        // The fixture's tokens are deliberately not JWTs: one sent verbatim gets exactly this body.
        runs.push([`${c.name}/inactive`, async () => {
          const res = await introspect("expired.token.one", SECRET);
          expect(res.status).toBe(status);
          expectBodyEquals(res.text, body);
        }]);
        break;
      case "callerSecret":
        runs.push([`${c.name}/caller-secret`, async () => {
          const res = await introspect("anything", "the-wrong-secret");
          expect(res.status).toBe(status);
          expectBodyEquals(res.text, body);
        }]);
        break;
      case "active":
        runs.push([`${c.name}/active`, async () => {
          if (want === null) throw new Error("an active case has a body");
          const expected = { ...want };
          // kind is derived from the sub prefix, so the cases that deliberately disagree with themselves are
          // unproducible here; the assertion becomes "the center answers the derived kind".
          const derived = kindOf(expected.sub ?? "");
          const kindAgrees = expected.kind === derived;
          const res = await introspect(signToken(expected.sub ?? "", expected.scope ?? "", expected.exp ?? 0), SECRET);
          expect(res.status).toBe(status);
          // Where the pairing is producible, the fixture's OWN body, never one re-marshalled by the code under test.
          if (kindAgrees) expectBodyEquals(res.text, body);
          else expectBodyEquals(res.text, JSON.stringify({ active: true, sub: expected.sub, scope: expected.scope, exp: expected.exp, kind: derived }));
        }]);
        break;
    }
  }

  it("classifies every case, with the totals the Go test asserts", () => {
    expect(counts).toEqual({ notApplicable: 21, active: 24, activeNoScopeKey: 3, inactive: 4, callerSecret: 2, ambiguousKeys: 5, clientOnly: 6 });
    expect(multiLine).toBe(4);
  });

  it.each(runs)("%s", async (_name, run) => {
    await run();
  });
});
