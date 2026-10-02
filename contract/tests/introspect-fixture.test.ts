// Every case of the vendored fixture, driven through the running service.
//
// The fixture describes what a CALLING SERVICE answers its own caller; this
// service is the CENTER. What binds it is the `contract` block and every
// `center` object: those bodies are this service's own output. Each case is
// accounted for (produced, or classified as not the center's to produce) and the
// totals are pinned, so a case added to the fixture fails the run instead of
// quietly being checked less.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { firstOccurrenceTwin, fixtureSha256, hasDuplicateKey, loadFixture, recordedSha256 } from "../lib/fixture.ts";
import type { FixtureCase } from "../lib/fixture.ts";
import { expectJson } from "../lib/expect.ts";
import { send } from "../lib/http.ts";
import { Lab } from "../lib/lab.ts";
import type { Api } from "../lib/lab.ts";

const fixture = loadFixture();
let lab: Lab;
let api: Api;

before(async () => {
  lab = await Lab.create();
  api = await lab.start();
});
after(async () => {
  await lab?.close();
});

describe("the vendored fixture is the copy it claims to be", () => {
  it("hashes to the sha256 recorded in SOURCE.txt", () => {
    assert.equal(
      fixtureSha256(),
      recordedSha256(),
      "src/api/testdata/introspection.json drifted from meta: re-copy it and update SOURCE.txt (and check .gitattributes still marks it -text)",
    );
  });
  it("is version 5 with 41 + 13 cases", () => {
    assert.equal(fixture.version, 5);
    assert.equal(fixture.cases.length, 41);
    assert.equal(fixture.gatewayCases.length, 13);
  });
});

type Class = "notCalled" | "active" | "activeNoScopeKey" | "inactive" | "callerSecret" | "duplicateKey" | "clientOnly";

function classify(c: FixtureCase): Class {
  const k = c.center;
  if (k.notCalled) return "notCalled";
  if (k.transport || (k.delayMs ?? 0) > 0) return "clientOnly";
  if (k.status === 401) return "callerSecret";
  if (k.status !== 200) return "clientOnly";
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(k.body ?? "") as Record<string, unknown>;
  } catch {
    return "clientOnly"; // a 200 that is not the contract (the HTML body)
  }
  if (hasDuplicateKey(k.body ?? "")) return "duplicateKey";
  if (doc.active !== true) return "inactive";
  return "scope" in doc ? "active" : "activeNoScopeKey";
}

function bearerToken(c: FixtureCase): string {
  const a = c.request.authorization;
  assert.equal(typeof a, "string", `${c.name}: expected a single authorization line`);
  return (a as string).replace(/^bearer /i, "");
}

const kindOf = (sub: string) => (sub.startsWith("user_") ? "operator" : "machine");

const all = [...fixture.cases, ...fixture.gatewayCases];
const counts: Record<Class, number> = { notCalled: 0, active: 0, activeNoScopeKey: 0, inactive: 0, callerSecret: 0, duplicateKey: 0, clientOnly: 0 };
const ep = fixture.contract.endpoint;

async function callCenter(token: string, secret: string): Promise<ReturnType<typeof send>> {
  return send(api.port, {
    method: ep.method,
    path: ep.path,
    headers: { "content-type": ep.contentType, [ep.secretHeader]: secret },
    body: ep.bodyTemplate.replace("<jwt>", encodeURIComponent(token)),
  });
}

describe("every fixture case, answered by the center", () => {
  for (const c of all) {
    const cls = classify(c);
    counts[cls]++;
    const label = `${c.name} [${cls}]`;

    switch (cls) {
      case "notCalled":
      case "clientOnly":
        // Nothing for the center to produce. Counted below so this cannot swallow a case that should run.
        it(label, { skip: "the center is not asked, or this is client-side transport: accounted for in the totals below" }, () => {});
        break;

      case "inactive":
        it(label, async () => {
          // The fixture's tokens are deliberately not JWTs; send one verbatim.
          const r = await callCenter(bearerToken(c), lab.secrets.introspection);
          expectJson(r, c.center.status as number, JSON.parse(c.center.body as string), { noStore: true });
        });
        break;

      case "callerSecret":
        it(label, async () => {
          const r = await callCenter("anything", "the-wrong-secret");
          expectJson(r, 401, JSON.parse(c.center.body as string), { noStore: true });
        });
        break;

      case "active":
      case "activeNoScopeKey":
        it(label, async () => {
          const want = JSON.parse(c.center.body as string) as { sub: string; scope?: string; exp: number; kind: string };
          const token = lab.token({ sub: want.sub, scope: want.scope ?? "", exp: want.exp });
          const r = await callCenter(token, lab.secrets.introspection);
          // `scope` is ALWAYS present from the center, "" when absent in the fixture body.
          // `kind` is derived from the `sub` prefix, so a case whose fixture kind disagrees
          // with its sub (kind-disagrees-with-sub-prefix and mirrors) can only be answered
          // with the derived kind: the center owns that rule.
          const expected = { ...want, scope: want.scope ?? "", kind: kindOf(want.sub) };
          if (cls === "active" && want.kind !== kindOf(want.sub)) {
            assert.notEqual(expected.kind, want.kind, "case should be the one where the fixture disagrees with itself");
          }
          expectJson(r, 200, expected, { noStore: true });
        });
        break;

      case "duplicateKey":
        it(label, async () => {
          // The center writes a well-formed object, never a repeated key: for a token carrying the
          // FIRST `sub` its answer is the fixture body with the repeat removed.
          const twin = firstOccurrenceTwin(c.center.body as string) as { sub: string; scope: string; exp: number };
          const token = lab.token({ sub: twin.sub, scope: twin.scope, exp: twin.exp });
          const r = await callCenter(token, lab.secrets.introspection);
          expectJson(r, 200, { ...twin, kind: kindOf(twin.sub) }, { noStore: true });
        });
        break;
    }
  }

  it("the classification totals are exactly the ones this suite was written against", () => {
    assert.deepEqual(counts, {
      notCalled: 21, // incl. 4 multi-line Authorization cases
      active: 16,
      activeNoScopeKey: 3, // client-only: the center always sends `scope`
      inactive: 4,
      callerSecret: 2,
      duplicateKey: 2,
      clientOnly: 6, // transport failures, a 500, an HTML body
    });
  });

  it("uses the fixture's own contract block", () => {
    assert.equal(ep.method, "POST");
    assert.equal(ep.path, "/auth/v1/introspect");
    assert.equal(ep.secretHeader, "X-Introspection-Secret");
    assert.equal(ep.contentType, "application/x-www-form-urlencoded");
    assert.equal(ep.bodyTemplate, "token=<jwt>");
    assert.equal(fixture.contract.env.secret, "AUTH_INTROSPECTION_SECRET");
  });
});
