// Routing, CORS, HEAD, OPTIONS, unknown routes and trailing slashes. These are
// the least principled parts of the contract (they are what gorilla/mux happens
// to do) and exactly the parts a port gets wrong silently, so the whole table is
// pinned rather than sampled.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { corsHeaders, expectEmpty, expectJson, expectText, pinnedHeaders } from "../lib/expect.ts";
import { send } from "../lib/http.ts";
import { Lab } from "../lib/lab.ts";
import type { Api } from "../lib/lab.ts";

let lab: Lab;
let api: Api;

before(async () => {
  lab = await Lab.create();
  api = await lab.start();
});
after(async () => {
  await lab?.close();
});

const NOT_OPTIONS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"];

/**
 * What a request gets when its method (or its whole path) is not served:
 *   405  empty body, no headers of note, no CORS
 *   404  "404 page not found\n" as text/plain, no CORS (HEAD: same headers, no body)
 *
 * Every path outside /api/auth falls to the catch-all OPTIONS route, which makes
 * the router answer 405 for any method but OPTIONS, whether or not the path
 * exists. Inside /api/auth the sub-router answers 404 instead, except for
 * /api/auth/v1/register, which answers 405. That is not a rule anyone chose: it
 * is the table, and it is the contract.
 */
const SERVED: Array<{ path: string; serves: string[]; otherwise: 404 | 405 }> = [
  { path: "/health", serves: ["GET"], otherwise: 405 },
  { path: "/auth/v1/token", serves: ["GET"], otherwise: 405 },
  { path: "/auth/v1/introspect", serves: ["POST"], otherwise: 405 },
  { path: "/auth/v1/m2m-token", serves: ["POST"], otherwise: 405 },
  { path: "/auth/v1/status", serves: ["GET"], otherwise: 405 },
  { path: "/api/auth/health", serves: ["GET"], otherwise: 404 },
  { path: "/api/auth/v1/status", serves: ["GET"], otherwise: 404 },
  { path: "/api/auth/v1/agent-token", serves: ["POST"], otherwise: 404 },
  { path: "/api/auth/v1/register", serves: ["POST"], otherwise: 405 },
  // Paths that are not routes at all:
  { path: "/", serves: [], otherwise: 405 },
  { path: "/nope", serves: [], otherwise: 405 },
  { path: "/auth", serves: [], otherwise: 405 },
  { path: "/auth/v1", serves: [], otherwise: 405 },
  { path: "/auth/v1/nope", serves: [], otherwise: 405 },
  { path: "/api", serves: [], otherwise: 405 },
  { path: "/api/auth", serves: [], otherwise: 404 },
  { path: "/api/auth/", serves: [], otherwise: 404 },
  { path: "/api/auth/nope", serves: [], otherwise: 404 },
  { path: "/api/auth/v1", serves: [], otherwise: 404 },
  { path: "/api/auth/v1/", serves: [], otherwise: 404 },
  { path: "/api/auth/v1/nope", serves: [], otherwise: 404 },
  { path: "/api/auth/v1/token", serves: [], otherwise: 404 },
  { path: "/api/auth/v1/introspect", serves: [], otherwise: 404 },
  { path: "/api/auth/v1/m2m-token", serves: [], otherwise: 404 },
  { path: "/api/authx/health", serves: [], otherwise: 404 },
  { path: "/auth/health", serves: [], otherwise: 405 },
  { path: "/auth/v1/health", serves: [], otherwise: 405 },
  { path: "/api/health", serves: [], otherwise: 405 },
  { path: "/api/auth/v1/health", serves: [], otherwise: 404 },
  // Trailing slash, case and look-alike paths are different paths:
  { path: "/health/", serves: [], otherwise: 405 },
  { path: "/auth/v1/token/", serves: [], otherwise: 405 },
  { path: "/auth/v1/status/", serves: [], otherwise: 405 },
  { path: "/auth/v1/introspect/", serves: [], otherwise: 405 },
  { path: "/auth/v1/m2m-token/", serves: [], otherwise: 405 },
  { path: "/Health", serves: [], otherwise: 405 },
  { path: "/auth/v1/STATUS", serves: [], otherwise: 405 },
  { path: "/api/Auth/health", serves: [], otherwise: 405 },
  { path: "/api/auth/health/", serves: [], otherwise: 404 },
  { path: "/api/auth/v1/status/", serves: [], otherwise: 404 },
  { path: "/api/auth/v1/register/", serves: [], otherwise: 404 },
  { path: "/api/auth/v1/agent-token/", serves: [], otherwise: 404 },
];

describe("methods and paths that are not served", () => {
  for (const { path, serves, otherwise } of SERVED) {
    it(`${path}: ${serves.length ? `serves ${serves.join("/")}, ` : ""}everything else is ${otherwise}${otherwise === 404 ? " [go-text]" : ""}`, async () => {
      for (const method of NOT_OPTIONS.filter((m) => !serves.includes(m))) {
        const r = await send(api.port, {
          method,
          path,
          headers: { "x-auth-service-secret": lab.secrets.shared, authorization: `Bearer ${lab.token()}` },
          body: method === "GET" || method === "HEAD" ? undefined : "{}",
        });
        const where = `${method} ${path}`;
        if (otherwise === 405) {
          assert.deepEqual({ where, status: r.status, text: r.text, headers: pinnedHeaders(r) }, { where, status: 405, text: "", headers: {} });
        } else if (method === "HEAD") {
          assert.deepEqual(
            { where, status: r.status, text: r.text, headers: pinnedHeaders(r) },
            { where, status: 404, text: "", headers: { "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" } },
          );
        } else {
          assert.equal(r.status, 404, where);
          expectText(r, 404, "404 page not found\n", { cors: false });
        }
      }
    });
  }
});

describe("HEAD is never served, not even on GET routes", () => {
  it("answers 405 (bare routes) or 404 (/api/auth routes) with no body and no CORS", async () => {
    for (const path of ["/health", "/auth/v1/status", "/auth/v1/token"]) {
      expectEmpty(await send(api.port, { method: "HEAD", path, headers: { "x-auth-service-secret": lab.secrets.shared } }), 405, { cors: false });
    }
    for (const path of ["/api/auth/health", "/api/auth/v1/status"]) {
      const r = await send(api.port, { method: "HEAD", path });
      assert.equal(r.status, 404);
      assert.equal(r.text, "");
    }
  });
});

describe("OPTIONS and CORS", () => {
  it("answers every OPTIONS request 204 with the CORS headers and nothing else, on any path", async () => {
    const paths = ["/health", "/nonexistent", "/", "/auth/v1/token", "/auth/v1/introspect", "/auth/v1/m2m-token", "/api/auth/v1/register", "/api/auth/v1/agent-token", "/api/auth/nope", "/health/", "/api/auth/health/", "/api/auth/v1/token"];
    for (const path of paths) {
      const r = await send(api.port, { method: "OPTIONS", path });
      expectEmpty(r, 204);
      assert.equal(r.header("content-length") ?? "0", "0", path);
    }
  });

  it("is open to any caller: no credentials needed, and a preflight's own request headers change nothing", async () => {
    const r = await send(api.port, {
      method: "OPTIONS",
      path: "/api/auth/v1/register",
      headers: {
        origin: "https://evil.example",
        "access-control-request-method": "DELETE",
        "access-control-request-headers": "x-anything, x-m2m-caller-secret, x-introspection-secret",
      },
    });
    expectEmpty(r, 204);
  });

  it("always answers with the one configured origin: never reflects the request's Origin, never sends credentials, max-age or Vary", async () => {
    for (const origin of ["https://evil.example", "null", DEFAULT_ORIGIN_FOR_TEST, ""]) {
      const r = await send(api.port, { path: "/health", headers: origin ? { origin } : {} });
      expectJson(r, 200, { status: "ok" });
      assert.equal(r.header("access-control-allow-origin"), "http://localhost:3000");
      for (const h of ["access-control-allow-credentials", "access-control-max-age", "vary", "access-control-expose-headers"]) {
        assert.equal(r.header(h), undefined, h);
      }
    }
  });

  it("does not allow the introspection or M2M secret headers cross-origin (no browser caller)", async () => {
    const r = await send(api.port, { method: "OPTIONS", path: "/auth/v1/introspect" });
    const allowed = (r.header("access-control-allow-headers") ?? "").toLowerCase();
    assert.equal(allowed, "content-type, authorization, x-auth-service-secret");
    assert.doesNotMatch(allowed, /m2m|introspection/);
  });

  it("carries CORS on handler responses of every status, and on none of the router's own 404/405/301", async () => {
    expectJson(await send(api.port, { path: "/health" }), 200, { status: "ok" });
    const r401 = await send(api.port, { method: "POST", path: "/auth/v1/m2m-token" });
    assert.deepEqual(
      Object.entries(corsHeaders()).filter(([k]) => r401.header(k) === undefined),
      [],
    );
    assert.equal((await send(api.port, { path: "/nope" })).header("access-control-allow-origin"), undefined);
    assert.equal((await send(api.port, { path: "//health" })).header("access-control-allow-origin"), undefined);
  });

  it("takes the allowed origin from CORS_ALLOWED_ORIGIN", async () => {
    const custom = await lab.start({ env: { CORS_ALLOWED_ORIGIN: "https://dashboard.contract.example" } });
    for (const r of [await custom.get("/health"), await send(custom.port, { method: "OPTIONS", path: "/health" })]) {
      assert.equal(r.header("access-control-allow-origin"), "https://dashboard.contract.example");
      assert.equal(r.header("access-control-allow-methods"), "GET, POST, OPTIONS");
      assert.equal(r.header("access-control-allow-headers"), "Content-Type, Authorization, X-Auth-Service-Secret");
    }
    await custom.stop();
  });

  it("treats an empty CORS_ALLOWED_ORIGIN as unset: the default is http://localhost:3000", async () => {
    const empty = await lab.start({ env: { CORS_ALLOWED_ORIGIN: "" } });
    assert.equal((await empty.get("/health")).header("access-control-allow-origin"), "http://localhost:3000");
    await empty.stop();
  });
});

const DEFAULT_ORIGIN_FOR_TEST = "http://localhost:3000";

describe("path cleaning and encoding", () => {
  const redirects: Array<[string, string, string]> = [
    ["GET", "//health", "/health"],
    ["GET", "/health//", "/health/"],
    ["GET", "/a/../health", "/health"],
    ["GET", "/./health", "/health"],
    ["GET", "/auth/v1/../health", "/auth/health"],
    ["GET", "/auth/v1/status/.", "/auth/v1/status"],
    ["GET", "//api/auth/health", "/api/auth/health"],
    ["GET", "/api/auth//health", "/api/auth/health"],
    ["GET", "/api/auth/./health", "/api/auth/health"],
    ["POST", "//auth/v1/introspect", "/auth/v1/introspect"],
    ["OPTIONS", "//health", "/health"],
  ];
  for (const [method, path, location] of redirects) {
    it(`${method} ${path} is a 301 to ${location}, answered before any route runs`, async () => {
      const r = await send(api.port, { method, path });
      expectEmpty(r, 301, { cors: false, headers: { location } });
    });
  }

  it("routes on the decoded path", async () => {
    for (const path of ["/%68ealth", "/api/auth%2Fhealth", "/api%2Fauth/health", "/health?", "/health?x=1&y=2"]) {
      expectJson(await send(api.port, { path }), 200, { status: "ok" });
    }
  });
});
