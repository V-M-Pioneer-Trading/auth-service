/**
 * The routes ported in this step (health, status), CORS, and the router table the contract suite pins as
 * gorilla/mux and net/http write it. supertest against the real app (testSupport/createTestApp.ts).
 */
import request from "supertest";

import { credential, createTestApp, NOW, TEST_ORIGIN, time } from "../testSupport/createTestApp";

const ALL_CORS = {
  "access-control-allow-origin": TEST_ORIGIN,
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization, X-Auth-Service-Secret",
};
const CORS_NAMES = Object.keys(ALL_CORS);

/** The headers the contract compares (lib/expect.ts PINNED), of a supertest response. */
const PINNED = ["content-type", "cache-control", "x-content-type-options", "location", "allow", "vary", "etag", "www-authenticate", "set-cookie", ...CORS_NAMES, "access-control-expose-headers", "access-control-allow-credentials", "access-control-max-age"];
const pinned = (headers: Record<string, unknown>): Record<string, unknown> => Object.fromEntries(Object.entries(headers).filter(([k]) => PINNED.includes(k)));

describe("health", () => {
  it.each(["/health", "/api/auth/health"])("GET %s is {status:ok} as application/json, with CORS and nothing else pinned", async (path) => {
    const res = await request(createTestApp()).get(path);
    expect(res.status).toBe(200);
    expect(res.text).toBe('{"status":"ok"}\n');
    expect(pinned(res.headers)).toEqual({ "content-type": "application/json", ...ALL_CORS });
  });

  it("does not look at a credential: a request with every kind of header is the same answer", async () => {
    const res = await request(createTestApp()).get("/health").set("Authorization", "Bearer x").set("X-Auth-Service-Secret", "y");
    expect(res.status).toBe(200);
  });
});

describe("GET /auth/v1/status and /api/auth/v1/status", () => {
  const both = ["/auth/v1/status", "/api/auth/v1/status"];

  it.each(both)("%s: no credential row is UNCONFIGURED, and nothing else is in the answer", async (path) => {
    const res = await request(createTestApp(undefined)).get(path);
    expect(res.status).toBe(200);
    expect(res.text).toBe('{"state":"UNCONFIGURED"}\n');
    expect(pinned(res.headers)).toEqual({ "content-type": "application/json", ...ALL_CORS });
  });

  it.each(both)("%s: HEALTHY with the symbol and the dates as Go formats them, and never a token", async (path) => {
    const row = credential({ resetDate: time("2026-09-28T14:00:00+02:00"), nextPredictedReset: time("2026-10-12T03:04:05.987Z") });
    const res = await request(createTestApp(row)).get(path);
    expect(JSON.parse(res.text)).toEqual({ state: "HEALTHY", agentSymbol: "AGENT_ONE", resetDate: "2026-09-28T14:00:00+02:00", nextPredictedReset: "2026-10-12T03:04:05Z" });
    expect(res.text).not.toMatch(/token/i);
    // Key order is Go's struct order.
    expect(res.text).toBe('{"state":"HEALTHY","agentSymbol":"AGENT_ONE","resetDate":"2026-09-28T14:00:00+02:00","nextPredictedReset":"2026-10-12T03:04:05Z"}\n');
  });

  it("omits what is unknown instead of sending null or an empty string", async () => {
    const res = await request(createTestApp(credential({ agentSymbol: "" }))).get("/auth/v1/status");
    expect(res.text).toBe('{"state":"HEALTHY"}\n');
  });

  it("omits a date that is Go's zero time", async () => {
    const res = await request(createTestApp(credential({ resetDate: time("0001-01-01T00:00:00Z"), nextPredictedReset: time("0001-01-01T01:00:00+01:00") }))).get("/auth/v1/status");
    expect(res.text).toBe('{"state":"HEALTHY","agentSymbol":"AGENT_ONE"}\n');
  });

  it("is WIPE_IMMINENT from 24 h before the predicted reset, and stays so after it has passed", async () => {
    const next = "2026-10-05T12:00:00Z"; // NOW + 24 h exactly
    const at = async (nowMs: number): Promise<string> => {
      const res = await request(createTestApp(credential({ nextPredictedReset: time(next) }), { now: () => nowMs })).get("/auth/v1/status");
      return (JSON.parse(res.text) as { state: string }).state;
    };
    expect(await at(NOW - 1)).toBe("HEALTHY");
    expect(await at(NOW)).toBe("WIPE_IMMINENT");
    expect(await at(Date.parse(next) + 3_600_000)).toBe("WIPE_IMMINENT");
    expect(await at(Date.parse(next) + 30 * 86_400_000)).toBe("WIPE_IMMINENT");
  });

  it("is APP_TOKEN_EXPIRED when the flag is set, which outranks WIPE_IMMINENT", async () => {
    const res = await request(createTestApp(credential({ tokenExpired: true, nextPredictedReset: time("2026-10-04T13:00:00Z") }))).get("/auth/v1/status");
    expect((JSON.parse(res.text) as { state: string }).state).toBe("APP_TOKEN_EXPIRED");
  });

  it("is public: no header is needed, and a bad one is not looked at", async () => {
    const res = await request(createTestApp(credential())).get("/auth/v1/status").set("Authorization", "garbage");
    expect(res.status).toBe(200);
  });

  it("answers a failed read as Go's http.Error: 500, text/plain, the sentence and a newline", async () => {
    const store = {
      get: (): never => {
        throw new Error("disk on fire");
      },
    };
    const res = await request(createTestApp(undefined, { store })).get("/auth/v1/status");
    expect(res.status).toBe(500);
    expect(res.text).toBe("failed to load status: disk on fire\n");
    expect(res.headers["content-type"]).toBe("text/plain; charset=utf-8");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("reads the store on every request: the answer follows the row", async () => {
    let row = credential();
    const app = createTestApp(undefined, { store: { get: () => row } });
    expect(JSON.parse((await request(app).get("/auth/v1/status")).text)).toMatchObject({ state: "HEALTHY" });
    row = credential({ tokenExpired: true });
    expect(JSON.parse((await request(app).get("/auth/v1/status")).text)).toMatchObject({ state: "APP_TOKEN_EXPIRED" });
  });
});

describe("routes not ported yet are not registered", () => {
  it.each([
    ["GET", "/auth/v1/token"],
  ])("%s %s is the router's bare 405, as it is for a wrong method", async (method, path) => {
    const app = createTestApp(credential());
    const res = await (method === "GET" ? request(app).get(path) : request(app).post(path));
    expect(res.status).toBe(405);
    expect(res.text).toBe("");
  });

  it.each(["/api/auth/v1/agent-token", "/api/auth/v1/register"])("POST %s is a 404 until it is registered", async (path) => {
    const res = await request(createTestApp(credential())).post(path);
    expect(res.status).toBe(404);
  });
});

describe("CORS and OPTIONS", () => {
  it.each(["/health", "/nonexistent", "/", "/auth/v1/token", "/auth/v1/introspect", "/api/auth/v1/register", "/api/auth/nope", "/health/", "/api/auth/v1/token"])("OPTIONS %s is 204, the three CORS headers, no body", async (path) => {
    const res = await request(createTestApp()).options(path);
    expect(res.status).toBe(204);
    expect(res.text).toBe("");
    expect(pinned(res.headers)).toEqual(ALL_CORS);
  });

  it("never reflects the request's Origin, never sends credentials, max-age, Vary or Expose-Headers", async () => {
    for (const origin of ["https://evil.example", "null", TEST_ORIGIN]) {
      const res = await request(createTestApp()).get("/health").set("Origin", origin);
      expect(res.headers["access-control-allow-origin"]).toBe(TEST_ORIGIN);
      for (const name of ["access-control-allow-credentials", "access-control-max-age", "vary", "access-control-expose-headers"]) expect(res.headers[name]).toBeUndefined();
    }
  });

  it("does not allow the introspection or M2M secret headers cross-origin (no browser caller)", async () => {
    const res = await request(createTestApp()).options("/auth/v1/introspect").set("Access-Control-Request-Headers", "x-introspection-secret, x-m2m-caller-secret");
    expect(String(res.headers["access-control-allow-headers"]).toLowerCase()).toBe("content-type, authorization, x-auth-service-secret");
  });
});

describe("the router's own answers", () => {
  it.each([
    ["POST", "/health"],
    ["PUT", "/auth/v1/status"],
    ["DELETE", "/health"],
    ["GET", "/"],
    ["GET", "/nope"],
    ["GET", "/health/"],
    ["GET", "/Health"],
    ["GET", "/auth/v1/STATUS"],
    ["GET", "/api/Auth/health"],
    ["POST", "/api"],
  ])("%s %s outside /api/auth is a bare 405: empty body, no Allow, no CORS", async (method, path) => {
    const res = await request(createTestApp())[method === "GET" ? "get" : method === "POST" ? "post" : method === "PUT" ? "put" : "delete"](path);
    expect(res.status).toBe(405);
    expect(res.text).toBe("");
    expect(pinned(res.headers)).toEqual({});
  });

  it.each([
    ["POST", "/api/auth/health"],
    ["POST", "/api/auth/v1/status"],
    ["GET", "/api/auth/v1/agent-token"],
    ["GET", "/api/auth"],
    ["GET", "/api/auth/"],
    ["GET", "/api/auth/nope"],
    ["GET", "/api/auth/v1/token"],
    ["GET", "/api/authx/health"],
    ["GET", "/api/auth/health/"],
    ["GET", "/api/auth/v1/register/"],
  ])("%s %s under /api/auth is 404 page not found, text/plain, nosniff, no CORS", async (method, path) => {
    const app = createTestApp();
    const res = await (method === "GET" ? request(app).get(path) : request(app).post(path));
    expect(res.status).toBe(404);
    expect(res.text).toBe("404 page not found\n");
    expect(pinned(res.headers)).toEqual({ "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" });
  });

  it("the one exception under /api/auth: the wrong method on /api/auth/v1/register is a bare 405", async () => {
    for (const method of ["get", "put", "delete", "head"] as const) {
      const res = await request(createTestApp())[method]("/api/auth/v1/register");
      expect(res.status).toBe(405);
      expect(res.text).toBeFalsy();
      expect(pinned(res.headers)).toEqual({});
    }
  });

  it("HEAD is never served, not even on a GET route: 405 on bare routes, 404 (with its headers, no body) under /api/auth", async () => {
    for (const path of ["/health", "/auth/v1/status", "/auth/v1/token"]) {
      const res = await request(createTestApp(credential())).head(path);
      expect(res.status).toBe(405);
      expect(pinned(res.headers)).toEqual({});
    }
    for (const path of ["/api/auth/health", "/api/auth/v1/status"]) {
      const res = await request(createTestApp(credential())).head(path);
      expect(res.status).toBe(404);
      expect(res.text).toBeFalsy();
      expect(pinned(res.headers)).toEqual({ "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" });
    }
  });
});

describe("path cleaning and encoding", () => {
  it.each([
    ["GET", "//health", "/health"],
    ["GET", "/health//", "/health/"],
    ["GET", "/a/../health", "/health"],
    ["GET", "/./health", "/health"],
    ["GET", "/auth/v1/../health", "/auth/health"],
    ["GET", "/auth/v1/status/.", "/auth/v1/status"],
    ["GET", "//api/auth/health", "/api/auth/health"],
    ["GET", "/api/auth//health", "/api/auth/health"],
    ["POST", "//auth/v1/introspect", "/auth/v1/introspect"],
    ["OPTIONS", "//health", "/health"],
  ])("%s %s is a 301 to %s: empty, Location only, no CORS", async (method, path, location) => {
    const app = createTestApp();
    const res = await request(app)[method.toLowerCase() as "get" | "post" | "options"](path);
    expect(res.status).toBe(301);
    expect(res.text).toBe("");
    expect(pinned(res.headers)).toEqual({ location });
  });

  it("keeps the query on a redirect", async () => {
    const res = await request(createTestApp()).get("//health?x=1&y=%20");
    expect(res.headers.location).toBe("/health?x=1&y=%20");
  });

  it("routes on the decoded path (and a query changes nothing)", async () => {
    for (const path of ["/%68ealth", "/api/auth%2Fhealth", "/api%2Fauth/health", "/health?", "/health?x=1&y=2", "/auth/v1/status?%zz"]) {
      const res = await request(createTestApp(credential())).get(path);
      expect(res.status).toBe(200);
    }
  });

  it("answers a malformed percent escape with a bare 400 and closes the connection", async () => {
    const res = await request(createTestApp()).get("/health/%zz");
    expect(res.status).toBe(400);
    expect(res.text).toBe("400 Bad Request");
    expect(res.headers.connection).toBe("close");
  });
});

describe("the log", () => {
  it("is one line per request, the decoded path only: a token mistakenly sent in a query string never reaches it", async () => {
    const lines: string[] = [];
    const app = createTestApp(credential(), { log: (line) => void lines.push(line) });
    await request(app).get("/health");
    await request(app).post("/auth/v1/introspect?token=eyJ.query-token-sentinel.sig");
    await request(app).get("/%68ealth?access_token=secret-sentinel");
    expect(lines).toEqual(["GET request: to /health", "POST request: to /auth/v1/introspect", "GET request: to /health"]);
  });

  it("cannot be forged by a path with a newline in it", async () => {
    const lines: string[] = [];
    const app = createTestApp(credential(), { log: (line) => void lines.push(line) });
    await request(app).get("/x%0a2026/01/01 00:00:00 forged");
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain("\n");
    expect(lines[0]).toContain("\\x0a");
  });
});

describe("what the app sets and does not", () => {
  it("sends no X-Powered-By and no ETag (Express' defaults would fail the contract)", async () => {
    const res = await request(createTestApp(credential())).get("/auth/v1/status");
    expect(res.headers["x-powered-by"]).toBeUndefined();
    expect(res.headers.etag).toBeUndefined();
  });
});
