/**
 * The vault's routes over HTTP, against the real app, the real verifier, the real SQLite store and the real poller,
 * with st-gateway stubbed: GET /auth/v1/token (the secret gate, the forced poll, no-store), the session gate on the
 * operator routes, Restore Token, Reset Agent, and that no credential reaches a log line, a status answer or an error
 * body. Raw sockets where supertest would hide what is on the wire (two headers of one name).
 */
import type * as nodeCrypto from "node:crypto";
import { createPublicKey, generateKeyPairSync, sign, timingSafeEqual } from "node:crypto";
import net from "node:net";
import type { AddressInfo } from "node:net";
import type { DatabaseSync } from "node:sqlite";
import request from "supertest";

import { getCredential, sqliteVaultStore, type VaultStore } from "../db/credential";
import { openInMemory } from "../db/database";
import { createVerifier } from "../jwt/verify";
import { Poller } from "../poller";
import { createHttpServer } from "../server";
import { TransportError, UpstreamError } from "../spacetraders/client";
import { createTestApp, credential, NOW, TEST_ORIGIN, time } from "../testSupport/createTestApp";
import { FakeUpstream, rootOf } from "../testSupport/fakeUpstream";
import { afterUnauthorized, bearerFrom, MAX_OPERATOR_BODY, splitScopes, vaultSecretOk, type VaultDeps } from "../vault";

jest.setTimeout(30000);

// The real timingSafeEqual, watched: the vault secret must go through it (Go compared with !=; decision 23).
jest.mock("node:crypto", () => {
  const actual = jest.requireActual<typeof nodeCrypto>("node:crypto");
  return { ...actual, timingSafeEqual: jest.fn((a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) => actual.timingSafeEqual(a, b)) };
});

const SHARED = "vault-shared-secret-for-tests";
const INTROSPECTION = "introspection-secret-for-tests";
const key = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const foreign = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const NOW_S = Math.floor(NOW / 1000);
const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");
function jwt(claims: Record<string, unknown> = {}, signer = key): string {
  const input = `${b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${b64u(JSON.stringify({ sub: "user_test", scope: "agent:reset", exp: NOW_S + 3600, ...claims }))}`;
  return `${input}.${b64u(sign("sha256", Buffer.from(input), signer))}`;
}

const CORS = {
  "access-control-allow-origin": TEST_ORIGIN,
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization, X-Auth-Service-Secret",
};

const REGISTERED = credential({
  accountToken: "account-token-sentinel",
  agentToken: "agent-token-sentinel",
  agentSymbol: "CONTRACT-1",
  faction: "COSMIC",
  email: "pilot@example.com",
  resetDate: time("2026-09-01T00:00:00Z"),
  nextPredictedReset: time("2099-01-01T00:00:00Z"),
});

interface World {
  app: ReturnType<typeof createTestApp>;
  db: DatabaseSync;
  store: VaultStore;
  upstream: FakeUpstream;
  poller: Poller;
  logs: string[];
  monotonic: { now: number };
}

const pollers: Poller[] = [];
afterEach(async () => {
  for (const p of pollers.splice(0)) await p.stop();
});

function world(row: typeof REGISTERED | null = REGISTERED): World {
  const db = openInMemory();
  const store = sqliteVaultStore(db);
  if (row !== null) store.upsert(row, NOW);
  const upstream = new FakeUpstream();
  const logs: string[] = [];
  const log = (line: string): void => void logs.push(line);
  const monotonic = { now: 0 };
  const poller = new Poller({ store, upstream, log, now: () => NOW, monotonic: () => monotonic.now });
  pollers.push(poller);
  const vault: VaultDeps = { sharedSecret: SHARED, store, poller, log };
  const app = createTestApp(undefined, {
    store,
    log,
    vault,
    introspection: { secret: INTROSPECTION, verifier: createVerifier({ key: createPublicKey(key), issuer: "" }) },
  });
  return { app, db, store, upstream, poller, logs, monotonic };
}

const token = (w: World, secret: string | null = SHARED, query = "") => {
  const r = request(w.app).get(`/auth/v1/token${query}`);
  return secret === null ? r : r.set("X-Auth-Service-Secret", secret);
};

function expectEnvelope(res: request.Response, status: number, message: string): void {
  expect(res.status).toBe(status);
  expect(res.headers["content-type"]).toBe("application/json");
  expect(res.headers["cache-control"]).toBe("no-store");
  for (const [k, v] of Object.entries(CORS)) expect(res.headers[k]).toBe(v);
  expect(res.text).toBe(`${JSON.stringify({ error: { message } })}\n`);
}

function expectText(res: request.Response, status: number, text: string | RegExp): void {
  expect(res.status).toBe(status);
  expect(res.headers["content-type"]).toBe("text/plain; charset=utf-8");
  expect(res.headers["x-content-type-options"]).toBe("nosniff");
  expect(res.headers["cache-control"]).toBeUndefined();
  if (typeof text === "string") expect(res.text).toBe(text);
  else expect(res.text).toMatch(text);
}

function expectJson(res: request.Response, status: number, body: unknown, cacheControl?: string): void {
  expect(res.status).toBe(status);
  expect(res.headers["content-type"]).toBe("application/json");
  expect(res.headers["cache-control"]).toBe(cacheControl);
  for (const [k, v] of Object.entries(CORS)) expect(res.headers[k]).toBe(v);
  expect(JSON.parse(res.text)).toEqual(body);
}

/** One raw request; the answer's status line and body. */
async function raw(app: ReturnType<typeof createTestApp>, head: string, body = ""): Promise<{ status: number; text: string }> {
  const server = createHttpServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await new Promise((resolve, reject) => {
      const socket = net.connect((server.address() as AddressInfo).port, "127.0.0.1", () => {
        socket.write(`${head}Connection: close\r\n\r\n${body}`);
      });
      let data = "";
      socket.on("data", (d: Buffer) => (data += d.toString("latin1")));
      socket.on("error", reject);
      socket.on("close", () => {
        const [statusLine = "", ...rest] = data.split("\r\n");
        resolve({ status: Number(statusLine.split(" ")[1]), text: rest.join("\r\n").split("\r\n\r\n").slice(1).join("\r\n\r\n") });
      });
    });
  } finally {
    server.close();
  }
}

describe("GET /auth/v1/token: the shared secret", () => {
  it("answers the agent token, and only that, with CORS and no Cache-Control (as Go; the contract pins the absence)", async () => {
    const w = world();
    expectJson(await token(w), 200, { agentToken: "agent-token-sentinel" });
  });

  it.each([
    ["wrong", "wrong"],
    ["empty", ""],
    ["upper-cased", SHARED.toUpperCase()],
    ["one byte longer", `${SHARED}x`],
    ["one byte shorter", SHARED.slice(0, -1)],
    ["the introspection secret", INTROSPECTION],
  ])("is 403, the envelope and no-store for a %s secret", async (_name, secret) => {
    expectEnvelope(await token(world(), secret), 403, "invalid or missing shared secret");
  });

  it("is 403 without the header, with a Clerk session, and with the secret in the query string", async () => {
    const w = world();
    expectEnvelope(await token(w, null), 403, "invalid or missing shared secret");
    expectEnvelope(await request(w.app).get("/auth/v1/token").set("Authorization", `Bearer ${jwt()}`), 403, "invalid or missing shared secret");
    expectEnvelope(await token(w, null, `?secret=${SHARED}&x-auth-service-secret=${SHARED}`), 403, "invalid or missing shared secret");
  });

  it("reads the first of two secret headers, as Go's Header.Get does", async () => {
    const w = world();
    const first = await raw(w.app, `GET /auth/v1/token HTTP/1.1\r\nHost: x\r\nX-Auth-Service-Secret: ${SHARED}\r\nX-Auth-Service-Secret: wrong\r\n`);
    expect(first.status).toBe(200);
    const second = await raw(w.app, `GET /auth/v1/token HTTP/1.1\r\nHost: x\r\nX-Auth-Service-Secret: wrong\r\nX-Auth-Service-Secret: ${SHARED}\r\n`);
    expect(second.status).toBe(403);
  });

  it("ignores surrounding spaces and tabs in the header value", async () => {
    expect((await raw(world().app, `GET /auth/v1/token HTTP/1.1\r\nHost: x\r\nX-Auth-Service-Secret:   ${SHARED} \t\r\n`)).status).toBe(200);
  });

  it("is 503 text while nothing is stored, and while the stored token is empty, in every state", async () => {
    expectText(await token(world(null)), 503, "no agent token configured\n");
    expectText(await token(world(credential({ agentToken: "" }))), 503, "no agent token configured\n");
    expectJson(await token(world(credential({ tokenExpired: true }))), 200, { agentToken: "agent-token-sentinel" });
  });

  it("is 500 text, naming no credential, when the row cannot be read", async () => {
    const w = world();
    jest.spyOn(w.store, "get").mockImplementation(() => {
      throw new Error("database disk image is malformed");
    });
    const res = await token(w);
    expectText(res, 500, "failed to load credential: Error: database disk image is malformed\n");
  });

  it("is not mounted under /api/auth, at any method (decision 9)", async () => {
    const w = world();
    for (const method of ["get", "post"] as const) {
      const res = await request(w.app)[method]("/api/auth/v1/token").set("X-Auth-Service-Secret", SHARED);
      expect(res.status).toBe(404);
      expect(res.text).toBe("404 page not found\n");
    }
  });

  it("compares in constant time: timingSafeEqual over two SHA-256 digests, whatever the lengths", () => {
    const spy = jest.mocked(timingSafeEqual);
    spy.mockClear();
    expect(vaultSecretOk("configured", "x")).toBe(false);
    expect(vaultSecretOk("configured", "configured")).toBe(true);
    expect(spy).toHaveBeenCalledTimes(2);
    for (const [a, b] of spy.mock.calls) {
      expect((a as Buffer).length).toBe(32);
      expect((b as Buffer).length).toBe(32);
    }
  });

  it("matches nothing when no secret is configured, an empty or absent header included", () => {
    expect(vaultSecretOk("", "")).toBe(false);
    expect(vaultSecretOk("", undefined)).toBe(false);
    expect(vaultSecretOk("s", undefined)).toBe(false);
  });
});

describe("GET /auth/v1/token?afterUnauthorized=true: the forced poll", () => {
  it("reads the flag as Go's URL.Query().Get does: the exact value true, the first value, the query's errors ignored", () => {
    for (const yes of ["/t?afterUnauthorized=true", "/t?x=1&afterUnauthorized=true&y=2", "/t?afterUnauthorized=true&afterUnauthorized=false", "/t?a=%zz&afterUnauthorized=true", "/t?afterUnauthorized=tru%65"]) {
      expect([yes, afterUnauthorized(yes)]).toEqual([yes, true]);
    }
    for (const no of ["/t", "/t?afterUnauthorized=false", "/t?afterUnauthorized=TRUE", "/t?afterUnauthorized=1", "/t?afterUnauthorized=", "/t?afterUnauthorized", "/t?AfterUnauthorized=true", "/t?afterunauthorized=true", "/t?x=afterUnauthorized%3Dtrue", "/t?afterUnauthorized=false&afterUnauthorized=true", "/t?afterUnauthorized=true;x=1", "/t?afterUnauthorized=true%"]) {
      expect([no, afterUnauthorized(no)]).toEqual([no, false]);
    }
  });

  it("polls before it answers: an unchanged resetDate flags the token, which is still served", async () => {
    const w = world();
    expectJson(await token(w, SHARED, "?afterUnauthorized=true"), 200, { agentToken: "agent-token-sentinel" });
    expect(w.upstream.rootCalls).toHaveLength(1);
    expect(getCredential(w.db)?.tokenExpired).toBe(true);
    expect(JSON.parse((await request(w.app).get("/auth/v1/status")).text)).toMatchObject({ state: "APP_TOKEN_EXPIRED" });
  });

  it("answers the NEW token when the poll finds a wipe", async () => {
    const w = world();
    w.upstream.root = () => Promise.resolve(rootOf("2026-09-15", "2099-02-01T00:00:00Z"));
    expectJson(await token(w, SHARED, "?afterUnauthorized=true"), 200, { agentToken: "agent-token-1" });
  });

  it("does not poll without the exact flag, nor for a caller without the secret", async () => {
    const w = world();
    await token(w, SHARED, "?afterUnauthorized=TRUE");
    await token(w, "wrong", "?afterUnauthorized=true");
    await token(w, null, "?afterUnauthorized=true");
    expect(w.upstream.rootCalls).toHaveLength(0);
  });

  it("logs a failed poll, without upstream's text, and answers what is stored", async () => {
    const w = world();
    w.upstream.root = () => Promise.reject(new UpstreamError(500, "GET /", Buffer.from("upstream-body-sentinel")));
    expectJson(await token(w, SHARED, "?afterUnauthorized=true"), 200, { agentToken: "agent-token-sentinel" });
    expect(w.logs.filter((l) => !l.startsWith("GET request"))).toEqual(["forced poll after 401 failed: spacetraders upstream error (500) on GET /"]);
  });

  it("goes through once per 10 s, the window shared by every caller", async () => {
    const w = world();
    await Promise.all(Array.from({ length: 8 }, () => token(w, SHARED, "?afterUnauthorized=true")));
    expect(w.upstream.rootCalls).toHaveLength(1);
    w.monotonic.now += 10_000;
    await token(w, SHARED, "?afterUnauthorized=true");
    expect(w.upstream.rootCalls).toHaveLength(2);
  });
});

describe("the session gate on the operator routes", () => {
  const paths = ["/api/auth/v1/agent-token", "/api/auth/v1/register"];
  const post = (w: World, path: string, authorization?: string, body = '{"agentToken":"x","accountToken":"a","symbol":"S","faction":"F"}') => {
    const r = request(w.app).post(path).set("Content-Type", "application/json");
    return (authorization === undefined ? r : r.set("Authorization", authorization)).send(body);
  };

  it.each(paths)("%s: 401 'a bearer token is required' for no usable bearer credential", async (path) => {
    const w = world();
    for (const authorization of [undefined, "", "Bearer", "Bearer ", "Basic dXNlcjpwYXNz", "Token abc", `Bearer ${jwt()} extra`, jwt()]) {
      expectEnvelope(await post(w, path, authorization), 401, "a bearer token is required");
    }
    expect(w.upstream.registerCalls).toHaveLength(0);
  });

  it.each(paths)("%s: 401 'invalid or expired session' for anything that does not verify", async (path) => {
    const w = world();
    for (const t of ["garbage", jwt({ exp: NOW_S - 3600 }), jwt({}, foreign), jwt({ sub: undefined })]) {
      expectEnvelope(await post(w, path, `Bearer ${t}`), 401, "invalid or expired session");
    }
  });

  it.each(paths)("%s: 403 for a valid session without agent:reset as a whole word", async (path) => {
    const w = world();
    for (const scope of [undefined, "", "fleet:control", "agent:resetx", "AGENT:RESET", "agent:reset:read", "fleet:control\u000bagent:reset", "fleet:control agent:reset", null, 5]) {
      expectEnvelope(await post(w, path, `Bearer ${jwt({ scope })}`), 403, "this action requires a scope this session does not carry");
    }
    expect(w.upstream.registerCalls).toHaveLength(0);
  });

  it("lets through the scope among others, split on space, tab, CR and LF, or in an array; the scheme in any case", async () => {
    const w = world();
    for (const [scheme, scope] of [
      ["Bearer", "fleet:control agent:reset"],
      ["bearer", "fleet:control\tagent:reset"],
      ["BEARER", "fleet:control\r\nagent:reset"],
      ["Bearer", "  agent:reset  "],
      ["Bearer", ["fleet:control", "agent:reset"]],
    ] as const) {
      expectJson(await post(w, "/api/auth/v1/agent-token", `${scheme}   ${jwt({ scope })}`), 200, { status: "restored" });
    }
  });

  it("reads the credential as clerk-client's bearerFrom does (the owner's decision on #15)", () => {
    expect(bearerFrom("Bearer abc")).toBe("abc");
    expect(bearerFrom("  bearer \t abc  ")).toBe("abc");
    expect(bearerFrom("Bearer abc")).toBe("abc");
    expect(bearerFrom("Bearer abc def")).toBeNull();
    expect(bearerFrom("Bearer")).toBeNull();
    expect(bearerFrom("Bearer a, Bearer b")).toBeNull();
    expect(bearerFrom("Basic abc")).toBeNull();
    expect(bearerFrom(undefined)).toBeNull();
    expect(splitScopes("a\u000bb c d\te\r\nf")).toEqual(["a\u000bb", "c d", "e", "f"]);
  });

  it("decides on the first of two Authorization headers", async () => {
    const w = world();
    const head = (a: string, b: string): string =>
      `POST /api/auth/v1/agent-token HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 18\r\nAuthorization: ${a}\r\nAuthorization: ${b}\r\n`;
    expect((await raw(w.app, head(`Bearer ${jwt()}`, "Bearer garbage"), '{"agentToken":"x"}')).status).toBe(200);
    expect((await raw(w.app, head("Bearer garbage", `Bearer ${jwt()}`), '{"agentToken":"x"}')).status).toBe(401);
  });

  it("does not take the token from the query string", async () => {
    const w = world();
    const res = await request(w.app).post(`/api/auth/v1/agent-token?token=${jwt()}&access_token=${jwt()}`).send('{"agentToken":"x"}');
    expectEnvelope(res, 401, "a bearer token is required");
  });

  it("authenticates before it reads the body", async () => {
    const w = world();
    expectEnvelope(await post(w, "/api/auth/v1/register", undefined, "{not json"), 401, "a bearer token is required");
    expectEnvelope(await post(w, "/api/auth/v1/agent-token", `Bearer ${jwt({ scope: "nope" })}`, "{not json"), 403, "this action requires a scope this session does not carry");
    expectEnvelope(await post(w, "/api/auth/v1/register", "Bearer garbage", "{not json"), 401, "invalid or expired session");
  });
});

describe("POST /api/auth/v1/agent-token (Restore Token)", () => {
  const restore = (w: World, body: string, contentType = "application/json") =>
    request(w.app).post("/api/auth/v1/agent-token").set("Authorization", `Bearer ${jwt()}`).set("Content-Type", contentType).send(body);

  it("replaces only the agent token, verbatim, clears the flag, records it, and calls nothing upstream", async () => {
    const w = world(credential({ ...REGISTERED, tokenExpired: true }));
    expectJson(await restore(w, JSON.stringify({ agentToken: "  restored token\t" })), 200, { status: "restored" });
    expect(getCredential(w.db)).toEqual({ ...REGISTERED, agentToken: "  restored token\t", tokenExpired: false });
    expect(w.db.prepare("SELECT event, detail FROM registration_history").all()).toEqual([{ event: "token_restored", detail: "" }]);
    expect(w.upstream.rootCalls.length + w.upstream.registerCalls.length).toBe(0);
  });

  it("is 409 text while nothing is registered", async () => {
    expectText(await restore(world(null), '{"agentToken":"x"}'), 409, "no credential configured to restore a token onto\n");
  });

  it("is 400 'agentToken is required' for an empty, null, absent or null-bodied token", async () => {
    const w = world();
    for (const body of ["{}", '{"agentToken":""}', '{"agentToken":null}', '{"other":"x"}', "null"]) expectText(await restore(w, body), 400, "agentToken is required\n");
    expect(getCredential(w.db)?.agentToken).toBe("agent-token-sentinel");
  });

  it("is 400 'invalid request body: ' for what Go's decoder refuses", async () => {
    const w = world();
    for (const body of ["", "{", "not json", "[]", '"a string"', "42", '{"agentToken": 5}', '{"agentToken": {"a":1}}', '{"agentToken": ["x"]}']) {
      expectText(await restore(w, body), 400, /^invalid request body: .+\n$/);
    }
    expect(getCredential(w.db)?.agentToken).toBe("agent-token-sentinel");
  });

  it("decodes like Go: key case ignored, unknown keys ignored, last duplicate wins, trailing data ignored, any content type", async () => {
    const w = world();
    for (const [body, stored] of [
      ['{"AGENTTOKEN":"upper"}', "upper"],
      ['{"agenttoken":"lower","unknown":{"a":[1,2]}}', "lower"],
      ['{"agentToken":"first","agentToken":"second"}', "second"],
      ['{"agentToken":"trailing"} this is never read', "trailing"],
    ] as const) {
      expectJson(await restore(w, body), 200, { status: "restored" });
      expect(getCredential(w.db)?.agentToken).toBe(stored);
    }
    expectJson(await restore(w, '{"agentToken":"as-text"}', "text/plain"), 200, { status: "restored" });
  });

  it("refuses a first value that does not end within 1 MiB, and takes one that does whatever follows", async () => {
    const w = world();
    expectText(await restore(w, `{"agentToken":"${"a".repeat(MAX_OPERATOR_BODY)}"}`), 400, "invalid request body: http: request body too large\n");
    expectJson(await restore(w, `{"agentToken":"short"}${" ".repeat(MAX_OPERATOR_BODY)}`), 200, { status: "restored" });
    expect(getCredential(w.db)?.agentToken).toBe("short");
  });

  it("is 500 with the store's error when the write fails, and logs a failed history row without failing", async () => {
    const w = world();
    const append = jest.spyOn(w.store, "appendHistory").mockImplementation(() => {
      throw new Error("disk full");
    });
    expectJson(await restore(w, '{"agentToken":"x"}'), 200, { status: "restored" });
    expect(w.logs).toContain("failed to record token_restored: Error: disk full");
    append.mockRestore();
    jest.spyOn(w.store, "updateAgentToken").mockImplementation(() => {
      throw new Error("database is locked");
    });
    expectText(await restore(w, '{"agentToken":"y"}'), 500, "Error: database is locked\n");
  });
});

describe("POST /api/auth/v1/register (Reset Agent)", () => {
  const register = (w: World, body: unknown) =>
    request(w.app)
      .post("/api/auth/v1/register")
      .set("Authorization", `Bearer ${jwt()}`)
      .send(typeof body === "string" ? body : JSON.stringify(body));
  const BODY = { accountToken: "account-token-2", symbol: "SECOND", faction: "VOID", email: "e@example.com" };

  it("registers, stores the credential wholesale, polls once, and answers SpaceTraders' symbol", async () => {
    const w = world(credential({ ...REGISTERED, tokenExpired: true }));
    w.upstream.root = () => Promise.resolve(rootOf("2026-10-01", "2099-03-01T00:00:00Z"));
    expectJson(await register(w, BODY), 200, { agentSymbol: "UPSTREAM", status: "registered" });
    expect(w.upstream.registerCalls).toEqual([{ accountToken: "account-token-2", symbol: "SECOND", faction: "VOID", email: "e@example.com" }]);
    expect(w.upstream.rootCalls).toHaveLength(1);
    expect(getCredential(w.db)).toEqual({
      accountToken: "account-token-2",
      agentToken: "agent-token-1",
      agentSymbol: "UPSTREAM",
      faction: "VOID",
      email: "e@example.com",
      resetDate: time("2026-10-01T00:00:00Z"),
      nextPredictedReset: time("2099-03-01T00:00:00Z"),
      tokenExpired: false,
    });
    expect((w.db.prepare("SELECT event FROM registration_history").all() as { event: string }[]).map((r) => r.event)).toEqual(["registered"]);
  });

  it("clears the stored dates, and still succeeds without them when the poll after it fails", async () => {
    const w = world();
    w.upstream.root = () => Promise.reject(new TransportError("GET /", new Error("x")));
    expectJson(await register(w, BODY), 200, { agentSymbol: "UPSTREAM", status: "registered" });
    expect(getCredential(w.db)).toMatchObject({ resetDate: null, nextPredictedReset: null });
    expect(w.logs.filter((l) => !l.startsWith("POST request"))).toEqual(["post-registration poll failed: GET /: request failed"]);
  });

  it("is 400 for a missing field or a body Go's decoder refuses, and calls nothing upstream", async () => {
    const w = world();
    for (const body of [{}, { symbol: "A", faction: "B" }, { accountToken: "t", faction: "B" }, { accountToken: "t", symbol: "A" }, { accountToken: "", symbol: "A", faction: "B" }, "null"]) {
      expectText(await register(w, body), 400, "accountToken, symbol and faction are required\n");
    }
    for (const body of ["", "{", "[]", '{"accountToken": 1, "symbol": "A", "faction": "B"}', '{"email": 5, "accountToken":"t","symbol":"A","faction":"B"}']) {
      expectText(await register(w, body), 400, /^invalid request body: /);
    }
    expect(w.upstream.registerCalls).toHaveLength(0);
  });

  it("passes upstream's 4xx/5xx through with its raw body, byte for byte, and leaves the row alone", async () => {
    const w = world();
    for (const [status, body] of [
      [400, Buffer.from('{"error":{"message":"bad"}}')],
      [409, Buffer.from("taken")],
      [422, Buffer.alloc(0)],
      [503, Buffer.from([0x3c, 0xff, 0xfe, 0x3e])],
    ] as const) {
      w.upstream.registration = () => Promise.reject(new UpstreamError(status, "POST /register", body));
      const res = await request(w.app).post("/api/auth/v1/register").set("Authorization", `Bearer ${jwt()}`).send(JSON.stringify(BODY)).buffer(true).parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on("data", (c: Buffer) => chunks.push(c));
        r.on("end", () => { cb(null, Buffer.concat(chunks)); });
      });
      expect(res.status).toBe(status);
      expect(res.headers["content-type"]).toBe("text/plain; charset=utf-8");
      expect(res.body).toEqual(Buffer.concat([Buffer.from("POST /register: "), body, Buffer.from("\n")]));
    }
    expect(getCredential(w.db)).toEqual(REGISTERED);
  });

  it("is 502 for a transport failure or an unusable answer, naming no credential", async () => {
    const w = world();
    w.upstream.registration = () => Promise.reject(new TransportError("POST /register", Object.assign(new Error("fetch failed"), { cause: { code: "ECONNREFUSED" } })));
    expectText(await register(w, BODY), 502, "POST /register: request failed (ECONNREFUSED)\n");
    w.upstream.registration = () => Promise.reject(new SyntaxError("Unexpected token"));
    expectText(await register(w, BODY), 502, "SyntaxError: Unexpected token\n");
    expect(getCredential(w.db)).toEqual(REGISTERED);
  });

  it("is 500 'registered but failed to persist credential' when the write fails", async () => {
    const w = world();
    jest.spyOn(w.store, "upsert").mockImplementation(() => {
      throw new Error("database is locked");
    });
    expectText(await register(w, BODY), 500, "registered but failed to persist credential: Error: database is locked\n");
  });
});

describe("no credential leaves the vault but through the token route", () => {
  it("is in no log line, no status answer and no error body, across every route and failure", async () => {
    const w = world();
    const secrets = ["agent-token-sentinel", "account-token-sentinel", "new-account-sentinel", "restored-sentinel", SHARED];
    const bodies: string[] = [];
    const keep = (r: request.Response): void => void bodies.push(r.text);

    keep(await token(w, "wrong"));
    expect((await token(w, SHARED, "?afterUnauthorized=true")).status).toBe(200);
    keep(await request(w.app).get("/auth/v1/status"));
    keep(await request(w.app).get("/api/auth/v1/status"));
    w.upstream.registration = () => Promise.reject(new UpstreamError(500, "POST /register", Buffer.from("boom")));
    keep(await request(w.app).post("/api/auth/v1/register").set("Authorization", `Bearer ${jwt()}`).send(JSON.stringify({ accountToken: "new-account-sentinel", symbol: "S", faction: "F" })));
    w.upstream.registration = () => Promise.reject(new TransportError("POST /register", new Error("x")));
    keep(await request(w.app).post("/api/auth/v1/register").set("Authorization", `Bearer ${jwt()}`).send(JSON.stringify({ accountToken: "new-account-sentinel", symbol: "S", faction: "F" })));
    keep(await request(w.app).post("/api/auth/v1/register").set("Authorization", `Bearer ${jwt({ scope: "x" })}`).send(JSON.stringify({ accountToken: "new-account-sentinel" })));
    keep(await request(w.app).post("/api/auth/v1/agent-token").set("Authorization", `Bearer ${jwt()}`).send('{"agentToken":"restored-sentinel" "x"}'));
    keep(await request(w.app).post("/api/auth/v1/agent-token").set("Authorization", `Bearer ${jwt()}`).send('{"agentToken":"restored-sentinel"}'));
    // Upstream echoing a credential back in an error body: it must not reach the log.
    w.upstream.root = () => Promise.reject(new UpstreamError(500, "GET /", Buffer.from("restored-sentinel account-token-sentinel")));
    w.monotonic.now += 10_000;
    const answered = await token(w, SHARED, "?afterUnauthorized=true");
    expect(JSON.parse(answered.text)).toEqual({ agentToken: "restored-sentinel" });

    expect(w.logs.length).toBeGreaterThan(8);
    for (const s of secrets) {
      expect(w.logs.filter((l) => l.includes(s))).toEqual([]);
      expect(bodies.filter((b) => b.includes(s))).toEqual([]);
    }
  });
});
