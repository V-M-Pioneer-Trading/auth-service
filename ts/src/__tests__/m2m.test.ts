/**
 * POST /auth/v1/m2m-token over HTTP, against the real app, the real minters and a Clerk stub on a real socket: the
 * secret gate, the answer shapes and headers, both trust anchors, what is asked of Clerk, single flight across
 * requests, the detached mint, redirects, the answer's limits, the mint timeout, the proxy, and the log.
 */
import { createPublicKey, generateKeyPairSync, verify, type KeyObject } from "node:crypto";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import request from "supertest";

import { ConfigError, type M2MConfig } from "../config";
import { clerkMinter } from "../m2m/clerk";
import { createM2MService, type M2MService, type M2MServiceOptions } from "../m2m/service";
import { createApp, createHttpServer } from "../server";
import { storeOf, TEST_ORIGIN } from "../testSupport/createTestApp";

jest.setTimeout(30000);

const SHARED = "shared-secret-sentinel";
const INTROSPECTION = "introspection-secret-sentinel";
const AUTOMATION = "automation-caller-secret-sentinel";
const AI = "ai-caller-secret-sentinel";
const MACHINE_AUTOMATION = "sk_machine_automation_sentinel";
const MACHINE_AI = "sk_machine_ai_sentinel";
const devKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;

const CORS = {
  "access-control-allow-origin": TEST_ORIGIN,
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization, X-Auth-Service-Secret",
};
const UNKNOWN = { error: "unknown caller" };
const FAILED = { error: "the token could not be minted" };

const b64u = (s: string): string => Buffer.from(s).toString("base64url");
const nowS = (): number => Math.floor(Date.now() / 1000);
/** A Clerk-shaped token (unsigned: the service reads only iat and exp). */
const clerkToken = (scope: string, lifetime = 86400, iatOffset = 0, sub = "mch_stub"): string => {
  const iat = nowS() + iatOffset;
  return `${b64u('{"alg":"RS256","typ":"JWT"}')}.${b64u(JSON.stringify({ sub, scope, iat, exp: iat + lifetime }))}.c2ln`;
};
const payloadOf = (token: string): Record<string, unknown> => JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString()) as Record<string, unknown>;

// ---- a Clerk stub --------------------------------------------------------------------------------------------

interface Call {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}
type Reply = (call: Call, res: http.ServerResponse, nth: number) => void;

class ClerkStub {
  calls: Call[] = [];
  reply: Reply = (call, res) => {
    const asked = JSON.parse(call.body) as { claims: { scope: string } };
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ object: "m2m_token", token: clerkToken(asked.claims.scope) }));
  };
  readonly server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const call = { method: req.method ?? "", url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString() };
      this.calls.push(call);
      this.reply(call, res, this.calls.length);
    });
  });
  async listen(): Promise<void> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
  }
  get url(): string {
    return `http://127.0.0.1:${String((this.server.address() as AddressInfo).port)}`;
  }
  async close(): Promise<void> {
    this.server.closeAllConnections();
    await new Promise((resolve) => this.server.close(resolve));
  }
}

let clerk: ClerkStub;
let logs: string[];
beforeEach(async () => {
  clerk = new ClerkStub();
  await clerk.listen();
  logs = [];
});
afterEach(async () => {
  await clerk.close();
});

function config(mode: "clerk" | "dev", over: Partial<M2MConfig> = {}): M2MConfig {
  return {
    callers: [
      { name: "automation-service", secret: AUTOMATION, machineKey: mode === "clerk" ? MACHINE_AUTOMATION : "" },
      { name: "ai-service", secret: AI, machineKey: mode === "clerk" ? MACHINE_AI : "" },
    ],
    devSigningKey: mode === "dev" ? devKey : undefined,
    issuer: "",
    clerkTokensUrl: mode === "clerk" ? `${clerk.url}/v1/m2m_tokens` : "",
    ...over,
  };
}

function service(mode: "clerk" | "dev", over: Partial<M2MConfig> = {}, options: Partial<M2MServiceOptions> = {}): M2MService {
  return createM2MService(config(mode, over), SHARED, INTROSPECTION, { log: (l) => logs.push(l), env: {}, ...options });
}

const appOf = (m2m?: M2MService) =>
  createApp({ corsAllowedOrigin: TEST_ORIGIN, credentials: storeOf(undefined), ...(m2m === undefined ? {} : { m2m }), log: (l) => logs.push(l) });

const post = (app: ReturnType<typeof appOf>, secret: string | null, path = "/auth/v1/m2m-token") => {
  const r = request(app).post(path);
  return secret === null ? r : r.set("X-M2M-Caller-Secret", secret);
};

function expectAnswer(res: request.Response, status: number, body: unknown): void {
  expect(res.status).toBe(status);
  expect(res.headers["content-type"]).toBe("application/json");
  expect(res.headers["cache-control"]).toBe("no-store");
  expect(res.headers.etag).toBeUndefined();
  for (const [k, v] of Object.entries(CORS)) expect(res.headers[k]).toBe(v);
  expect(JSON.parse(res.text)).toEqual(body);
  expect(res.text.endsWith("\n")).toBe(true);
}

// ---- the route ------------------------------------------------------------------------------------------------

describe("the secret gate", () => {
  it.each([
    ["missing", null],
    ["empty", ""],
    ["wrong", "nope"],
    ["a prefix", AUTOMATION.slice(0, -1)],
    ["one character more", `${AUTOMATION}x`],
    ["the wrong case", AUTOMATION.toUpperCase()],
    ["the vault secret", SHARED],
    ["the introspection secret", INTROSPECTION],
    ["a machine key", MACHINE_AUTOMATION],
  ])("answers 401 {error:'unknown caller'} with no-store for a %s secret, and costs no mint", async (_label, secret) => {
    expectAnswer(await post(appOf(service("clerk")), secret), 401, UNKNOWN);
    expect(clerk.calls).toHaveLength(0);
  });

  it("does not take the secret from the query string or another header", async () => {
    const app = appOf(service("clerk"));
    expectAnswer(await post(app, null, `/auth/v1/m2m-token?secret=${AI}&x-m2m-caller-secret=${AI}`), 401, UNKNOWN);
    for (const header of ["X-Auth-Service-Secret", "X-Introspection-Secret", "Authorization", "X-M2M-Caller"]) {
      expectAnswer(await request(app).post("/auth/v1/m2m-token").set(header, AI), 401, UNKNOWN);
    }
  });

  it("matches the header name in any case and ignores surrounding whitespace in its value", async () => {
    const res = await request(appOf(service("dev"))).post("/auth/v1/m2m-token").set("x-m2m-caller-SECRET", `  ${AI}\t`);
    expect(res.status).toBe(200);
  });

  it("reads the first of two X-M2M-Caller-Secret headers", async () => {
    const server = createHttpServer(appOf(service("dev")));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const raw = (first: string, second: string) =>
      new Promise<string>((resolve) => {
        const socket = net.connect(port, "127.0.0.1", () => {
          socket.end(`POST /auth/v1/m2m-token HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-M2M-Caller-Secret: ${first}\r\nX-M2M-Caller-Secret: ${second}\r\nContent-Length: 0\r\n\r\n`);
        });
        let out = "";
        socket.on("data", (c: Buffer) => (out += c.toString()));
        socket.on("close", () => {
          resolve(out.split("\r\n")[0] ?? "");
        });
      });
    expect(await raw(AI, "nope")).toBe("HTTP/1.1 200 OK");
    expect(await raw("nope", AI)).toBe("HTTP/1.1 401 Unauthorized");
    server.close();
  });

  it("is POST only: GET is the router's bare 405", async () => {
    const res = await request(appOf(service("dev"))).get("/auth/v1/m2m-token").set("X-M2M-Caller-Secret", AI);
    expect(res.status).toBe(405);
    expect(res.text).toBe("");
  });

  it("with no M2M configuration the route is mounted and every caller is unknown", async () => {
    expectAnswer(await post(appOf(), AUTOMATION), 401, UNKNOWN);
    expectAnswer(await post(appOf(), null), 401, UNKNOWN);
  });

  it("a caller with no secret is disabled; the other still mints", async () => {
    const app = appOf(service("dev", { callers: [{ name: "automation-service", secret: AUTOMATION, machineKey: "" }, { name: "ai-service", secret: "", machineKey: "" }] }));
    expect((await post(app, AUTOMATION)).status).toBe(200);
    expectAnswer(await post(app, AI), 401, UNKNOWN);
    expectAnswer(await post(app, ""), 401, UNKNOWN);
  });
});

describe("the service validates its table again, as newM2MHandler does", () => {
  it.each([
    ["a caller secret equal to the vault secret", { callers: [{ name: "automation-service", secret: SHARED, machineKey: "" }] }],
    ["a caller secret equal to the introspection secret", { callers: [{ name: "automation-service", secret: INTROSPECTION, machineKey: "" }] }],
    ["two callers with one secret", { callers: [{ name: "automation-service", secret: AI, machineKey: "" }, { name: "ai-service", secret: AI, machineKey: "" }] }],
    ["a caller outside the table", { callers: [{ name: "planner", secret: "x", machineKey: "" }] }],
    ["a dev key next to a machine key", { callers: [{ name: "automation-service", secret: AI, machineKey: "k" }] }],
  ])("refuses %s", (_label, over) => {
    expect(() => service("dev", over)).toThrow(ConfigError);
  });
});

// ---- dev mode -------------------------------------------------------------------------------------------------

describe("dev mode: signed here with DEV_M2M_SIGNING_KEY_FILE", () => {
  const verifies = (token: string, key: KeyObject): boolean => {
    const [h, p, s] = token.split(".");
    return verify("sha256", Buffer.from(`${h ?? ""}.${p ?? ""}`), key, Buffer.from(s ?? "", "base64url"));
  };

  it.each([
    ["automation-service", AUTOMATION, "fleet:control"],
    ["ai-service", AI, "events:write planner:advise"],
  ])("%s gets a 24 h RS256 token for its own scopes, named mch_local_<caller>, as golang-jwt writes it", async (name, secret, scope) => {
    const before = nowS();
    const res = await post(appOf(service("dev")), secret);
    const after = nowS();
    const { token, expires_at } = JSON.parse(res.text) as { token: string; expires_at: number };
    expectAnswer(res, 200, { token, expires_at });
    const [h, p] = token.split(".");
    expect(Buffer.from(h ?? "", "base64url").toString()).toBe('{"alg":"RS256","kid":"dev-only-do-not-use","typ":"JWT"}');
    const iat = payloadOf(token).iat as number;
    expect(iat).toBeGreaterThanOrEqual(before);
    expect(iat).toBeLessThanOrEqual(after);
    expect(Buffer.from(p ?? "", "base64url").toString()).toBe(`{"exp":${String(iat + 86400)},"iat":${String(iat)},"scope":"${scope}","sub":"mch_local_${name}"}`);
    expect(expires_at).toBe(iat + 86400);
    expect(verifies(token, createPublicKey(devKey))).toBe(true);
  });

  it("carries CLERK_ISSUER as iss when it is set, escaped as encoding/json escapes it", async () => {
    const res = await post(appOf(service("dev", { issuer: "https://clerk.example/a&b<c>" })), AI);
    const { token } = JSON.parse(res.text) as { token: string };
    const payload = Buffer.from(token.split(".")[1] ?? "", "base64url").toString();
    expect(payload).toContain('"iss":"https://clerk.example/a\\u0026b\\u003cc\\u003e"');
    expect(payloadOf(token).iss).toBe("https://clerk.example/a&b<c>");
  });

  it("lets a caller request nothing: body, query and other headers cannot name a caller or a scope", async () => {
    const res = await request(appOf(service("dev")))
      .post("/auth/v1/m2m-token?scope=fleet:admin&caller=ai-service")
      .set("X-M2M-Caller-Secret", AUTOMATION)
      .set("X-M2M-Caller", "ai-service")
      .set("Content-Type", "application/json")
      .send(JSON.stringify({ scope: "everything", caller: "ai-service" }));
    const claims = payloadOf((JSON.parse(res.text) as { token: string }).token);
    expect(claims.scope).toBe("fleet:control");
    expect(claims.sub).toBe("mch_local_automation-service");
  });

  it("serves the cached token again rather than signing a new one", async () => {
    const app = appOf(service("dev"));
    const first = (await post(app, AI)).text;
    await new Promise((r) => setTimeout(r, 1100));
    expect((await post(app, AI)).text).toBe(first);
  });
});

// ---- Clerk mode -----------------------------------------------------------------------------------------------

describe("Clerk mode: what it asks Clerk", () => {
  it("POSTs /v1/m2m_tokens with the caller's own machine key, its scopes and 24 h, in Go's byte order", async () => {
    const app = appOf(service("clerk"));
    expect((await post(app, AUTOMATION)).status).toBe(200);
    expect((await post(app, AI)).status).toBe(200);
    const [auto, ai] = clerk.calls;
    expect(auto?.method).toBe("POST");
    expect(auto?.url).toBe("/v1/m2m_tokens");
    expect(auto?.headers.authorization).toBe(`Bearer ${MACHINE_AUTOMATION}`);
    expect(ai?.headers.authorization).toBe(`Bearer ${MACHINE_AI}`);
    expect(auto?.headers["content-type"]).toBe("application/json");
    expect(auto?.body).toBe('{"claims":{"scope":"fleet:control"},"seconds_until_expiration":86400,"token_format":"jwt"}');
    expect(ai?.body).toBe('{"claims":{"scope":"events:write planner:advise"},"seconds_until_expiration":86400,"token_format":"jwt"}');
    expect(clerk.calls).toHaveLength(2);
  });

  it("serves Clerk's token verbatim, expires_at read from its exp", async () => {
    const minted = clerkToken("events:write planner:advise", 3600, -10, "mch_real");
    clerk.reply = (_c, res) => res.end(JSON.stringify({ token: minted }));
    const res = await post(appOf(service("clerk")), AI);
    expectAnswer(res, 200, { token: minted, expires_at: payloadOf(minted).exp });
  });

  it("takes any 2xx", async () => {
    clerk.reply = (call, res) => {
      res.statusCode = 201;
      res.end(JSON.stringify({ token: clerkToken("x") }));
    };
    expect((await post(appOf(service("clerk")), AI)).status).toBe(200);
  });

  it("CLERK_API_BASE_URL unset means api.clerk.com", () => {
    // Nothing is sent: building the service only resolves the endpoint.
    expect(() => service("clerk", { clerkTokensUrl: "" })).not.toThrow();
  });
});

describe("Clerk mode: single flight across requests", () => {
  it("25 concurrent requests from one caller cost one Clerk call and all get the same answer", async () => {
    const reply = clerk.reply;
    clerk.reply = (call, res, n) => setTimeout(() => { reply(call, res, n); }, 300);
    const app = appOf(service("clerk"));
    const answers = await Promise.all(Array.from({ length: 25 }, () => post(app, AUTOMATION)));
    expect(new Set(answers.map((r) => r.status))).toEqual(new Set([200]));
    expect(new Set(answers.map((r) => r.text)).size).toBe(1);
    expect(clerk.calls).toHaveLength(1);
  });

  it("two callers, two calls, however many requests", async () => {
    const reply = clerk.reply;
    clerk.reply = (call, res, n) => setTimeout(() => { reply(call, res, n); }, 200);
    const app = appOf(service("clerk"));
    await Promise.all([...Array.from({ length: 10 }, () => post(app, AUTOMATION)), ...Array.from({ length: 10 }, () => post(app, AI))]);
    expect(clerk.calls).toHaveLength(2);
  });

  it("a caller who hangs up does not cancel the mint: the retry finds the token, one Clerk call in all", async () => {
    const reply = clerk.reply;
    clerk.reply = (call, res, n) => setTimeout(() => { reply(call, res, n); }, 500);
    const server = createHttpServer(appOf(service("clerk")));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    await new Promise<void>((resolve) => {
      const req = http.request({ port, host: "127.0.0.1", method: "POST", path: "/auth/v1/m2m-token", headers: { "X-M2M-Caller-Secret": AI } });
      req.on("error", () => { resolve(); });
      req.end();
      setTimeout(() => {
        req.destroy();
        resolve();
      }, 100);
    });
    await new Promise((r) => setTimeout(r, 700));
    const res = await request(server).post("/auth/v1/m2m-token").set("X-M2M-Caller-Secret", AI);
    expect(res.status).toBe(200);
    expect(clerk.calls).toHaveLength(1);
    server.close();
  });
});

describe("Clerk mode: every reason a mint fails is a 503 with nothing of Clerk's in it", () => {
  const cases: [string, Reply][] = [
    ["Clerk answers 500", (_c, res) => { res.statusCode = 500; res.end('{"errors":[{"message":"boom with a secret-looking value"}]}'); }],
    ["Clerk answers 401", (_c, res) => { res.statusCode = 401; res.end("{}"); }],
    ["Clerk answers 429", (_c, res) => { res.statusCode = 429; res.end("slow down"); }],
    ["a 307, which is never followed", (_c, res) => { res.statusCode = 307; res.setHeader("Location", "/v1/elsewhere"); res.end(); }],
    ["a 204", (_c, res) => { res.statusCode = 204; res.end(); }],
    ["a body that is not JSON", (_c, res) => res.end("<html>")],
    ["no token", (_c, res) => res.end("{}")],
    ["an empty token", (_c, res) => res.end('{"token":""}')],
    ["a token that is not a JWT", (_c, res) => res.end('{"token":"not-a-jwt"}')],
    ["a token under 60 s", (_c, res) => res.end(JSON.stringify({ token: clerkToken("x", 59) }))],
    ["a token over 7 days", (_c, res) => res.end(JSON.stringify({ token: clerkToken("x", 7 * 86400 + 1) }))],
    ["a token already expired", (_c, res) => res.end(JSON.stringify({ token: clerkToken("x", 3600, -7200) }))],
    ["a token past its refresh point", (_c, res) => res.end(JSON.stringify({ token: clerkToken("x", 100, -60) }))],
    ["Clerk hanging up", (_c, res) => res.socket?.destroy()],
  ];
  it.each(cases)("%s", async (_label, reply) => {
    clerk.reply = reply;
    const res = await post(appOf(service("clerk")), AUTOMATION);
    expectAnswer(res, 503, FAILED);
    expect(clerk.calls).toHaveLength(1);
    expect(res.text).not.toMatch(/boom|secret/);
  });

  it("does not follow a redirect, so the machine key goes nowhere else", async () => {
    clerk.reply = (call, res) => {
      if (call.url === "/v1/m2m_tokens") {
        res.statusCode = 302;
        res.setHeader("Location", `${clerk.url}/v1/stolen`);
        res.end();
      } else {
        res.end(JSON.stringify({ token: clerkToken("x") }));
      }
    };
    expectAnswer(await post(appOf(service("clerk")), AUTOMATION), 503, FAILED);
    expect(clerk.calls.map((c) => c.url)).toEqual(["/v1/m2m_tokens"]);
    expect(logs).toContain("minting a machine token for automation-service failed: POST /m2m_tokens: status 302");
  });
});

describe("Clerk mode: reading the answer as Go's decoder does", () => {
  it("takes the token as soon as the first JSON value is complete, without waiting for the rest", async () => {
    clerk.reply = (_c, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write(`${JSON.stringify({ token: clerkToken("x") })}\n`);
      // ...and never ends the body.
    };
    const t0 = Date.now();
    expect((await post(appOf(service("clerk", {}, { mintTimeoutMs: 5000 })), AI)).status).toBe(200);
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it("gives up at 64 KiB without a complete value, without waiting for the end or the timeout", async () => {
    clerk.reply = (_c, res) => {
      res.writeHead(200);
      res.write(" ".repeat(70_000));
    };
    const t0 = Date.now();
    expectAnswer(await post(appOf(service("clerk", {}, { mintTimeoutMs: 5000 })), AI), 503, FAILED);
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it("accepts a token whose value ends inside the first 64 KiB, whatever follows", async () => {
    clerk.reply = (_c, res) => res.end(`${JSON.stringify({ token: clerkToken("x") })}${"x".repeat(70_000)}`);
    expect((await post(appOf(service("clerk")), AI)).status).toBe(200);
  });
});

describe("Clerk mode: the mint timeout", () => {
  it("gives up on a Clerk that never answers when the mint's own timeout fires: 503, and Clerk sees the request go", async () => {
    let gone = false;
    clerk.reply = (_c, res) => {
      res.on("close", () => (gone = true));
    };
    const t0 = Date.now();
    expectAnswer(await post(appOf(service("clerk", {}, { mintTimeoutMs: 400 })), AI), 503, FAILED);
    const took = Date.now() - t0;
    expect(took).toBeGreaterThanOrEqual(350);
    expect(took).toBeLessThan(2000);
    await new Promise((r) => setTimeout(r, 100));
    expect(gone).toBe(true);
    expect(logs).toContain("minting a machine token for ai-service failed: POST /m2m_tokens: context deadline exceeded");
  });
});

describe("the proxy, chosen as Go's ProxyFromEnvironment chooses it", () => {
  it("tunnels through the chosen proxy with its credentials, and the machine key goes to the target", async () => {
    const seen: { url: string; auth: string | undefined; bearer: string | undefined }[] = [];
    const proxy = http.createServer((req, res) => {
      seen.push({ url: req.url ?? "", auth: req.headers["proxy-authorization"], bearer: req.headers.authorization });
      req.resume();
      req.on("end", () => res.end(JSON.stringify({ token: clerkToken("x") })));
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const host = `127.0.0.1:${String((proxy.address() as AddressInfo).port)}`;
    const mint = clerkMinter({
      url: "http://clerk.invalid:8080/v1/m2m_tokens",
      machineKey: MACHINE_AI,
      scopes: "x",
      proxy: { kind: "proxy", proxy: { scheme: "http", host, username: "u", password: "p@ss" } },
    });
    expect(payloadOf(await mint(new AbortController().signal)).scope).toBe("x");
    expect(seen).toEqual([{ url: "http://clerk.invalid:8080/v1/m2m_tokens", auth: `Basic ${Buffer.from("u:p@ss").toString("base64")}`, bearer: `Bearer ${MACHINE_AI}` }]);
    proxy.closeAllConnections();
    proxy.close();
  });

  it("fails a mint it cannot route as Go would (socks5) or that Go refuses (HTTP_PROXY under CGI)", async () => {
    const socks = clerkMinter({ url: `${clerk.url}/v1/m2m_tokens`, machineKey: "k", scopes: "x", proxy: { kind: "proxy", proxy: { scheme: "socks5", host: "127.0.0.1:1080" } } });
    await expect(socks(new AbortController().signal)).rejects.toThrow("POST /m2m_tokens: a socks5 proxy is not supported");
    const cgi = clerkMinter({ url: `${clerk.url}/v1/m2m_tokens`, machineKey: "k", scopes: "x", proxy: { kind: "refused", reason: "refusing to use HTTP_PROXY value in CGI environment" } });
    await expect(cgi(new AbortController().signal)).rejects.toThrow(/CGI/);
    expect(clerk.calls).toHaveLength(0);
  });

  it("reads the environment it is given: a loopback Clerk is never proxied, a proxy for other hosts is used", async () => {
    const app = appOf(service("clerk", {}, { env: { HTTP_PROXY: "http://127.0.0.1:9" } }));
    expect((await post(app, AI)).status).toBe(200);
    expect(clerk.calls).toHaveLength(1);
  });
});

// ---- the log ------------------------------------------------------------------------------------------------------

describe("log hygiene", () => {
  it("never writes a machine key, a caller secret, a token or Clerk's text; one line per failed mint, one per backoff window", async () => {
    const SENTINEL = "clerk-error-body-sentinel";
    clerk.reply = (_c, res) => {
      res.statusCode = 500;
      res.end(JSON.stringify({ errors: [{ message: SENTINEL, long_message: `${SENTINEL} ${MACHINE_AUTOMATION}` }] }));
    };
    const app = appOf(service("clerk"));
    await Promise.all(Array.from({ length: 5 }, () => post(app, AUTOMATION)));
    await post(app, AUTOMATION);
    await post(app, AUTOMATION);
    await post(app, "wrong-secret-sentinel");
    clerk.reply = (_c, res) => res.end(JSON.stringify({ token: clerkToken("x") }));
    const ok = await post(app, AI);
    const token = (JSON.parse(ok.text) as { token: string }).token;
    const text = logs.join("\n");
    for (const value of [MACHINE_AUTOMATION, MACHINE_AI, AUTOMATION, AI, SHARED, INTROSPECTION, SENTINEL, "wrong-secret-sentinel", token, token.split(".")[1] ?? ""]) {
      expect(text).not.toContain(value);
    }
    expect(logs.filter((l) => l.includes("failed: POST /m2m_tokens: status 500"))).toHaveLength(1);
    expect(logs.filter((l) => l.includes("not calling Clerk again yet"))).toEqual([
      "minting a machine token for automation-service: the last mint failed less than 10 s ago; not calling Clerk again yet",
    ]);
  });
});
