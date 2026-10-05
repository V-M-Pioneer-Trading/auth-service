/**
 * POST /auth/v1/introspect over HTTP, against the real app and the real verifier: the caller-secret gate, the form as
 * Go's ParseForm reads it, the cap, the answer shapes and headers. Raw sockets where supertest would hide what is on
 * the wire (two headers of one name, chunking, Expect: 100-continue, the connection after an oversized body).
 */
import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import net from "node:net";
import type { AddressInfo } from "node:net";
import request from "supertest";

import { createVerifier } from "../jwt/verify";
import { INTROSPECTION_SECRET_REQUIRED, introspectionSecretOk, MAX_INTROSPECTION_BODY } from "../introspection";
import { createHttpServer } from "../server";
import { createTestApp, NOW, TEST_ORIGIN } from "../testSupport/createTestApp";

jest.setTimeout(30000);

const SECRET = "introspection-secret-for-tests";
const key = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const NOW_S = Math.floor(NOW / 1000);
const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");
function jwt(claims: Record<string, unknown> = {}): string {
  const input = `${b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${b64u(JSON.stringify({ sub: "user_test", scope: "agent:reset", exp: NOW_S + 3600, ...claims }))}`;
  return `${input}.${b64u(sign("sha256", Buffer.from(input), key))}`;
}
const ACTIVE = { active: true, sub: "user_test", scope: "agent:reset", exp: NOW_S + 3600, kind: "operator" };
const INACTIVE = { active: false };

const app = (secret = SECRET, issuer = "") => createTestApp(undefined, { introspection: { secret, verifier: createVerifier({ key: createPublicKey(key), issuer }) } });
const FORM = "application/x-www-form-urlencoded";
const post = (body: string, opts: { secret?: string | null; path?: string; contentType?: string | null; target?: ReturnType<typeof app> } = {}) => {
  let r = request(opts.target ?? app()).post(opts.path ?? "/auth/v1/introspect");
  if (opts.contentType !== null) r = r.set("Content-Type", opts.contentType ?? FORM);
  if (opts.secret !== null) r = r.set("X-Introspection-Secret", opts.secret ?? SECRET);
  return r.send(body);
};

const CORS = {
  "access-control-allow-origin": TEST_ORIGIN,
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization, X-Auth-Service-Secret",
};

/** The whole answer: status, the headers the contract pins, the body bytes. */
function expectAnswer(res: request.Response, status: number, body: unknown): void {
  expect(res.status).toBe(status);
  expect(res.headers["content-type"]).toBe("application/json");
  expect(res.headers["cache-control"]).toBe("no-store");
  expect(res.headers.etag).toBeUndefined();
  for (const [k, v] of Object.entries(CORS)) expect(res.headers[k]).toBe(v);
  expect(res.text).toBe(`${JSON.stringify(body)}\n`);
}

describe("the caller secret gate", () => {
  it("answers a good secret and a good token with exactly the five keys, application/json and no-store", async () => {
    expectAnswer(await post(`token=${jwt()}`), 200, ACTIVE);
  });

  it.each([
    ["wrong", "nope"],
    ["empty", ""],
    ["a prefix", SECRET.slice(0, -1)],
    ["an extension", `${SECRET}x`],
    ["re-cased", SECRET.toUpperCase()],
  ])("refuses a %s secret with the 401 envelope and no-store, before reading the body", async (_n, secret) => {
    expectAnswer(await post(`token=${jwt()}`, { secret }), 401, { error: { message: INTROSPECTION_SECRET_REQUIRED } });
  });

  it("refuses a missing header", async () => {
    expectAnswer(await post(`token=${jwt()}`, { secret: null }), 401, { error: { message: INTROSPECTION_SECRET_REQUIRED } });
  });

  it("refuses everyone, an empty header included, when no secret is configured", async () => {
    const target = app("");
    expectAnswer(await post(`token=${jwt()}`, { secret: "", target }), 401, { error: { message: INTROSPECTION_SECRET_REQUIRED } });
    expectAnswer(await post(`token=${jwt()}`, { secret: null, target }), 401, { error: { message: INTROSPECTION_SECRET_REQUIRED } });
  });

  it("compares bytes, so a secret is never matched by a different encoding of it", () => {
    expect(introspectionSecretOk("sé", Buffer.from("sé", "utf8").toString("latin1"))).toBe(true);
    expect(introspectionSecretOk("sé", "sé")).toBe(false);
    expect(introspectionSecretOk("", "")).toBe(false);
    expect(introspectionSecretOk("", undefined)).toBe(false);
    expect(introspectionSecretOk("a", undefined)).toBe(false);
  });

  it("does not read the secret from the query string or another header", async () => {
    expectAnswer(await post(`token=${jwt()}`, { secret: null, path: `/auth/v1/introspect?X-Introspection-Secret=${SECRET}` }), 401, {
      error: { message: INTROSPECTION_SECRET_REQUIRED },
    });
    const res = await request(app()).post("/auth/v1/introspect").set("Content-Type", FORM).set("X-Auth-Service-Secret", SECRET).send(`token=${jwt()}`);
    expect(res.status).toBe(401);
  });

  it("is POST only: GET and HEAD are the router's bare 405", async () => {
    const get = await request(app()).get(`/auth/v1/introspect?token=${jwt()}`).set("X-Introspection-Secret", SECRET);
    expect(get.status).toBe(405);
    expect(get.text).toBe("");
    expect(get.headers["cache-control"]).toBeUndefined();
    expect((await request(app()).head("/auth/v1/introspect")).status).toBe(405);
  });

  it("is not under /api/auth", async () => {
    expect((await post(`token=${jwt()}`, { path: "/api/auth/v1/introspect" })).status).toBe(404);
  });
});

describe("the form, as Go's ParseForm reads it", () => {
  it("takes the first token value and only the body's", async () => {
    expectAnswer(await post(`token=${jwt()}&token=garbage`), 200, ACTIVE);
    expectAnswer(await post(`token=garbage&token=${jwt()}`), 200, INACTIVE);
    expectAnswer(await post("", { path: `/auth/v1/introspect?token=${jwt()}` }), 200, INACTIVE);
    expectAnswer(await post(`token=${jwt({ sub: "user_body" })}`, { path: `/auth/v1/introspect?token=${jwt({ sub: "user_query" })}` }), 200, { ...ACTIVE, sub: "user_body" });
  });

  it("decodes the value: + and %XX", async () => {
    expectAnswer(await post(`token=${encodeURIComponent(jwt())}`), 200, ACTIVE);
    expectAnswer(await post(`%74oken=${jwt()}`), 200, ACTIVE);
  });

  it.each([
    ["a malformed escape after the token", (t: string) => `token=${t}&bad=%zz`],
    ["a malformed escape before it", (t: string) => `bad=%zz&token=${t}`],
    ["a lone %", (t: string) => `token=${t}&%=1`],
    ["a semicolon after it", (t: string) => `token=${t}&a=1;b=2`],
    ["a semicolon before it", (t: string) => `a=1;b=2&token=${t}`],
    ["a semicolon in its own pair", (t: string) => `token=${t};x=1`],
  ])("is inactive for %s, however valid the token", async (_n, body) => {
    expectAnswer(await post(body(jwt())), 200, INACTIVE);
  });

  it.each(["?%zz", "?a=1;b=2", "?%", "?token=%"])("is inactive for the query %s next to a valid body token", async (query) => {
    expectAnswer(await post(`token=${jwt()}`, { path: `/auth/v1/introspect${query}` }), 200, INACTIVE);
  });

  it("allows an escaped semicolon, and a query that parses", async () => {
    expectAnswer(await post(`token=${jwt()}&a=%3B`), 200, ACTIVE);
    expectAnswer(await post(`token=${jwt()}`, { path: "/auth/v1/introspect?a=1&b" }), 200, ACTIVE);
  });

  it.each([
    [`${FORM}; charset=UTF-8`, true],
    ["Application/X-WWW-Form-Urlencoded", true],
    [` ${FORM} ;`, true],
    [`${FORM}; charset`, false],
    [`${FORM}; a=1; a=2`, false],
    ["application/json", false],
    ["text/plain", false],
    ["multipart/form-data; boundary=x", false],
  ])("Content-Type %j reads the token: %s", async (contentType, active) => {
    expectAnswer(await post(`token=${jwt()}`, { contentType }), 200, active ? ACTIVE : INACTIVE);
  });

  it("does not read a JSON body", async () => {
    expectAnswer(await post(JSON.stringify({ token: jwt() }), { contentType: "application/json" }), 200, INACTIVE);
  });

  it("is inactive for an absent, empty or whitespace token", async () => {
    for (const body of ["", "token=", "other=1", "token=%20", `token=%20${jwt()}`]) expectAnswer(await post(body), 200, INACTIVE);
  });
});

describe("the 8 KiB cap", () => {
  const padded = (total: number): string => {
    const head = `token=${jwt()}&pad=`;
    return head + "a".repeat(total - head.length);
  };

  it("accepts 8192 bytes and answers 8193 {active:false}, not an error", async () => {
    expect(MAX_INTROSPECTION_BODY).toBe(8192);
    expectAnswer(await post(padded(8192)), 200, ACTIVE);
    expectAnswer(await post(padded(8193)), 200, INACTIVE);
    expectAnswer(await post(`token=${"a".repeat(8192)}`), 200, INACTIVE);
  });
});

/** A real server, raw bytes in and out. */
async function withServer<T>(f: (port: number) => Promise<T>): Promise<T> {
  const server = createHttpServer(app());
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  try {
    return await f((server.address() as AddressInfo).port);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
}

/** Writes `parts` (strings, or pauses in ms), reads until `until` holds or the socket closes. */
function exchange(port: number, parts: (string | number)[], until: (got: string) => boolean, limitMs = 5000) {
  return new Promise<{ got: string; closed: boolean }>((resolve) => {
    const s = net.connect(port, "127.0.0.1");
    let got = "";
    let done = false;
    const finish = (closed: boolean): void => {
      if (done) return;
      done = true;
      s.destroy();
      resolve({ got, closed });
    };
    s.on("error", () => undefined);
    s.on("data", (d: Buffer) => {
      got += d.toString("latin1");
      if (until(got)) finish(false);
    });
    s.on("close", () => {
      finish(true);
    });
    setTimeout(() => {
      finish(false);
    }, limitMs).unref();
    void (async () => {
      for (const p of parts) {
        if (typeof p === "number") await new Promise((r) => setTimeout(r, p));
        else if (!s.destroyed) s.write(p, "latin1");
      }
    })();
  });
}

const bodyOf = (got: string): string => got.slice(got.indexOf("\r\n\r\n") + 4);
const lengthHead = (headers: string, length: number) => `POST /auth/v1/introspect HTTP/1.1\r\nHost: x\r\n${headers}Content-Length: ${String(length)}\r\n\r\n`;
const chunked = (body: string): string => `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`;

describe("on the wire", () => {
  it("reads the FIRST of two X-Introspection-Secret headers (Node would join them)", async () => {
    await withServer(async (port) => {
      const body = `token=${jwt()}`;
      const first = await exchange(port, [lengthHead(`Content-Type: ${FORM}\r\nX-Introspection-Secret: ${SECRET}\r\nx-introspection-secret: wrong\r\n`, body.length) + body], (g) => g.includes("}\n"));
      expect(first.got).toMatch(/^HTTP\/1\.1 200 /);
      expect(JSON.parse(bodyOf(first.got))).toEqual(ACTIVE);
      const second = await exchange(port, [lengthHead(`Content-Type: ${FORM}\r\nX-Introspection-Secret: wrong\r\nX-Introspection-Secret: ${SECRET}\r\n`, body.length) + body], (g) => g.includes("}\n"));
      expect(second.got).toMatch(/^HTTP\/1\.1 401 /);
    });
  });

  it("does not read a form body that declares no content type, or an empty one (application/octet-stream to Go)", async () => {
    await withServer(async (port) => {
      const body = `token=${jwt()}`;
      for (const contentType of ["", "Content-Type: \r\n"]) {
        const r = await exchange(port, [lengthHead(`${contentType}X-Introspection-Secret: ${SECRET}\r\n`, body.length) + body], (g) => g.includes("}\n"));
        expect(JSON.parse(bodyOf(r.got))).toEqual(INACTIVE);
      }
    });
  });

  it("ignores whitespace around the secret's value and the header name's case", async () => {
    await withServer(async (port) => {
      const body = `token=${jwt()}`;
      const r = await exchange(port, [lengthHead(`Content-Type: ${FORM}\r\nx-INTROSPECTION-secret: \t ${SECRET} \t\r\n`, body.length) + body], (g) => g.includes("}\n"));
      expect(JSON.parse(bodyOf(r.got))).toEqual(ACTIVE);
    });
  });

  it("applies the cap to a chunked body: 8192 accepted, 8193 not", async () => {
    await withServer(async (port) => {
      const head = `POST /auth/v1/introspect HTTP/1.1\r\nHost: x\r\nContent-Type: ${FORM}\r\nX-Introspection-Secret: ${SECRET}\r\nTransfer-Encoding: chunked\r\n\r\n`;
      const padded = (total: number): string => {
        const h = `token=${jwt()}&pad=`;
        return h + "a".repeat(total - h.length);
      };
      const ok = await exchange(port, [head + chunked(padded(8192))], (g) => g.includes("}\n"));
      expect(JSON.parse(bodyOf(ok.got))).toEqual(ACTIVE);
      const over = await exchange(port, [head + chunked(padded(8193))], (g) => g.includes("}\n"));
      expect(JSON.parse(bodyOf(over.got))).toEqual(INACTIVE);
    });
  });

  it("answers an endless body {active:false} after reading just past the cap, and closes the connection", async () => {
    await withServer(async (port) => {
      const head = `POST /auth/v1/introspect HTTP/1.1\r\nHost: x\r\nContent-Type: ${FORM}\r\nX-Introspection-Secret: ${SECRET}\r\nTransfer-Encoding: chunked\r\n\r\n`;
      const parts: (string | number)[] = [head];
      for (let i = 0; i < 400; i++) parts.push(`4000\r\n${"a".repeat(0x4000)}\r\n`, 5);
      const r = await exchange(port, parts, () => false, 8000);
      expect(r.closed).toBe(true);
      expect(r.got).toMatch(/^HTTP\/1\.1 200 /);
      expect(JSON.parse(bodyOf(r.got))).toEqual(INACTIVE);
    });
  });

  it("sends 100 Continue only once it reads the body: never to a wrong secret, never for a body it does not read", async () => {
    await withServer(async (port) => {
      const body = `token=${jwt()}`;
      const expect100 = "Expect: 100-continue\r\n";
      const good = await exchange(port, [lengthHead(`${expect100}Content-Type: ${FORM}\r\nX-Introspection-Secret: ${SECRET}\r\n`, body.length)], (g) => g.includes("100 Continue"), 2000);
      expect(good.got).toMatch(/^HTTP\/1\.1 100 Continue\r\n\r\n/);
      const wrong = await exchange(port, [lengthHead(`${expect100}Content-Type: ${FORM}\r\nX-Introspection-Secret: wrong\r\n`, body.length)], (g) => g.includes("}\n"), 2000);
      expect(wrong.got).toMatch(/^HTTP\/1\.1 401 /);
      expect(wrong.got).not.toContain("100 Continue");
      const json = await exchange(port, [lengthHead(`${expect100}Content-Type: application/json\r\nX-Introspection-Secret: ${SECRET}\r\n`, body.length)], (g) => g.includes("}\n"), 2000);
      expect(json.got).not.toContain("100 Continue");
      expect(JSON.parse(bodyOf(json.got))).toEqual(INACTIVE);
    });
  });

  it("does not send 100 Continue to HTTP/1.0", async () => {
    await withServer(async (port) => {
      const body = `token=${jwt()}`;
      const head = `POST /auth/v1/introspect HTTP/1.0\r\nExpect: 100-continue\r\nContent-Type: ${FORM}\r\nX-Introspection-Secret: ${SECRET}\r\nContent-Length: ${String(body.length)}\r\n\r\n`;
      const r = await exchange(port, [head, 300, body], (g) => g.includes("}\n"), 3000);
      expect(r.got).not.toContain("100 Continue");
      expect(JSON.parse(bodyOf(r.got))).toEqual(ACTIVE);
    });
  });

  it("survives a caller that hangs up mid-body, and keeps serving", async () => {
    await withServer(async (port) => {
      const gone = await exchange(port, [lengthHead(`Content-Type: ${FORM}\r\nX-Introspection-Secret: ${SECRET}\r\n`, 1000) + "token=abc"], () => true, 300);
      expect(gone.got).toBe("");
      const body = `token=${jwt()}`;
      const r = await exchange(port, [lengthHead(`Content-Type: ${FORM}\r\nX-Introspection-Secret: ${SECRET}\r\n`, body.length) + body], (g) => g.includes("}\n"));
      expect(JSON.parse(bodyOf(r.got))).toEqual(ACTIVE);
    });
  });
});
