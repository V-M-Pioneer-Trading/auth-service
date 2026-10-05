/**
 * The SpaceTraders client against a real HTTP server standing in for st-gateway: what is sent (path, headers, body),
 * how answers are read (Go's json.Unmarshal, status mapping), and the 30 s bound on the whole exchange.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

import { GoJsonError } from "../goJson";
import { formatRfc3339 } from "../goTime";
import { describeError, parseFlexibleTime, spaceTradersClient, TransportError, UPSTREAM_TIMEOUT_MS, UpstreamError } from "../spacetraders/client";

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  rawHeaders: string[];
  body: Buffer;
}

let server: http.Server;
let base: string;
let seen: Seen[] = [];
let reply: (req: http.IncomingMessage, res: http.ServerResponse) => void = (_req, res) => res.end("{}");

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, rawHeaders: req.rawHeaders, body: Buffer.concat(chunks) });
      reply(req, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}/proxy`;
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
});
beforeEach(() => {
  seen = [];
  reply = (_req, res) => res.end("{}");
});

const json = (status: number, body: string) => (_req: http.IncomingMessage, res: http.ServerResponse) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
};

describe("GET / (the unauthenticated root)", () => {
  it("asks {ST_GATEWAY_URL}/proxy/ with no Authorization header and reads the two dates", async () => {
    reply = json(200, '{"resetDate":"2026-09-01","serverResets":{"next":"2099-03-04T05:06:07.891+05:30","frequency":"weekly"},"status":"online"}');
    const root = await spaceTradersClient({ baseUrl: base }).getRoot();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ method: "GET", url: "/proxy/" });
    expect(seen[0]?.headers.authorization).toBeUndefined();
    expect(root.resetDate && formatRfc3339(root.resetDate)).toBe("2026-09-01T00:00:00Z");
    expect(root.nextReset && formatRfc3339(root.nextReset)).toBe("2099-03-04T05:06:07+05:30");
    expect(root.frequency).toBe("weekly");
  });

  it("reads absent or unparseable dates as zero (null)", async () => {
    reply = json(200, '{"resetDate":"not-a-date"}');
    expect(await spaceTradersClient({ baseUrl: base }).getRoot()).toEqual({ resetDate: null, nextReset: null, frequency: "" });
  });

  it("is an UpstreamError for a status of 400 or more, carrying upstream's body for the operator only", async () => {
    for (const status of [400, 404, 500, 503]) {
      reply = json(status, "upstream-body-sentinel");
      const err = await spaceTradersClient({ baseUrl: base }).getRoot().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(UpstreamError);
      expect((err as UpstreamError).status).toBe(status);
      expect((err as UpstreamError).answer.toString()).toBe("GET /: upstream-body-sentinel");
      expect(describeError(err)).toBe(`spacetraders upstream error (${String(status)}) on GET /`);
    }
  });

  it("is a decode error for a 2xx that is not exactly one JSON value", async () => {
    for (const body of ["", "not json", "<html></html>", '{"resetDate":"2026-09-01"} trailing', '{"resetDate":5}']) {
      reply = json(200, body);
      await expect(spaceTradersClient({ baseUrl: base }).getRoot()).rejects.toBeInstanceOf(GoJsonError);
    }
  });
});

describe("POST /register", () => {
  it("sends the account token as the bearer, JSON, and {symbol, faction} without email when it is empty", async () => {
    reply = json(201, '{"data":{"token":"t-new","agent":{"symbol":"S","credits":175000}}}');
    const result = await spaceTradersClient({ baseUrl: base }).register("account-token-1", "CONTRACT-1", "COSMIC", "");
    expect(result).toEqual({ agentToken: "t-new", agentSymbol: "S", credits: 175000n });
    expect(seen[0]).toMatchObject({ method: "POST", url: "/proxy/register" });
    expect(seen[0]?.headers.authorization).toBe("Bearer account-token-1");
    expect(seen[0]?.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(seen[0]?.body.toString() ?? "")).toEqual({ symbol: "CONTRACT-1", faction: "COSMIC" });
  });

  it("includes email when there is one, and passes every string through untouched, as UTF-8", async () => {
    reply = json(201, '{"data":{"token":"t"}}');
    await spaceTradersClient({ baseUrl: base }).register("spaced tok én", "ünï", "x y", "pilot@example.com");
    expect(JSON.parse(seen[0]?.body.toString("utf8") ?? "")).toEqual({ symbol: "ünï", faction: "x y", email: "pilot@example.com" });
    const i = seen[0]?.rawHeaders.findIndex((h) => h.toLowerCase() === "authorization") ?? -1;
    expect(Buffer.from(seen[0]?.rawHeaders[i + 1] ?? "", "latin1").toString("utf8")).toBe("Bearer spaced tok én");
  });

  it("refuses an account token that cannot be a header value, sending nothing", async () => {
    for (const bad of ["a\nb", "a\rb", "a\u0001b", "a\u0000b"]) {
      await expect(spaceTradersClient({ baseUrl: base }).register(bad, "S", "F", "")).rejects.toBeInstanceOf(TransportError);
    }
    expect(seen).toHaveLength(0);
  });

  it("accepts any 2xx, and reads one with no token as an empty token", async () => {
    reply = json(200, '{"data":{"agent":{"symbol":"NOTOKEN"}}}');
    expect(await spaceTradersClient({ baseUrl: base }).register("a", "S", "F", "")).toEqual({ agentToken: "", agentSymbol: "NOTOKEN", credits: 0n });
  });

  it("passes the status and raw body of a refusal along", async () => {
    reply = (_req, res) => {
      res.writeHead(409);
      res.end(Buffer.from([0x7b, 0xff, 0x7d]));
    };
    const err = (await spaceTradersClient({ baseUrl: base }).register("a", "S", "F", "").catch((e: unknown) => e)) as UpstreamError;
    expect(err.status).toBe(409);
    expect(err.answer).toEqual(Buffer.from([...Buffer.from("POST /register: "), 0x7b, 0xff, 0x7d]));
    expect(err.message).not.toContain("{");
  });

  it("is a decode error for a credits value Go's int would refuse", async () => {
    reply = json(201, '{"data":{"token":"t","agent":{"credits":1.5}}}');
    await expect(spaceTradersClient({ baseUrl: base }).register("a", "S", "F", "")).rejects.toBeInstanceOf(GoJsonError);
  });
});

describe("the bound on an exchange", () => {
  it("is 30 s", () => {
    expect(UPSTREAM_TIMEOUT_MS).toBe(30_000);
  });

  it("abandons a call that is not answered within it, by default 30 s", async () => {
    jest.useFakeTimers();
    try {
      let signal: AbortSignal | undefined;
      const hanging: typeof fetch = (_url, init) =>
        new Promise((_resolve, reject) => {
          signal = init?.signal ?? undefined;
          signal?.addEventListener("abort", () => { reject(new DOMException("aborted", "AbortError")); });
        });
      let settled: unknown = "pending";
      void spaceTradersClient({ baseUrl: base, fetch: hanging })
        .getRoot()
        .catch((e: unknown) => (settled = e));
      await jest.advanceTimersByTimeAsync(29_999);
      expect(settled).toBe("pending");
      await jest.advanceTimersByTimeAsync(1);
      expect(settled).toBeInstanceOf(TransportError);
      expect(describeError(settled)).toBe("GET /: request abandoned (timeout or shutdown)");
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      jest.useRealTimers();
    }
  });

  it("covers the body too: an answer whose body stalls is abandoned", async () => {
    reply = (_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"resetDate":');
    };
    const started = Date.now();
    await expect(spaceTradersClient({ baseUrl: base, timeoutMs: 200 }).getRoot()).rejects.toBeInstanceOf(TransportError);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("is cut short by the caller's signal (shutdown), and a signal already aborted sends nothing", async () => {
    reply = () => undefined; // never answers
    const abort = new AbortController();
    const call = spaceTradersClient({ baseUrl: base }).getRoot(abort.signal);
    await new Promise((r) => setTimeout(r, 50));
    abort.abort();
    await expect(call).rejects.toBeInstanceOf(TransportError);
    const before = seen.length;
    await expect(spaceTradersClient({ baseUrl: base }).getRoot(abort.signal)).rejects.toBeInstanceOf(TransportError);
    expect(seen.length).toBe(before);
  });

  it("says why a call failed by code, never by URL or header", async () => {
    const err = await spaceTradersClient({ baseUrl: "http://127.0.0.1:1/proxy" })
      .register("account-token-sentinel", "S", "F", "")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TransportError);
    expect(describeError(err)).toMatch(/^POST \/register: request failed( \([A-Z0-9_]+\))?$/);
    expect(describeError(err)).not.toContain("127.0.0.1");
  });
});

describe("parseFlexibleTime", () => {
  it("is RFC 3339, else a bare date at midnight UTC, else zero", () => {
    expect(parseFlexibleTime("")).toBeNull();
    expect(parseFlexibleTime("garbage")).toBeNull();
    expect(parseFlexibleTime("0001-01-01T00:00:00Z")).toBeNull();
    const d = parseFlexibleTime("2026-09-01");
    expect(d && formatRfc3339(d)).toBe("2026-09-01T00:00:00Z");
  });
});
