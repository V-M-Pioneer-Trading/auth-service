/**
 * What the HTTP server does on real sockets: an answer that leaves a request body unread, the header timeout, a request
 * Node cannot parse, `Expect: 100-continue`. Hardening ported from agent-service's proven server (see its CLAUDE.md);
 * every case here has a Go net/http behaviour it matches.
 */
import net from "node:net";
import type { AddressInfo } from "node:net";

import { clientErrorAnswer, createHttpServer } from "../server";
import { credential, createTestApp } from "../testSupport/createTestApp";

jest.setTimeout(30000);

async function listen() {
  const server = createHttpServer(createTestApp(credential()));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: (server.address() as AddressInfo).port };
}

/** Sends `head`, then `chunk` every 5 ms until the server closes the connection; reports what it said and how long it took. */
function flood(port: number, head: string, chunk: string) {
  return new Promise<{ status: string; closedAfterMs: number; sent: number }>((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    const t0 = Date.now();
    let received = "";
    let sent = 0;
    const timer = setInterval(() => {
      if (socket.destroyed) return;
      sent += chunk.length;
      socket.write(chunk, () => undefined);
    }, 5);
    socket.on("error", () => undefined);
    socket.on("data", (d: Buffer) => (received += d.toString("latin1")));
    socket.on("close", () => {
      clearInterval(timer);
      resolve({ status: received.split("\r\n", 1)[0] ?? "", closedAfterMs: Date.now() - t0, sent });
    });
    socket.write(head);
  });
}
const CHUNKED = (path: string) => `POST ${path} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n`;
const chunk = `10000\r\n${"a".repeat(0x10000)}\r\n`;

/** Writes `parts` in order, waits for `until` to be true of what came back (or the socket to close), and reports it. */
function exchange(port: number, parts: (string | number)[], until: (got: string) => boolean, limitMs = 5000) {
  return new Promise<{ got: string; ms: number; closed: boolean }>((resolve) => {
    const s = net.connect(port, "127.0.0.1");
    const t0 = Date.now();
    let got = "";
    let done = false;
    const finish = (closed: boolean): void => {
      if (done) return;
      done = true;
      s.destroy();
      resolve({ got, ms: Date.now() - t0, closed });
    };
    s.on("error", () => undefined);
    s.on("data", (d: Buffer) => {
      got += d.toString("latin1");
      if (until(got)) finish(false);
    });
    s.on("close", () => { finish(true); });
    setTimeout(() => { finish(false); }, limitMs).unref();
    void (async () => {
      for (const p of parts) {
        if (typeof p === "number") await new Promise((r) => setTimeout(r, p));
        else s.write(p, "latin1");
      }
    })();
  });
}
const BODY_200K = "x".repeat(200_000);
const POST = (path: string, length: number) => `POST ${path} HTTP/1.1\r\nHost: x\r\nContent-Length: ${String(length)}\r\n\r\n`;

describe("an answer that leaves the request body unread closes the connection", () => {
  it("an endless chunked body to a route that answers 405 without reading it: closed within a second or so, bounded upload", async () => {
    const { server, port } = await listen();
    const r = await flood(port, CHUNKED("/health"), chunk);
    expect(r.status).toBe("HTTP/1.1 405 Method Not Allowed");
    expect(r.closedAfterMs).toBeLessThan(3000);
    expect(r.sent).toBeLessThan(64 << 20);
    server.close();
  });

  it("the same under /api/auth, where the answer is 404", async () => {
    const { server, port } = await listen();
    const r = await flood(port, CHUNKED("/api/auth/health"), chunk);
    expect(r.status).toBe("HTTP/1.1 404 Not Found");
    expect(r.closedAfterMs).toBeLessThan(3000);
    server.close();
  });

  it("a body that did arrive in full keeps the connection: two requests on one socket", async () => {
    const { server, port } = await listen();
    const answers = await new Promise<string>((resolve) => {
      const s = net.connect(port, "127.0.0.1");
      let got = "";
      s.on("data", (d: Buffer) => {
        got += d.toString();
        if ((got.match(/HTTP\/1\.1 405/g) ?? []).length === 2) {
          s.destroy();
          resolve(got);
        }
      });
      const req = "POST /health HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}";
      s.write(req + req);
    });
    expect((answers.match(/HTTP\/1\.1 405/g) ?? []).length).toBe(2);
    server.close();
  });
});

describe("an unread body does not wedge the connection (other callers share it behind a proxy)", () => {
  it("200 KB sent to a 405, then a second request on the same socket: answered within a second, no 408 anywhere", async () => {
    const { server, port } = await listen();
    const r = await exchange(port, [POST("/health", 200_000) + BODY_200K, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n"], (g) => g.includes('"status":"ok"'), 3000);
    expect(r.got).toContain('"status":"ok"');
    expect(r.ms).toBeLessThan(1000);
    expect(r.got).not.toContain("408");
    server.close();
  });

  it("a partial body and then silence: closed at about a second, with no 408", async () => {
    const { server, port } = await listen();
    const r = await exchange(port, [POST("/health", 100_000) + "x".repeat(1000)], () => false, 6000);
    expect(r.closed).toBe(true);
    expect(r.got.split("\r\n", 1)[0]).toBe("HTTP/1.1 405 Method Not Allowed");
    expect(r.ms).toBeGreaterThanOrEqual(900);
    expect(r.ms).toBeLessThan(3500);
    expect(r.got).not.toContain("408");
    server.close();
  });
});

describe("the header timeout is 10 s, checked every second", () => {
  it("is configured so", async () => {
    const { server } = await listen();
    expect([server.headersTimeout, server.requestTimeout, server.keepAliveTimeout]).toEqual([10_000, 30_000, 120_000]);
    server.close();
  });

  it("slow headers are cut off at about 10 s, not 30 or more, and are not answered with a 408", async () => {
    const { server, port } = await listen();
    const t0 = Date.now();
    let got = "";
    const closed = await new Promise<number>((resolve) => {
      const s = net.connect(port, "127.0.0.1");
      s.on("close", () => { resolve(Date.now() - t0); });
      s.on("error", () => undefined);
      s.on("data", (d: Buffer) => (got += d.toString()));
      s.write("GET /health HTTP/1.1\r\nHost: x\r\n");
    });
    expect(closed).toBeGreaterThanOrEqual(9000);
    expect(closed).toBeLessThan(14000);
    expect(got).toBe("");
    server.close();
  });
});

describe("Expect: 100-continue", () => {
  const head = (path: string) => `POST ${path} HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n`;

  it("is not answered with 100 by a route that does not read the body: the caller is told 405 and uploads nothing", async () => {
    const { server, port } = await listen();
    const r = await exchange(port, [head("/health")], (g) => g.includes("405"), 3000);
    expect(r.got).not.toContain("100 Continue");
    expect(r.got).toContain("HTTP/1.1 405");
    server.close();
  });

  it("is not sent to an HTTP/1.0 client, which has no such thing", async () => {
    const { server, port } = await listen();
    const r = await exchange(port, ["POST /health HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n", 200, "{}"], (g) => g.includes("405"), 2000);
    expect(r.got).not.toContain("100 Continue");
    expect(r.got).toContain("405");
    server.close();
  });
});

describe("a request Node cannot parse", () => {
  it("is answered with exactly these bytes, CRLFs and no body, and the socket is closed afterwards", async () => {
    const { server, port } = await listen();
    const bad = await exchange(port, ["GARBAGE\r\n\r\n"], () => false, 3000);
    expect(bad.got).toBe("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    expect(bad.closed).toBe(true);
    const big = await exchange(port, ["GET /health HTTP/1.1\r\nHost: x\r\nX: " + "a".repeat(100_000) + "\r\n\r\n"], () => false, 3000);
    expect(big.got).toBe("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n");
    expect(big.closed).toBe(true);
    server.close();
  });

  it("clientErrorAnswer is written with explicit CRLFs", () => {
    expect(clientErrorAnswer(Object.assign(new Error("x"), { code: "HPE_INVALID_METHOD" }))).toBe("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    expect(clientErrorAnswer(Object.assign(new Error("x"), { code: "HPE_HEADER_OVERFLOW" }))).toBe("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n");
  });
});

describe("absolute-form request targets are routed on their path, as Go does", () => {
  it("GET http://host/health is the health route, and an empty path is the 301 to /", async () => {
    const { server, port } = await listen();
    const ok = await exchange(port, ["GET http://example.test/health HTTP/1.1\r\nHost: x\r\n\r\n"], (g) => g.includes('"status":"ok"'), 3000);
    expect(ok.got).toContain("HTTP/1.1 200");
    const empty = await exchange(port, ["GET http://example.test HTTP/1.1\r\nHost: x\r\n\r\n"], (g) => g.includes("\r\n\r\n"), 3000);
    expect(empty.got).toContain("HTTP/1.1 301");
    expect(empty.got.toLowerCase()).toContain("location: /\r\n");
    const fragment = await exchange(port, ["GET http://h#f HTTP/1.1\r\nHost: x\r\n\r\n"], (g) => g.includes("\r\n\r\n"), 3000);
    expect(fragment.got).toContain("HTTP/1.1 400");
    server.close();
  });
});
