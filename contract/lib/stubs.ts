// Stub upstreams, served from the test process on 0.0.0.0 so a container can
// reach them as host.docker.internal.
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { sleep } from "./http.ts";

export interface Call {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  at: number;
}

export interface StubReply {
  status?: number;
  headers?: Record<string, string>;
  /** Objects are JSON-encoded; strings are sent verbatim. */
  body?: unknown;
  delayMs?: number;
  /** Close the socket without answering. */
  destroy?: boolean;
}

export type StubHandler = (call: Call, nth: number) => StubReply | Promise<StubReply>;

export class Stub {
  readonly calls: Call[] = [];
  handler: StubHandler;
  readonly port: number;
  private readonly server: Server;

  private constructor(server: Server, port: number, handler: StubHandler) {
    this.server = server;
    this.port = port;
    this.handler = handler;
  }

  static async start(handler: StubHandler): Promise<Stub> {
    let stub!: Stub;
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", async () => {
        const call: Call = {
          method: req.method ?? "",
          path: req.url ?? "",
          headers: req.headers,
          body: Buffer.concat(chunks).toString("utf8"),
          at: Date.now(),
        };
        stub.calls.push(call);
        try {
          const reply = await stub.handler(call, stub.calls.length);
          if (reply.delayMs) await sleep(reply.delayMs);
          if (reply.destroy) {
            req.socket.destroy();
            return;
          }
          const isJson = reply.body !== undefined && typeof reply.body !== "string";
          const body = reply.body === undefined ? "" : typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body);
          res.writeHead(reply.status ?? 200, { ...(isJson ? { "content-type": "application/json" } : {}), ...reply.headers });
          res.end(body);
        } catch (err) {
          res.writeHead(500);
          res.end(String(err));
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "0.0.0.0", resolve));
    stub = new Stub(server, (server.address() as AddressInfo).port, handler);
    return stub;
  }

  callsTo(method: string, path: string): Call[] {
    return this.calls.filter((c) => c.method === method && c.path === path);
  }

  clear(): void {
    this.calls.length = 0;
  }

  close(): Promise<void> {
    this.server.closeAllConnections();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }
}

export interface RootDoc {
  resetDate?: string;
  serverResets?: { next?: string; frequency?: string };
  [k: string]: unknown;
}

/**
 * SpaceTraders as the service sees it through st-gateway:
 *   GET  {ST_GATEWAY_URL}/proxy/          unauthenticated root (resetDate, serverResets)
 *   POST {ST_GATEWAY_URL}/proxy/register  agent registration
 */
export class SpaceTradersStub {
  root: StubReply = SpaceTradersStub.defaultRoot();
  /** How many registrations have been answered; tokens are agent-token-<n>. Survives clear(), not reset(). */
  registrations = 0;
  register: (call: Call, nth: number) => StubReply = (call) => this.defaultRegister(call);
  private inner!: Stub;

  static async start(): Promise<SpaceTradersStub> {
    const s = new SpaceTradersStub();
    s.inner = await Stub.start((call, nth) => {
      if (call.method === "GET" && call.path === "/proxy/") return s.root;
      if (call.method === "POST" && call.path === "/proxy/register") return s.register(call, nth);
      return { status: 404, body: "unexpected call to the SpaceTraders stub" };
    });
    return s;
  }

  get port(): number {
    return this.inner.port;
  }
  get calls(): Call[] {
    return this.inner.calls;
  }
  rootCalls(): Call[] {
    return this.inner.callsTo("GET", "/proxy/");
  }
  registerCalls(): Call[] {
    return this.inner.callsTo("POST", "/proxy/register");
  }
  /** Calls to anything else: a regression signal, the service should make none. */
  strayCalls(): Call[] {
    return this.inner.calls.filter((c) => c.path !== "/proxy/" && c.path !== "/proxy/register");
  }
  setRoot(resetDate: string | undefined, next: string | undefined): void {
    const doc: RootDoc = {};
    if (resetDate !== undefined) doc.resetDate = resetDate;
    if (next !== undefined) doc.serverResets = { next, frequency: "fortnightly" };
    this.root = { status: 200, body: doc };
  }
  /** Forget recorded calls, keep the configured answers. */
  clear(): void {
    this.inner.clear();
  }
  /** Back to a pristine stub: no calls, default answers, token numbering from 1. */
  reset(): void {
    this.inner.clear();
    this.registrations = 0;
    this.root = SpaceTradersStub.defaultRoot();
    this.register = (call) => this.defaultRegister(call);
  }
  static defaultRoot(): StubReply {
    return { status: 200, body: { resetDate: "2026-09-01", serverResets: { next: "2099-01-01T00:00:00Z", frequency: "fortnightly" } } };
  }
  /** The agent SpaceTraders hands back: the requested symbol, a numbered token. */
  defaultRegister(call: Call): StubReply {
    const req = JSON.parse(call.body || "{}") as { symbol?: string };
    return { status: 201, body: { data: { token: `agent-token-${++this.registrations}`, agent: { symbol: req.symbol ?? "NOSYMBOL", credits: 175000 } } } };
  }
  close(): Promise<void> {
    return this.inner.close();
  }
}

/** Clerk's Backend API: POST /v1/m2m_tokens only. */
export class ClerkStub {
  handler: StubHandler = () => ({ status: 500 });
  private inner!: Stub;

  static async start(): Promise<ClerkStub> {
    const s = new ClerkStub();
    s.inner = await Stub.start((call, nth) => s.handler(call, nth));
    return s;
  }
  get port(): number {
    return this.inner.port;
  }
  get calls(): Call[] {
    return this.inner.calls;
  }
  mintCalls(): Call[] {
    return this.inner.callsTo("POST", "/v1/m2m_tokens");
  }
  clear(): void {
    this.inner.clear();
  }
  close(): Promise<void> {
    return this.inner.close();
  }
}
