// A Lab is one test file's world: generated keys and secrets, the two stub
// upstreams, and a way to start the service wired to them.
import { generateRsa, nowSeconds, randomSecret, signJwt } from "./crypto.ts";
import type { Claims, RsaKeyPair } from "./crypto.ts";
import { send } from "./http.ts";
import type { Reply, RequestOptions } from "./http.ts";
import { newVolume, startExpectingExit, startService, stubHost } from "./service.ts";
import type { Env, FailedStart, Service, Volume } from "./service.ts";
import { ClerkStub, SpaceTradersStub } from "./stubs.ts";

export const CALLERS = {
  automation: { name: "automation-service", scope: "fleet:control", suffix: "AUTOMATION_SERVICE" },
  ai: { name: "ai-service", scope: "events:write planner:advise", suffix: "AI_SERVICE" },
} as const;

export type M2MMode = "dev" | "clerk" | "none";

export interface StartOptions {
  /** Which trust anchor mints machine tokens. Default "dev". */
  m2m?: M2MMode;
  /** Overrides on top of the defaults. An undefined value removes the variable. */
  env?: Env;
  files?: Record<string, string>;
  volume?: Volume;
}

export class Lab {
  readonly clerkKey: RsaKeyPair = generateRsa();
  /** A second keypair nothing trusts: for forged signatures and for a mismatched dev signer. */
  readonly foreignKey: RsaKeyPair = generateRsa();
  readonly secrets = {
    shared: randomSecret("shared"),
    introspection: randomSecret("introspection"),
    callerAutomation: randomSecret("caller-automation"),
    callerAi: randomSecret("caller-ai"),
    machineAutomation: randomSecret("machine-automation"),
    machineAi: randomSecret("machine-ai"),
  };
  private readonly running = new Set<Service>();

  readonly st: SpaceTradersStub;
  readonly clerk: ClerkStub;

  private constructor(st: SpaceTradersStub, clerk: ClerkStub) {
    this.st = st;
    this.clerk = clerk;
  }

  static async create(): Promise<Lab> {
    return new Lab(await SpaceTradersStub.start(), await ClerkStub.start());
  }

  stubUrl(port: number): string {
    return `http://${stubHost}:${port}`;
  }

  /** The environment of a healthy, fully configured service. */
  baseEnv(m2m: M2MMode = "dev"): { env: Env; files: Record<string, string> } {
    const env: Env = {
      PORT: "8080",
      CLERK_JWT_KEY: this.clerkKey.publicPem,
      AUTH_SERVICE_SHARED_SECRET: this.secrets.shared,
      AUTH_INTROSPECTION_SECRET: this.secrets.introspection,
      ST_GATEWAY_URL: this.stubUrl(this.st.port),
    };
    const files: Record<string, string> = {};
    if (m2m !== "none") {
      env.M2M_CALLER_SECRET_AUTOMATION_SERVICE = this.secrets.callerAutomation;
      env.M2M_CALLER_SECRET_AI_SERVICE = this.secrets.callerAi;
    }
    if (m2m === "dev") {
      // The dev signer is the very key the service verifies with, so a minted token introspects as active.
      files["dev-m2m.pem"] = this.clerkKey.privatePem;
      env.DEV_M2M_SIGNING_KEY_FILE = "@file:dev-m2m.pem";
    }
    if (m2m === "clerk") {
      env.M2M_MACHINE_KEY_AUTOMATION_SERVICE = this.secrets.machineAutomation;
      env.M2M_MACHINE_KEY_AI_SERVICE = this.secrets.machineAi;
      env.CLERK_API_BASE_URL = this.stubUrl(this.clerk.port);
    }
    return { env, files };
  }

  private spec(opts: StartOptions) {
    const base = this.baseEnv(opts.m2m ?? "dev");
    return {
      env: { ...base.env, ...opts.env },
      files: { ...base.files, ...opts.files },
      // Always a volume of its own: the service must never write into the working directory.
      volume: opts.volume ?? newVolume(),
    };
  }

  newVolume(): Volume {
    return newVolume();
  }

  async start(opts: StartOptions = {}): Promise<Api> {
    const svc = await startService(this.spec(opts));
    this.running.add(svc);
    void svc.exited.then(() => this.running.delete(svc));
    return new Api(svc, this);
  }

  /** For configurations the service must refuse: resolves with its exit code and output. */
  startExpectingExit(opts: StartOptions = {}): Promise<FailedStart> {
    return startExpectingExit(this.spec(opts));
  }

  async close(): Promise<void> {
    await Promise.all([...this.running].map((s) => s.stop()));
    await this.st.close();
    await this.clerk.close();
  }

  // ---- tokens ----

  /** A Clerk-shaped session or machine token signed with the trusted key. */
  token(claims: Claims = {}, key: RsaKeyPair = this.clerkKey): string {
    return signJwt(
      { sub: "user_contract_operator", scope: "agent:reset", iat: nowSeconds(), exp: nowSeconds() + 3600, ...claims },
      { key: key.privateKey },
    );
  }

  /** A Clerk M2M token as the Clerk stub hands it back. Every call yields a different token (jti). */
  stubMachineToken(scope: string, lifetimeSeconds = 86400, iatOffset = 0, extra: Claims = {}): string {
    const iat = nowSeconds() + iatOffset;
    return this.token({ sub: "mch_stub_machine", scope, iat, exp: iat + lifetimeSeconds, jti: randomSecret("jti"), ...extra });
  }

  /** The token healthyClerk() most recently handed out. */
  lastMintedToken = "";

  /** Make the Clerk stub behave: mint what it is asked for, signed by the key the service verifies with. */
  healthyClerk(opts: { lifetimeSeconds?: number; iatOffset?: number; delayMs?: number } = {}): void {
    this.clerk.handler = (call) => {
      const asked = JSON.parse(call.body || "{}") as { claims?: { scope?: string } };
      this.lastMintedToken = this.stubMachineToken(asked.claims?.scope ?? "", opts.lifetimeSeconds ?? 86400, opts.iatOffset ?? 0);
      return { status: 200, delayMs: opts.delayMs, body: { token: this.lastMintedToken } };
    };
  }
}

/** The running service, with the requests the suite makes most. */
export class Api {
  readonly svc: Service;
  readonly lab: Lab;

  constructor(svc: Service, lab: Lab) {
    this.svc = svc;
    this.lab = lab;
  }

  get port(): number {
    return this.svc.port;
  }
  output(): string {
    return this.svc.output();
  }
  stop(): Promise<void> {
    return this.svc.stop();
  }

  req(opts: RequestOptions): Promise<Reply> {
    return send(this.svc.port, opts);
  }

  get(path: string, headers?: Record<string, string>): Promise<Reply> {
    return send(this.svc.port, { path, headers });
  }

  postJson(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Reply> {
    return send(this.svc.port, {
      method: "POST",
      path,
      headers: { "content-type": "application/json", ...headers },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
  }

  /** secret: undefined means the right one, null means send no header. */
  introspect(token: string | undefined, secret: string | null | undefined = undefined): Promise<Reply> {
    const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
    const s = secret === undefined ? this.lab.secrets.introspection : secret;
    if (s !== null) headers["x-introspection-secret"] = s;
    return send(this.svc.port, {
      method: "POST",
      path: "/auth/v1/introspect",
      headers,
      body: token === undefined ? "" : `token=${encodeURIComponent(token)}`,
    });
  }

  /** secret: undefined means the right one, null means send no header. */
  agentToken(secret: string | null | undefined = undefined, query = ""): Promise<Reply> {
    const s = secret === undefined ? this.lab.secrets.shared : secret;
    return send(this.svc.port, {
      path: `/auth/v1/token${query}`,
      headers: s === null ? {} : { "x-auth-service-secret": s },
    });
  }

  /** secret: null means send no header. */
  m2m(secret: string | null): Promise<Reply> {
    return send(this.svc.port, {
      method: "POST",
      path: "/auth/v1/m2m-token",
      headers: secret === null ? {} : { "x-m2m-caller-secret": secret },
    });
  }

  status(path = "/auth/v1/status"): Promise<Reply> {
    return this.get(path);
  }

  /** POST /api/auth/v1/register with a session carrying agent:reset. */
  register(body: unknown, token = this.lab.token()): Promise<Reply> {
    return this.postJson("/api/auth/v1/register", body, { authorization: `Bearer ${token}` });
  }

  restore(body: unknown, token = this.lab.token()): Promise<Reply> {
    return this.postJson("/api/auth/v1/agent-token", body, { authorization: `Bearer ${token}` });
  }
}
