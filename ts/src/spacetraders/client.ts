/**
 * @file The two SpaceTraders calls auth-service makes, through st-gateway's shared rate budget (`{ST_GATEWAY_URL}/proxy`):
 * the unauthenticated root (`GET /`, for `resetDate` and `serverResets.next`) and registration (`POST /register`, with
 * the account token as the bearer). Ported from the Go service's src/spacetraders/client.go.
 *
 *  - Every call is bounded: 30 s for the whole exchange, body included (Go's `http.Client{Timeout: 30 * time.Second}`),
 *    and abandoned at once when the caller's signal aborts (shutdown).
 *  - A status of 400 or more is an UpstreamError carrying upstream's raw body: the register route passes both through
 *    to the operator (contract README note 24). Anything else is decoded with Go's `json.Unmarshal` rules (goJson.ts),
 *    so a 2xx whose body is not the expected JSON is an error, and a 3xx with a body is read like a 2xx, as in Go.
 *  - Nothing here logs. An error's `message` never holds a credential; an UpstreamError's `body` is upstream's text and
 *    is for the operator's answer only, never for a log line (see `describeError`).
 */
import { isZeroTime, parseDateOnly, parseRfc3339, type GoTime } from "../goTime";
import { GoJsonError, unmarshal } from "../goJson";

/** The bound on one upstream exchange, body included. */
export const UPSTREAM_TIMEOUT_MS = 30_000;

/** A status of 400 or more from upstream. */
export class UpstreamError extends Error {
  /** What the operator is answered: `POST /register: ` and upstream's body, as raw bytes. */
  readonly answer: Buffer;
  constructor(
    readonly status: number,
    readonly what: string,
    body: Buffer,
  ) {
    // The message names the call and the status only: upstream's body stays out of anything that may be logged.
    super(`spacetraders upstream error (${String(status)}) on ${what}`);
    this.name = "UpstreamError";
    this.answer = Buffer.concat([Buffer.from(`${what}: `, "utf8"), body]);
  }
}

/** The call never got an answer: no connection, a reset, the timeout, or shutdown. */
export class TransportError extends Error {
  constructor(what: string, cause: unknown) {
    super(`${what}: ${transportReason(cause)}`);
    this.name = "TransportError";
  }
}

/** The reason a fetch failed, from its cause's code: never a URL, a header or a body. */
function transportReason(err: unknown): string {
  // By name, not instanceof: fetch's AbortError is a DOMException, of another realm under a test runner.
  const name = (err as { name?: unknown } | null)?.name;
  if (name === "AbortError" || name === "TimeoutError") return "request abandoned (timeout or shutdown)";
  const cause = (err as { cause?: unknown } | null)?.cause;
  const code = (cause as { code?: unknown } | undefined)?.code;
  if (typeof code === "string" && /^[A-Z0-9_]+$/.test(code)) return `request failed (${code})`;
  return "request failed";
}

/** What may be written to the log about an error from this module, the poller or the store. */
export function describeError(err: unknown): string {
  if (err instanceof UpstreamError || err instanceof TransportError || err instanceof GoJsonError) return err.message;
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return "unknown error";
}

export interface RootInfo {
  /** null when absent or unparseable (Go's zero Time). */
  readonly resetDate: GoTime | null;
  readonly nextReset: GoTime | null;
  readonly frequency: string;
}

export interface RegisterResult {
  readonly agentToken: string;
  readonly agentSymbol: string;
  readonly credits: bigint;
}

/** parseFlexibleTime: RFC 3339, else a bare date (midnight UTC), else zero (null). */
export function parseFlexibleTime(s: string): GoTime | null {
  if (s === "") return null;
  const t = parseRfc3339(s) ?? parseDateOnly(s);
  return t === null || isZeroTime(t) ? null : t;
}

const ROOT_SHAPE = { resetDate: "string", serverResets: { next: "string", frequency: "string" } } as const;
const REGISTER_SHAPE = { data: { token: "string", agent: { symbol: "string", credits: "int" } } } as const;

export interface SpaceTradersClient {
  getRoot(signal?: AbortSignal): Promise<RootInfo>;
  register(accountToken: string, symbol: string, faction: string, email: string, signal?: AbortSignal): Promise<RegisterResult>;
}

export interface ClientOptions {
  /** `{ST_GATEWAY_URL}/proxy`. */
  readonly baseUrl: string;
  /** Replaced in tests. */
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
}

export function spaceTradersClient(options: ClientOptions): SpaceTradersClient {
  const timeoutMs = options.timeoutMs ?? UPSTREAM_TIMEOUT_MS;
  const doFetch = options.fetch ?? fetch;

  /** One exchange, body read to the end, inside the timeout. */
  async function exchange(what: string, path: string, init: RequestInit, signal: AbortSignal | undefined): Promise<{ status: number; body: Buffer }> {
    const timeout = new AbortController();
    const timer = setTimeout(() => {
      timeout.abort();
    }, timeoutMs);
    const onAbort = (): void => {
      timeout.abort();
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted === true) timeout.abort();
    try {
      const res = await doFetch(options.baseUrl + path, { ...init, signal: timeout.signal });
      const body = Buffer.from(await res.arrayBuffer());
      return { status: res.status, body };
    } catch (err) {
      throw new TransportError(what, err);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }

  return {
    async getRoot(signal) {
      const what = "GET /";
      const { status, body } = await exchange(what, "/", { method: "GET" }, signal);
      if (status >= 400) throw new UpstreamError(status, what, body);
      const raw = unmarshal(body, ROOT_SHAPE, "spacetraders.rawRootResponse");
      return { resetDate: parseFlexibleTime(raw.resetDate), nextReset: parseFlexibleTime(raw.serverResets.next), frequency: raw.serverResets.frequency };
    },

    async register(accountToken, symbol, faction, email, signal) {
      const what = "POST /register";
      // email is omitted when empty (`json:"email,omitempty"`): it reserves the call sign across a reset when known.
      const payload = JSON.stringify(email === "" ? { symbol, faction } : { symbol, faction, email });
      const { status, body } = await exchange(
        what,
        "/register",
        { method: "POST", headers: { Authorization: `Bearer ${asHeaderBytes(accountToken)}`, "Content-Type": "application/json" }, body: payload },
        signal,
      );
      if (status >= 400) throw new UpstreamError(status, what, body);
      const raw = unmarshal(body, REGISTER_SHAPE, "spacetraders.rawRegisterResponse");
      return { agentToken: raw.data.token, agentSymbol: raw.data.agent.symbol, credits: raw.data.agent.credits };
    },
  };
}

/**
 * A header value as Go writes it: the string's UTF-8 bytes. fetch takes a header value as a ByteString (one char per
 * byte), so the bytes go in as latin1. A control character (other than a tab) fails the request, as Go's
 * ValidHeaderFieldValue does; surrounding spaces and tabs are trimmed by both.
 */
function asHeaderBytes(value: string): string {
  return Buffer.from(value, "utf8").toString("latin1");
}
