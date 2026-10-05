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
import { fromHeaderValue, resolveReference } from "./location";

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

/** How many redirects Go's default CheckRedirect follows: the 10th redirect is refused ("stopped after 10 redirects"). */
export const MAX_REDIRECTS = 10;

/** A request or redirect Go's client would refuse to make. Its message names no URL. */
class RedirectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RedirectError";
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** The call never got an answer: no connection, a reset, the timeout, or shutdown. */
export class TransportError extends Error {
  constructor(what: string, cause: unknown) {
    super(`${what}: ${transportReason(cause)}`);
    this.name = "TransportError";
  }
}

/** The reason a fetch failed, from its cause's code: never a URL, a header or a body. */
function transportReason(err: unknown): string {
  if (err instanceof RedirectError) return err.message;
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

  /**
   * The request, following redirects as Go 1.22's http.Client does (net/http client.go):
   *  - 301, 302, 303, 307 and 308 WITH a Location are followed; without one the response is the answer, as it stands
   *    (Go returns it: a 3xx is read like a 2xx by the callers);
   *  - 301, 302 and 303 turn any method but GET and HEAD into a GET without a body; Content-Type stays (Go copies every
   *    header to the next request); 307 and 308 repeat the method and the body;
   *  - the Location is read with Go's url.Parse and ResolveReference rules (`location.ts`, from agent-service), never
   *    by WHATWG `new URL(location, base)`: `///h`, `/\\h`, `http:\\\\h`, a tab in a host, `http://a\\@b` and the like stay
   *    on the origin or are refused as Go refuses them; userinfo, a scheme without a host and anything but http(s)
   *    are refused (`failed to parse Location header`, checked before the redirect count, as Go orders them);
   *  - the 10th redirect is refused (`stopped after 10 redirects`).
   * `Authorization` (the account token) goes only to the host the call started at, byte for byte as Go compares it and
   * as the URL actually fetched says, never over an https-to-http downgrade, and once a hop has left the host it stays
   * off for the rest of the chain, also if a later hop comes back. Stricter than Go, which also sends it to another
   * port of the same host and to a subdomain. A request body is never sent to another host either: a 307 or 308 that
   * would carry it there is refused. No Referer is added.
   */
  async function follow(start: string, init: { method: string; headers: Record<string, string>; body?: string }, signal: AbortSignal): Promise<Response> {
    const first = resolveReference(null, start);
    if (first === null) throw new RedirectError("ST_GATEWAY_URL is not a usable URL");
    let target = first;
    let method = init.method;
    let body = init.body;
    let stripped = false;
    for (let requests = 1; ; requests++) {
      const headers = { ...init.headers };
      if (stripped) delete headers.Authorization;
      const res = await doFetch(target.url, { method, headers, ...(body === undefined ? {} : { body }), redirect: "manual", signal });
      // fetch joins repeated Location headers with ", "; Go reads the first.
      const location = (res.headers.get("location") ?? "").split(", ", 1)[0] ?? "";
      if (!REDIRECT_STATUSES.has(res.status) || location === "") return res;
      await res.body?.cancel().catch(() => undefined);
      const next = resolveReference(target, fromHeaderValue(location));
      if (next === null) throw new RedirectError("failed to parse Location header");
      if (requests >= MAX_REDIRECTS) throw new RedirectError(`stopped after ${String(MAX_REDIRECTS)} redirects`);
      const sameHost = next.host === first.host && next.url.host === first.url.host;
      // Another scheme is another origin: an https-to-http downgrade loses the token, whatever host it names.
      if (!sameHost || next.url.protocol !== first.url.protocol) stripped = true;
      if (res.status <= 303) {
        if (method !== "GET" && method !== "HEAD") method = "GET";
        body = undefined;
      }
      // Stricter than Go: a body (the register call: call sign, faction, email) never leaves the host either. A 307 or
      // 308 that would carry it elsewhere is refused (a 502), where Go would resend it without Authorization.
      if (body !== undefined && !sameHost) throw new RedirectError("refusing to send the request body to another host");
      target = next;
    }
  }

  /** One exchange, redirects followed, body read to the end, all inside the timeout. */
  async function exchange(
    what: string,
    path: string,
    init: { method: string; headers: Record<string, string>; body?: string },
    signal: AbortSignal | undefined,
  ): Promise<{ status: number; body: Buffer }> {
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
      const res = await follow(options.baseUrl + path, init, timeout.signal);
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
      const { status, body } = await exchange(what, "/", { method: "GET", headers: {} }, signal);
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
