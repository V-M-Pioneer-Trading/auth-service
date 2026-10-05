/**
 * @file clerkMinter (src/api/m2m.go): one mint through Clerk's Backend API with the caller's own Machine Secret Key,
 * so the token's `sub` is that caller's Machine and its `scope` is a flat top-level claim.
 *
 *  - `POST {CLERK_API_BASE_URL or https://api.clerk.com}/v1/m2m_tokens`, `Authorization: Bearer <machine key>`,
 *    `{"claims":{"scope":...},"seconds_until_expiration":86400,"token_format":"jwt"}` (Go's json.Marshal order).
 *  - A redirect is never followed: the request carries a Machine Secret Key, and a 3xx from whatever answers is not a
 *    place to re-send it. node:http never follows one; the 3xx is a non-2xx, a failed mint.
 *  - Any 2xx is success. The answer is read as Go's `json.NewDecoder(io.LimitReader(body, 64<<10)).Decode` reads it
 *    (goJson.ts): the first JSON value, within the first 64 KiB, `token` matched as encoding/json matches a field.
 *  - Nothing upstream wrote reaches a log line or an error: a non-2xx is its status only, a transport failure its
 *    error code only, a body that does not decode a fixed sentence.
 *  - The proxy, if the environment names one, as Go's ProxyFromEnvironment chooses it (proxy.ts).
 */
import http from "node:http";
import https from "node:https";

import type { Mint } from "./cache";
import { decodeGoStruct, scanValue } from "./goJson";
import type { ProxyDecision } from "./proxy";
import { MintFailed } from "./token";

/** decision 22's 24 hours, not Clerk's default hour: at a refresh at half the lifetime, two mints per caller per day. */
export const TOKEN_LIFETIME_SECONDS = 86400;
/** clerkM2MTokensURL. */
export const CLERK_M2M_TOKENS_URL = "https://api.clerk.com/v1/m2m_tokens";
/** The io.LimitReader on Clerk's answer. */
export const MAX_CLERK_ANSWER = 64 << 10;

export interface ClerkMinterOptions {
  /** The mint endpoint. */
  readonly url: string;
  readonly machineKey: string;
  readonly scopes: string;
  /** Where the request goes: decided once, at startup, from the environment. */
  readonly proxy: ProxyDecision;
}

/** The agent for a decision; a socks5 proxy (which Go would dial) or an unusable one is a reason, the mint then fails. */
function agentFor(target: URL, decision: ProxyDecision): http.Agent | string {
  const secure = target.protocol === "https:";
  if (decision.kind === "refused") return decision.reason;
  if (decision.kind === "direct") return secure ? new https.Agent({ keepAlive: true }) : new http.Agent({ keepAlive: true });
  const { proxy } = decision;
  if (proxy.scheme !== "http" && proxy.scheme !== "https") return `a ${proxy.scheme} proxy is not supported`;
  const auth = proxy.username === undefined ? "" : `${encodeURIComponent(proxy.username)}${proxy.password === undefined ? "" : `:${encodeURIComponent(proxy.password)}`}@`;
  let proxyUrl: string;
  try {
    proxyUrl = new URL(`${proxy.scheme}://${auth}${proxy.host}`).href;
  } catch {
    return "the proxy URL cannot be used";
  }
  // Node's own tunnel (CONNECT for https, absolute-form for http); the decision is already made, so no NO_PROXY.
  const proxyEnv = secure ? { HTTPS_PROXY: proxyUrl } : { HTTP_PROXY: proxyUrl };
  return secure ? new https.Agent({ keepAlive: true, proxyEnv }) : new http.Agent({ keepAlive: true, proxyEnv });
}

export type ClerkAnswer = { readonly kind: "more" } | { readonly kind: "token"; readonly token: string } | { readonly kind: "failed"; readonly reason: string };

/**
 * What the decoder makes of the answer's first bytes (at most MAX_CLERK_ANSWER of them): "more" while the first JSON
 * value is incomplete and more may come; then the token, or why there is none. `eof`: the answer ended, or reached the
 * limit (which io.LimitReader makes an EOF).
 */
export function clerkAnswer(buf: Buffer, eof: boolean): ClerkAnswer {
  const scanned = scanValue(buf, 0, eof);
  if (scanned === "more") return { kind: "more" };
  if (scanned === "error") return { kind: "failed", reason: "the answer is not one JSON value" };
  const decoded = decodeGoStruct(buf.subarray(0, scanned.end), [{ name: "token", kind: "string" }]);
  if (decoded === null) return { kind: "failed", reason: "the answer is not the JSON Go decodes" };
  const token = decoded.get("token");
  if (typeof token !== "string" || token === "") return { kind: "failed", reason: "response carried no token" };
  return { kind: "token", token };
}

export function clerkMinter(options: ClerkMinterOptions): Mint {
  const target = new URL(options.url);
  const agent = agentFor(target, options.proxy);
  const transport = target.protocol === "https:" ? https : http;
  const body = JSON.stringify({ claims: { scope: options.scopes }, seconds_until_expiration: TOKEN_LIFETIME_SECONDS, token_format: "jwt" });

  return (signal) =>
    new Promise<string>((resolve, reject) => {
      if (typeof agent === "string") {
        reject(new MintFailed(`POST /m2m_tokens: ${agent}`));
        return;
      }
      let settled = false;
      const fail = (reason: string): void => {
        if (settled) return;
        settled = true;
        reject(new MintFailed(`POST /m2m_tokens: ${reason}`));
      };
      const transportFailure = (err: unknown): void => {
        // The code only: a message could carry whatever a library put in it.
        fail(signal.aborted ? "context deadline exceeded" : (err as NodeJS.ErrnoException).code ?? "transport error");
      };
      let req: http.ClientRequest;
      try {
        req = transport.request(target, {
          method: "POST",
          agent,
          signal,
          headers: {
            Authorization: `Bearer ${options.machineKey}`,
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body),
          },
        });
      } catch (err) {
        // An invalid header value (a machine key with a newline): Go's transport refuses it too.
        transportFailure(err);
        return;
      }
      req.on("error", transportFailure);
      req.on("response", (res) => {
        const status = res.statusCode ?? 0;
        if (status < 200 || status > 299) {
          // Status only. The body is upstream-controlled text, and this process holds the Clerk keys.
          res.destroy();
          fail(`status ${String(status)}`);
          return;
        }
        let buf = Buffer.alloc(0);
        const decide = (eof: boolean): void => {
          const answer = clerkAnswer(buf, eof);
          if (answer.kind === "more") return;
          // The rest is never read, as Go's decoder never reads past the first value.
          res.destroy();
          if (settled) return;
          if (answer.kind === "failed") {
            fail(answer.reason);
            return;
          }
          settled = true;
          resolve(answer.token);
        };
        res.on("data", (chunk: Buffer) => {
          if (settled) return;
          buf = Buffer.concat([buf, chunk.subarray(0, MAX_CLERK_ANSWER - buf.length)]);
          // The limit is an EOF to the decoder.
          decide(buf.length >= MAX_CLERK_ANSWER);
        });
        res.on("end", () => {
          if (!settled) decide(true);
        });
        res.on("error", transportFailure);
        res.on("close", () => {
          if (!settled) transportFailure(new Error("closed"));
        });
      });
      req.end(body);
    });
}
