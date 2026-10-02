// Assertions that compare a whole response at once so a failure shows status,
// pinned headers and body side by side.
import assert from "node:assert/strict";
import type { Reply } from "./http.ts";

/** The headers the contract pins. Anything else a framework adds is not compared. */
const PINNED = [
  "content-type",
  "cache-control",
  "access-control-allow-origin",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "access-control-allow-credentials",
  "access-control-allow-private-network",
  "access-control-expose-headers",
  "access-control-max-age",
  "x-content-type-options",
  "location",
  "allow",
  "vary",
  "etag",
  "www-authenticate",
  "set-cookie",
];

export const DEFAULT_ORIGIN = "http://localhost:3000";

export function corsHeaders(origin: string = DEFAULT_ORIGIN): Record<string, string> {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization, X-Auth-Service-Secret",
  };
}

export function pinnedHeaders(r: Reply): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const name of PINNED) {
    const v = r.headers[name];
    if (v !== undefined) out[name] = v;
  }
  return out;
}

export interface Expectation {
  /** Headers expected beyond CORS. Everything pinned and not listed must be absent. */
  headers?: Record<string, string>;
  /** CORS headers on the response. Default true; pass an origin to expect a non-default one. */
  cors?: boolean | string;
}

function expectedHeaders(e: Expectation, extra: Record<string, string>): Record<string, string> {
  const cors = e.cors === undefined || e.cors === true ? corsHeaders() : e.cors === false ? {} : corsHeaders(e.cors);
  return { ...cors, ...extra, ...e.headers };
}

/** A JSON body, compared structurally: deep-equal, null distinct from missing, numbers distinct from strings. */
export function expectJson(r: Reply, status: number, body: unknown, e: Expectation & { noStore?: boolean } = {}): void {
  const extra: Record<string, string> = { "content-type": "application/json" };
  if (e.noStore) extra["cache-control"] = "no-store";
  let parsed: unknown;
  try {
    parsed = r.json();
  } catch {
    parsed = `<not JSON> ${JSON.stringify(r.text.slice(0, 200))}`;
  }
  assert.deepStrictEqual(
    { status: r.status, headers: pinnedHeaders(r), body: parsed },
    { status, headers: expectedHeaders(e, extra), body },
  );
}

/** A plain-text body, byte for byte, as Go's http.Error writes it. */
export function expectText(r: Reply, status: number, text: string | RegExp, e: Expectation = {}): void {
  const extra = { "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" };
  const expectedHead = { status, headers: expectedHeaders(e, extra) };
  if (typeof text === "string") {
    assert.deepStrictEqual({ status: r.status, headers: pinnedHeaders(r), body: r.text }, { ...expectedHead, body: text });
  } else {
    assert.deepStrictEqual({ status: r.status, headers: pinnedHeaders(r) }, expectedHead);
    assert.match(r.text, text);
  }
}

/** No body at all, with exactly these pinned headers. */
export function expectEmpty(r: Reply, status: number, e: Expectation = {}): void {
  assert.deepStrictEqual(
    { status: r.status, headers: pinnedHeaders(r), body: r.text },
    { status, headers: expectedHeaders(e, {}), body: "" },
  );
}

/** The `{"error":{"message":…}}` envelope every authentication rejection uses. */
export function expectAuthError(r: Reply, status: number, message: string): void {
  expectJson(r, status, { error: { message } }, { noStore: true });
}

export const INACTIVE = { active: false };
