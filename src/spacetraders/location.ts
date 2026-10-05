/**
 * @file Reading a redirect's `Location` the way Go's `url.Parse` and
 * `ResolveReference` do, and handing fetch a URL that cannot mean anything else.
 *
 * Ported verbatim from agent-service (src/gateway/location.ts at bbe7163, its tests in
 * src/__tests__/client.test.ts) but for one lint-driven rewrite in hostAcceptable. Here the header that travels is
 * the SpaceTraders account token on POST /register; spacetraders/client.ts decides where it may go.
 *
 * The caller's Authorization travels with a redirect, so the question "where
 * does this go" has one answer here, decided once: the URL is assembled from the
 * parts Go's rules give (scheme, host, path, query) as `scheme://host/path?query`
 * and checked to come out of WHATWG parsing with that scheme and that host. WHATWG
 * would read several references differently (`///evil/x` is a host for it and a
 * path for Go; `https:/evil/x` is a host for it and an error for Go): none of them
 * is ever given to it as written.
 *
 * What Go refuses is refused (the call is then "st-gateway did not answer"):
 * a control character; a malformed `%` in the path, the host or the fragment (not
 * the query); a scheme-less reference whose first path segment has a colon (so a
 * leading space before `http://` is refused); a host Go does not allow, or a port
 * that is not digits; a scheme other than http and https; a scheme without a
 * host (`http:/evil`, `http:///x`, `mailto:x`).
 *
 * Deviations, on purpose:
 *  - a reference with userinfo (`http://u:p@host/`) is refused: Go would send it
 *    as Basic credentials, and nothing here forwards credentials to a redirect target;
 *  - a `%2e%2e` or `%2E` segment is resolved as a dot segment by WHATWG, not
 *    left alone as Go leaves it;
 *  - Go converts a non-ASCII host to punycode with its own IDNA tables, WHATWG with
 *    UTS 46; they agree on ordinary names; an IPv6 zone (`[fe80::1%25en0]`) is refused.
 *
 * A backslash is an ordinary path character (`%5C` on the wire), not a slash. The
 * host is kept as written (Go compares hosts byte for byte before it decides to
 * strip Authorization), after percent-decoding.
 */

import { domainToASCII } from "node:url";

/** A request target: what fetch is given, and Go's `URL.Host` (percent-decoded, case kept, port included). */
export interface Target {
  readonly url: URL;
  readonly host: string;
}

const CTL = /[\x00-\x1f\x7f]/;
const BAD_ESCAPE = /%(?![0-9A-Fa-f]{2})/;
/** Characters Go lets stand in a host (everything else below 0x80 is refused). */
const HOST_OK = /^[A-Za-z0-9\-._~!$&'()*+,;=:[\]<>"\u0080-￿%]*$/;

/**
 * A header value as fetch hands it over is one character per byte. Go sees the bytes: every byte
 * above 0x7f becomes `%XX` (a host then decodes it as UTF-8, a path keeps it escaped).
 */
export function fromHeaderValue(value: string): string {
  return Array.from(Buffer.from(value, "latin1"), (b) => (b < 0x80 ? String.fromCharCode(b) : `%${b.toString(16).toUpperCase()}`)).join("");
}

/** The `scheme:` of a reference, "" when it has none, null when Go calls the reference malformed. */
function schemeOf(ref: string): string | null {
  for (let i = 0; i < ref.length; i++) {
    const c = ref.charCodeAt(i);
    const letter = (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
    if (letter) continue;
    if ((c >= 0x30 && c <= 0x39) || c === 0x2b || c === 0x2d || c === 0x2e) {
      if (i === 0) return "";
      continue;
    }
    if (c === 0x3a) return i === 0 ? null : ref.slice(0, i);
    return "";
  }
  return "";
}

/** True when Go's host rules accept `host` (as it stands between "//" and the next "/"). */
function hostAcceptable(host: string): boolean {
  if (!HOST_OK.test(host)) return false;
  // A percent sign in a host is only allowed as %25 or as part of an encoded non-ASCII byte.
  for (const m of host.matchAll(/%(.?)(.?)/g)) {
    const hex = (m[1] ?? "") + (m[2] ?? "");
    if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return false;
    if (Number.parseInt(hex.slice(0, 1), 16) < 8 && hex !== "25") return false;
  }
  if (host.startsWith("[")) {
    const close = host.indexOf("]");
    return close > 0 && (close === host.length - 1 || /^:\d*$/.test(host.slice(close + 1)));
  }
  const colon = host.lastIndexOf(":");
  return colon === -1 || /^\d*$/.test(host.slice(colon + 1));
}

/** Go's unescape of a host: `%XX` bytes, read as UTF-8. */
const decodeHost = (host: string): string =>
  host.includes("%") ? Buffer.from(host.replace(/%([0-9A-Fa-f]{2})/g, (_m, h: string) => String.fromCharCode(Number.parseInt(h, 16))), "latin1").toString("utf8") : host;

/** The host name of a Go `URL.Host`: without the port and the brackets of an IPv6 literal. */
export function hostnameOf(host: string): string {
  if (host.startsWith("[")) return host.slice(1, host.indexOf("]"));
  const colon = host.lastIndexOf(":");
  return colon === -1 ? host : host.slice(0, colon);
}

/** Go's idnaASCII: a non-ASCII name as punycode, anything else (or what cannot be converted) as it is. */
export const asciiHostname = (name: string): string => (/^[\x00-\x7f]*$/.test(name) ? name : domainToASCII(name) || name);

/** Go's isDomainOrSubdomain, byte for byte (case matters; a name with a colon or a percent sign is never a subdomain). */
export function isDomainOrSubdomain(sub: string, parent: string): boolean {
  if (sub === parent) return true;
  if (/[:%]/.test(sub)) return false;
  return sub.endsWith(parent) && sub[sub.length - parent.length - 1] === ".";
}

/** Go's resolvePath (net/url): `ref` against `base`, with "." and ".." removed from the escaped text. */
export function resolvePath(base: string, ref: string): string {
  const full = ref === "" ? base : ref.startsWith("/") ? ref : base.slice(0, base.lastIndexOf("/") + 1) + ref;
  if (full === "") return "";
  let dst = "/";
  let first = true;
  let rest = full;
  let elem = "";
  for (let found = true; found; ) {
    const slash = rest.indexOf("/");
    found = slash !== -1;
    elem = found ? rest.slice(0, slash) : rest;
    rest = found ? rest.slice(slash + 1) : "";
    if (elem === ".") {
      first = false;
    } else if (elem === "..") {
      const kept = dst.slice(1);
      const index = kept.lastIndexOf("/");
      dst = "/";
      if (index === -1) first = true;
      else dst += kept.slice(0, index);
    } else {
      if (!first) dst += "/";
      dst += elem;
      first = false;
    }
  }
  if (elem === "." || elem === "..") dst += "/";
  return dst.length > 1 && dst[1] === "/" ? dst.slice(1) : dst;
}

/**
 * `ref` resolved against `base` (or taken as it stands when `base` is null), or null when Go refuses
 * it, or when it is not something this service follows. `ref` is ASCII: see `fromHeaderValue`.
 */
export function resolveReference(base: Target | null, ref: string): Target | null {
  if (CTL.test(ref)) return null;
  const hash = ref.indexOf("#");
  if (hash !== -1 && BAD_ESCAPE.test(ref.slice(hash + 1))) return null;
  const noFragment = hash === -1 ? ref : ref.slice(0, hash);
  const q = noFragment.indexOf("?");
  let rest = q === -1 ? noFragment : noFragment.slice(0, q);
  const query = q === -1 ? "" : noFragment.slice(q);

  const scheme = (schemeOf(rest) ?? "?").toLowerCase();
  if (scheme === "?") return null;
  if (scheme !== "" && scheme !== "http" && scheme !== "https") return null;
  rest = rest.slice(scheme === "" ? 0 : scheme.length + 1);
  if (scheme === "" && !rest.startsWith("/") && rest.split("/", 1)[0]?.includes(":")) return null;

  let host = "";
  if (rest.startsWith("//") && (scheme !== "" || !rest.startsWith("///"))) {
    const slash = rest.indexOf("/", 2);
    const authority = slash === -1 ? rest.slice(2) : rest.slice(2, slash);
    // hostAcceptable refuses "@" too, so userinfo ("u:p@host") never gets this far.
    if (!hostAcceptable(authority)) return null;
    host = decodeHost(authority);
    rest = slash === -1 ? "" : rest.slice(slash);
  }
  // A scheme needs a host of its own ("http:/evil" and "http:///x" have none: Go cannot send them).
  if (scheme !== "" && host === "") return null;
  if (BAD_ESCAPE.test(rest)) return null;

  const path = rest.replaceAll("\\", "%5C");
  let finalScheme: string;
  let finalHost: string;
  let finalPath: string;
  let finalQuery = query;
  if (scheme !== "" || host !== "") {
    finalScheme = scheme === "" ? (base?.url.protocol.slice(0, -1) ?? "") : scheme;
    finalHost = host;
    finalPath = resolvePath(path, "");
  } else {
    if (base === null) return null;
    finalScheme = base.url.protocol.slice(0, -1);
    finalHost = base.host;
    finalPath = resolvePath(base.url.pathname, path);
    if (path === "" && query === "") finalQuery = base.url.search;
  }
  if (finalScheme !== "http" && finalScheme !== "https") return null;

  // What Go means is "finalScheme, finalHost, finalPath, finalQuery"; this is checked to be what fetch will do.
  try {
    const url = new URL(`${finalScheme}://${finalHost}${finalPath === "" ? "/" : finalPath}${finalQuery}`);
    const intended = new URL(`${finalScheme}://${finalHost}/`);
    if (url.protocol !== `${finalScheme}:` || url.host !== intended.host || url.username !== "" || url.password !== "") return null;
    return { url, host: finalHost };
  } catch {
    return null;
  }
}
