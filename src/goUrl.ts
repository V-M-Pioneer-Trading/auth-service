/**
 * @file The verdict of the Go service's `clerkURLFromEnv` (src/api/m2m.go) on a CLERK_API_BASE_URL, which is
 * `url.Parse` followed by five checks. Ported from net/url as of Go 1.22 (the image's compiler); no WHATWG URL,
 * which rewrites and strips what Go keeps, in a decision about where a Machine Secret Key is sent.
 *
 * The value is accepted when Go's parser accepts it AND the scheme is http or https, the host (unescaped, port
 * and brackets removed) is not empty, there is no userinfo, no query (not even an empty `?`) and no fragment (no
 * `#` anywhere). Every refusal is the same one, so nothing here needs to say which rule failed.
 */

const isHex = (c: number): boolean => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
const unhex = (c: number): number => (c >= 0x61 ? c - 0x61 + 10 : c >= 0x41 ? c - 0x41 + 10 : c - 0x30);

type Mode = "host" | "zone" | "path";

/** Go's shouldEscape for the host and zone modes, which is all that matters for an ASCII byte there. */
const hostShouldEscape = (c: number): boolean => {
  if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)) return false;
  return !"-_.~!$&'()*+,;=:[]<>\"".includes(String.fromCharCode(c));
};

/** Go's unescape(s, mode); null for the errors it returns. Works on bytes, as Go does. */
export function unescape(s: Buffer, mode: Mode): Buffer | null {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i] ?? 0;
    if (c === 0x25) {
      const h1 = s[i + 1];
      const h2 = s[i + 2];
      if (i + 2 >= s.length || h1 === undefined || h2 === undefined || !isHex(h1) || !isHex(h2)) return null;
      const isPercentEscape = h1 === 0x32 && h2 === 0x35;
      // In a host a %-escape may only stand for a non-ASCII byte, or for the percent sign of a zone.
      if (mode === "host" && unhex(h1) < 8 && !isPercentEscape) return null;
      const value = (unhex(h1) << 4) | unhex(h2);
      if (mode === "zone" && !isPercentEscape && value !== 0x20 && hostShouldEscape(value)) return null;
      out.push(value);
      i += 2;
    } else {
      if ((mode === "host" || mode === "zone") && c < 0x80 && hostShouldEscape(c)) return null;
      out.push(c);
    }
  }
  return Buffer.from(out);
}

/** Go's validOptionalPort: "" or ":" followed by digits (possibly none). */
const validOptionalPort = (port: string): boolean => port === "" || /^:[0-9]*$/.test(port);

/** Go's parseHost: the unescaped host, or null. */
export function parseHost(host: Buffer): Buffer | null {
  const text = host.toString("latin1");
  if (text.startsWith("[")) {
    const close = text.lastIndexOf("]");
    if (close < 0) return null;
    if (!validOptionalPort(text.slice(close + 1))) return null;
    const zone = text.slice(0, close).indexOf("%25");
    if (zone >= 0) {
      const head = unescape(host.subarray(0, zone), "host");
      const middle = unescape(host.subarray(zone, close), "zone");
      const tail = unescape(host.subarray(close), "host");
      if (head === null || middle === null || tail === null) return null;
      return Buffer.concat([head, middle, tail]);
    }
  } else {
    const colon = text.lastIndexOf(":");
    if (colon !== -1 && !validOptionalPort(text.slice(colon))) return null;
  }
  return unescape(host, "host");
}

export interface ParsedBaseUrl {
  readonly scheme: string;
  /** Go's `u.Host`: unescaped, with its port. */
  readonly host: string;
}

/** Go's getScheme: [scheme, rest], or null for its one error (a ":" at position 0). */
export function getScheme(raw: string): [string, string] | null {
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if ((c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a)) continue;
    if ((c >= 0x30 && c <= 0x39) || c === 0x2b || c === 0x2d || c === 0x2e) {
      if (i === 0) return ["", raw];
      continue;
    }
    if (c === 0x3a) return i === 0 ? null : [raw.slice(0, i), raw.slice(i + 1)];
    return ["", raw];
  }
  return ["", raw];
}

/**
 * Go's `clerkURLFromEnv` verdict: the scheme and host of an accepted value, null for a refused one.
 * `raw` is the environment value (not empty: empty means unset and never gets here).
 */
export function parseClerkBaseUrl(raw: string): ParsedBaseUrl | null {
  // The query and fragment checks refuse any "?" or "#", so a value with one is refused whatever else it holds.
  if (raw.includes("?") || raw.includes("#")) return null;
  // stringContainsCTLByte
  for (const byte of Buffer.from(raw, "utf8")) if (byte < 0x20 || byte === 0x7f) return null;
  const scheme = getScheme(raw);
  if (scheme === null) return null;
  const [rawScheme, rest] = scheme;
  const lower = rawScheme.toLowerCase();
  if (lower !== "http" && lower !== "https") return null;
  // A rootless remainder is opaque; anything not starting "//" has no host.
  if (!rest.startsWith("//")) return null;
  const afterSlashes = rest.slice(2);
  const slash = afterSlashes.indexOf("/");
  const authority = slash < 0 ? afterSlashes : afterSlashes.slice(0, slash);
  const path = slash < 0 ? "" : afterSlashes.slice(slash);
  // Userinfo: a valid one makes `u.User` non-nil and an invalid one is a parse error.
  if (authority.includes("@")) return null;
  const host = parseHost(Buffer.from(authority, "utf8"));
  if (host === null) return null;
  if (unescape(Buffer.from(path, "utf8"), "path") === null) return null;

  // u.Hostname(): the port split off, the brackets of an IPv6 literal removed.
  let name = host.toString("latin1");
  const colon = name.lastIndexOf(":");
  if (colon !== -1 && validOptionalPort(name.slice(colon))) name = name.slice(0, colon);
  if (name.startsWith("[") && name.endsWith("]")) name = name.slice(1, -1);
  if (name === "") return null;
  return { scheme: lower, host: host.toString("utf8") };
}
