/**
 * @file The two parsers behind Go's `r.ParseForm()` on POST /auth/v1/introspect (contract README note 19), on Go
 * strings: a JavaScript string whose every char is one byte (latin1), which is what Node gives for a header value and
 * what a body's bytes are decoded to here.
 *
 *  - `mime.ParseMediaType` (Go 1.22) decides whether the body is read at all (only for
 *    `application/x-www-form-urlencoded`) and whether parsing failed;
 *  - `url.ParseQuery` parses both the body and the URL query. Its errors (a `;` anywhere, a malformed `%` escape) are
 *    sticky: ParseForm returns the first, and the handler then answers `{"active":false}` whatever else was parsed.
 */

export const FORM_MEDIA_TYPE = "application/x-www-form-urlencoded";

/** Go's utf8.DecodeRuneInString: the rune at `i` and its width; invalid UTF-8 is U+FFFD of width 1. */
export function decodeRune(s: string, i: number): [number, number] {
  const b0 = s.charCodeAt(i);
  if (b0 < 0x80) return [b0, 1];
  const cont = (k: number): number => {
    const b = s.charCodeAt(i + k);
    return b >= 0x80 && b <= 0xbf ? b & 0x3f : -1;
  };
  const bad: [number, number] = [0xfffd, 1];
  if (b0 >= 0xc2 && b0 <= 0xdf) {
    const c1 = cont(1);
    return c1 < 0 ? bad : [((b0 & 0x1f) << 6) | c1, 2];
  }
  if (b0 >= 0xe0 && b0 <= 0xef) {
    const b1 = s.charCodeAt(i + 1);
    // Overlongs (E0 80..9F) and surrogates (ED A0..BF) are invalid.
    if ((b0 === 0xe0 && b1 < 0xa0) || (b0 === 0xed && b1 > 0x9f)) return bad;
    const c1 = cont(1);
    const c2 = cont(2);
    return c1 < 0 || c2 < 0 ? bad : [((b0 & 0x0f) << 12) | (c1 << 6) | c2, 3];
  }
  if (b0 >= 0xf0 && b0 <= 0xf4) {
    const b1 = s.charCodeAt(i + 1);
    if ((b0 === 0xf0 && b1 < 0x90) || (b0 === 0xf4 && b1 > 0x8f)) return bad;
    const c1 = cont(1);
    const c2 = cont(2);
    const c3 = cont(3);
    return c1 < 0 || c2 < 0 || c3 < 0 ? bad : [((b0 & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3, 4];
  }
  return bad;
}

/** Go's unicode.IsSpace. */
function isSpace(r: number): boolean {
  return (
    (r >= 0x09 && r <= 0x0d) || r === 0x20 || r === 0x85 || r === 0xa0 || r === 0x1680 || (r >= 0x2000 && r <= 0x200a) ||
    r === 0x2028 || r === 0x2029 || r === 0x202f || r === 0x205f || r === 0x3000
  );
}

/** strings.TrimLeftFunc(s, unicode.IsSpace). */
function trimLeftSpace(s: string): string {
  let i = 0;
  while (i < s.length) {
    const [r, w] = decodeRune(s, i);
    if (!isSpace(r)) break;
    i += w;
  }
  return s.slice(i);
}

/** strings.TrimSpace. */
function trimSpace(s: string): string {
  const left = trimLeftSpace(s);
  // Walk forward, remembering where the last non-space rune ended (Go decodes backwards; the result is the same).
  let end = 0;
  for (let i = 0; i < left.length; ) {
    const [r, w] = decodeRune(left, i);
    i += w;
    if (!isSpace(r)) end = i;
  }
  return left.slice(0, end);
}

/**
 * strings.ToLower, far enough to compare with an ASCII media type: ASCII letters, and the two non-ASCII runes whose
 * lower case is ASCII (U+0130 to "i", U+212A KELVIN SIGN to "k"). Any other non-ASCII rune is kept as its bytes,
 * which can never equal an ASCII string, as its real lower case could not either.
 */
function toLowerForAscii(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; ) {
    const [r, w] = decodeRune(s, i);
    if (r === 0x130) out += "i";
    else if (r === 0x212a) out += "k";
    else if (r >= 0x41 && r <= 0x5a) out += String.fromCharCode(r + 0x20);
    else out += s.slice(i, i + w);
    i += w;
  }
  return out;
}

const TSPECIALS = `()<>@,;:\\"/[]?=`;
const isTSpecial = (c: number): boolean => c < 0x80 && TSPECIALS.includes(String.fromCharCode(c));
/** mime's isTokenChar, on runes: printable ASCII but space and the tspecials. */
const isTokenChar = (r: number): boolean => r > 0x20 && r < 0x7f && !isTSpecial(r);

function consumeToken(v: string): [string, string] {
  let i = 0;
  while (i < v.length) {
    const [r, w] = decodeRune(v, i);
    if (!isTokenChar(r)) break;
    i += w;
  }
  return [v.slice(0, i), v.slice(i)];
}

function consumeValue(v: string): [string, string] {
  if (v === "") return ["", ""];
  if (!v.startsWith('"')) return consumeToken(v);
  let out = "";
  for (let i = 1; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c === 0x22) return [out, v.slice(i + 1)];
    if (c === 0x5c && i + 1 < v.length && isTSpecial(v.charCodeAt(i + 1))) {
      out += v.charAt(i + 1);
      i++;
      continue;
    }
    if (c === 0x0d || c === 0x0a) return ["", v];
    out += v.charAt(i);
  }
  return ["", v];
}

function consumeMediaParam(v: string): [string, string, string] {
  let rest = trimLeftSpace(v);
  if (!rest.startsWith(";")) return ["", "", v];
  rest = trimLeftSpace(rest.slice(1));
  let param: string;
  [param, rest] = consumeToken(rest);
  param = param.toLowerCase(); // token characters are ASCII
  if (param === "") return ["", "", v];
  rest = trimLeftSpace(rest);
  if (!rest.startsWith("=")) return ["", "", v];
  rest = trimLeftSpace(rest.slice(1));
  const [value, rest2] = consumeValue(rest);
  if (value === "" && rest2 === rest) return ["", "", v];
  return [param, value, rest2];
}

function checkMediaTypeDisposition(s: string): boolean {
  const [typ, rest] = consumeToken(s);
  if (typ === "") return false;
  if (rest === "") return true;
  if (!rest.startsWith("/")) return false;
  const [subtype, rest2] = consumeToken(rest.slice(1));
  return subtype !== "" && rest2 === "";
}

export interface MediaType {
  /** What ParseMediaType returns as the media type: "" when it fails before or on the type itself. */
  readonly mediaType: string;
  /** Whether it returned an error (a media type can come back with one: a bad parameter). */
  readonly failed: boolean;
}

/** Go 1.22's mime.ParseMediaType, as far as its media type and its error go (the parameters themselves are unused). */
export function parseMediaType(v: string): MediaType {
  const semicolon = v.indexOf(";");
  const base = semicolon < 0 ? v : v.slice(0, semicolon);
  const mediaType = trimSpace(toLowerForAscii(base));
  if (!checkMediaTypeDisposition(mediaType)) return { mediaType: "", failed: true };
  const params = new Map<string, string>();
  const continuation = new Map<string, Map<string, string>>();
  let rest = v.slice(base.length);
  while (rest.length > 0) {
    rest = trimLeftSpace(rest);
    if (rest.length === 0) break;
    const [key, value, next] = consumeMediaParam(rest);
    if (key === "") {
      // Ignore trailing semicolons. Not an error.
      if (trimSpace(next) === ";") break;
      return { mediaType, failed: true };
    }
    let pmap = params;
    const star = key.indexOf("*");
    if (star >= 0) {
      const baseName = key.slice(0, star);
      pmap = continuation.get(baseName) ?? new Map<string, string>();
      continuation.set(baseName, pmap);
    }
    const existing = pmap.get(key);
    if (existing !== undefined && existing !== value) return { mediaType: "", failed: true };
    pmap.set(key, value);
    rest = next;
  }
  return { mediaType, failed: false };
}

/** Go's url.unescape in query-component mode: `+` is a space; null for a `%` not followed by two hex digits. */
export function queryUnescape(s: string): string | null {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i);
    if (c === "%") {
      const hex = s.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null;
      out += String.fromCharCode(parseInt(hex, 16));
      i += 2;
    } else {
      out += c === "+" ? " " : c;
    }
  }
  return out;
}

export interface ParsedQuery {
  /** Every key's values, in order. */
  readonly values: Map<string, string[]>;
  /** Whether url.ParseQuery returned an error (it keeps parsing after one). */
  readonly failed: boolean;
}

/** Go 1.22's url.ParseQuery. */
export function parseQuery(query: string): ParsedQuery {
  const values = new Map<string, string[]>();
  let failed = false;
  let rest = query;
  while (rest !== "") {
    const amp = rest.indexOf("&");
    let key = amp < 0 ? rest : rest.slice(0, amp);
    rest = amp < 0 ? "" : rest.slice(amp + 1);
    if (key.includes(";")) {
      failed = true; // "invalid semicolon separator in query"
      continue;
    }
    if (key === "") continue;
    const eq = key.indexOf("=");
    let value = eq < 0 ? "" : key.slice(eq + 1);
    key = eq < 0 ? key : key.slice(0, eq);
    const k = queryUnescape(key);
    const v = k === null ? null : queryUnescape(value);
    if (k === null || v === null) {
      failed = true;
      continue;
    }
    value = v;
    const list = values.get(k);
    if (list === undefined) values.set(k, [value]);
    else list.push(value);
  }
  return { values, failed };
}
