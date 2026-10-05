/**
 * @file The two places the Go mint path reads JSON, as Go 1.22's encoding/json reads it (src/api/m2m.go):
 *
 *  - Clerk's answer: `json.NewDecoder(io.LimitReader(body, 64<<10)).Decode(&struct{ Token string })`. The decoder
 *    reads the FIRST JSON value and stops there (what follows is never looked at), within the first 64 KiB.
 *  - a minted token's payload: `json.Unmarshal(raw, &struct{ Iat, Exp *float64 })`.
 *
 * What differs from `JSON.parse` and is reproduced:
 *
 *  - a struct field matches a key exactly or by Go's case folding (`"EXP"`, `"Iat"`, "to" U+212A KELVIN SIGN "en"),
 *    and members apply in document order, so of two spellings of one field the LAST in the text wins (`JSON.parse`
 *    keeps one value per exact key, at the position of its first appearance);
 *  - `null` leaves a string field as it was and sets a pointer field to nil;
 *  - a value of the wrong type fails the whole decode, after the rest has been read;
 *  - invalid UTF-8 inside a string becomes U+FFFD per byte (utf8.DecodeRune), not per WHATWG's maximal subpart, and
 *    a lone surrogate escape becomes U+FFFD;
 *  - more than 10000 levels of nesting is an error.
 *
 * Only the verdicts these two readers need are produced; nothing here is a general JSON library.
 */

/** U+FFFD, what an invalid byte becomes. */
const REPLACEMENT = String.fromCharCode(0xfffd);

const isWs = (c: number): boolean => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
const isDigit = (c: number): boolean => c >= 0x30 && c <= 0x39;
const isHex = (c: number): boolean => isDigit(c) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);

/** encoding/json's maxNestingDepth. */
const MAX_DEPTH = 10000;

/** Where a JSON value ends; "more" when the bytes so far are a valid prefix that needs more; "error" when no continuation is valid. */
export type ScanResult = { readonly end: number } | "more" | "error";

/** One string token at `i` (a `"`): the index after its closing quote. */
function scanString(b: Buffer, i: number): number | "more" | "error" {
  let j = i + 1;
  for (;;) {
    const c = b[j];
    if (c === undefined) return "more";
    if (c === 0x22) return j + 1;
    if (c < 0x20) return "error";
    if (c !== 0x5c) {
      j++;
      continue;
    }
    const e = b[j + 1];
    if (e === undefined) return "more";
    if (e === 0x75) {
      for (let k = 2; k < 6; k++) {
        const h = b[j + k];
        if (h === undefined) return "more";
        if (!isHex(h)) return "error";
      }
      j += 6;
    } else if ([0x22, 0x5c, 0x2f, 0x62, 0x66, 0x6e, 0x72, 0x74].includes(e)) {
      j += 2;
    } else {
      return "error";
    }
  }
}

/** One number at `i`: the index after it. At the end of the bytes a number is complete only at EOF. */
function scanNumber(b: Buffer, i: number, eof: boolean): number | "more" | "error" {
  let j = i;
  const end = (accepting: boolean): number | "more" | "error" => (j < b.length ? (accepting ? j : "error") : !eof ? "more" : accepting ? j : "error");
  if (b[j] === 0x2d) j++;
  if (j >= b.length) return end(false);
  if (b[j] === 0x30) j++;
  else if (isDigit(b[j] ?? 0)) while (j < b.length && isDigit(b[j] ?? 0)) j++;
  else return "error";
  if (j >= b.length) return end(true);
  if (b[j] === 0x2e) {
    j++;
    if (j >= b.length || !isDigit(b[j] ?? 0)) return end(false);
    while (j < b.length && isDigit(b[j] ?? 0)) j++;
    if (j >= b.length) return end(true);
  }
  if (b[j] === 0x65 || b[j] === 0x45) {
    j++;
    if (b[j] === 0x2b || b[j] === 0x2d) j++;
    if (j >= b.length || !isDigit(b[j] ?? 0)) return end(false);
    while (j < b.length && isDigit(b[j] ?? 0)) j++;
  }
  return end(true);
}

type State = "value" | "valueOrClose" | "keyOrClose" | "key" | "colon" | "after";

/**
 * Scans one JSON value starting at `from` (leading whitespace skipped), as encoding/json's Decoder finds the end of
 * the first value: an object or array ends at its closing bracket, a literal or string at its last byte, a number
 * at the first byte that cannot continue it (or at EOF). `eof` says no more bytes will come.
 */
export function scanValue(b: Buffer, from: number, eof: boolean): ScanResult {
  const more = (): ScanResult => (eof ? "error" : "more");
  const stack: number[] = [];
  let state: State = "value";
  let i = from;
  for (;;) {
    while (i < b.length && isWs(b[i] ?? 0)) i++;
    const c = b[i];
    if (c === undefined) return more();
    switch (state) {
      case "value":
      case "valueOrClose": {
        if (state === "valueOrClose" && c === 0x5d) {
          stack.pop();
          i++;
          break;
        }
        if (c === 0x7b || c === 0x5b) {
          if (stack.length >= MAX_DEPTH) return "error";
          stack.push(c);
          i++;
          state = c === 0x7b ? "keyOrClose" : "valueOrClose";
          continue;
        }
        let r: number | "more" | "error";
        if (c === 0x22) r = scanString(b, i);
        else if (c === 0x2d || isDigit(c)) r = scanNumber(b, i, eof);
        else {
          const word = c === 0x74 ? "true" : c === 0x66 ? "false" : c === 0x6e ? "null" : "";
          if (word === "") return "error";
          const got = b.toString("latin1", i, i + word.length);
          r = got === word ? i + word.length : word.startsWith(got) ? "more" : "error";
        }
        if (r === "more") return more();
        if (r === "error") return "error";
        i = r;
        break;
      }
      case "keyOrClose":
      case "key": {
        if (state === "keyOrClose" && c === 0x7d) {
          stack.pop();
          i++;
          break;
        }
        if (c !== 0x22) return "error";
        const r = scanString(b, i);
        if (r === "more") return more();
        if (r === "error") return "error";
        i = r;
        state = "colon";
        continue;
      }
      case "colon":
        if (c !== 0x3a) return "error";
        i++;
        state = "value";
        continue;
      case "after": {
        const top = stack[stack.length - 1];
        if (c === 0x2c) {
          i++;
          state = top === 0x7b ? "key" : "value";
          continue;
        }
        if ((top === 0x7b && c === 0x7d) || (top === 0x5b && c === 0x5d)) {
          stack.pop();
          i++;
          break;
        }
        return "error";
      }
    }
    // A value or a container just ended.
    if (stack.length === 0) return { end: i };
    state = "after";
  }
}

/** Bytes as Go's unquote reads a string's raw bytes: valid UTF-8 kept, each byte of an invalid sequence one U+FFFD. */
export function goUtf8(b: Buffer): string {
  let out = "";
  let i = 0;
  while (i < b.length) {
    const c = b[i] ?? 0;
    if (c < 0x80) {
      out += String.fromCharCode(c);
      i++;
      continue;
    }
    // utf8.DecodeRune's first-byte table and accept ranges.
    let size = 0;
    let lo = 0x80;
    let hi = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) size = 2;
    else if (c >= 0xe0 && c <= 0xef) {
      size = 3;
      if (c === 0xe0) lo = 0xa0;
      if (c === 0xed) hi = 0x9f;
    } else if (c >= 0xf0 && c <= 0xf4) {
      size = 4;
      if (c === 0xf0) lo = 0x90;
      if (c === 0xf4) hi = 0x8f;
    }
    let ok = size > 0 && i + size <= b.length;
    for (let k = 1; ok && k < size; k++) {
      const cc = b[i + k] ?? 0;
      if (k === 1 ? cc < lo || cc > hi : cc < 0x80 || cc > 0xbf) ok = false;
    }
    if (!ok) {
      out += REPLACEMENT;
      i++;
      continue;
    }
    out += b.toString("utf8", i, i + size);
    i += size;
  }
  return out;
}

/** encoding/json's foldName for the code points that fold into ASCII; any other non-ASCII code point folds to itself. */
export function goFoldName(key: string): string {
  let out = "";
  for (const ch of key) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp < 0x80) out += ch.toUpperCase();
    // The two letters outside ASCII whose fold set holds an ASCII letter (Go's caseOrbit): the long s and the Kelvin
    // sign. (The dotless i is not one: Go keeps it apart from i, as recorded.)
    else if (cp === 0x17f) out += "S";
    else if (cp === 0x212a) out += "K";
    else out += ch;
  }
  return out;
}

/** A JSON text (already known valid) as a JS value, strings as Go decodes them. */
function parseGo(b: Buffer): unknown {
  return wellFormed(JSON.parse(goUtf8(b)));
}

function wellFormed(v: unknown): unknown {
  if (typeof v === "string") return v.toWellFormed();
  return v;
}

/** The top-level members of a valid JSON object, in document order, repeats included: [key, value bytes]. */
function members(b: Buffer, from: number): [string, Buffer][] {
  const out: [string, Buffer][] = [];
  let i = from;
  const skip = (): void => {
    while (i < b.length && isWs(b[i] ?? 0)) i++;
  };
  skip();
  i++; // "{"
  for (;;) {
    skip();
    if (b[i] === 0x7d) return out;
    if (b[i] === 0x2c) {
      i++;
      skip();
    }
    const keyEnd = scanString(b, i) as number;
    const key = parseGo(b.subarray(i, keyEnd)) as string;
    i = keyEnd;
    skip();
    i++; // ":"
    skip();
    const value = scanValue(b, i, true) as { end: number };
    out.push([key, b.subarray(i, value.end)]);
    i = value.end;
  }
}

export type GoField = { readonly name: string; readonly kind: "string" } | { readonly name: string; readonly kind: "float-pointer" };

/**
 * Decodes one JSON value (bytes from..end, known valid) into a Go struct of the given fields. Returns the field values
 * (a string field never set is "", a pointer field never set or set to null is undefined), or null when Go's decode
 * returns an error: a top-level value that is neither an object nor `null`, or a member of the wrong type.
 */
export function decodeGoStruct(b: Buffer, fields: readonly GoField[]): Map<string, string | number | undefined> | null {
  const values = new Map<string, string | number | undefined>();
  for (const f of fields) values.set(f.name, f.kind === "string" ? "" : undefined);
  let start = 0;
  while (start < b.length && isWs(b[start] ?? 0)) start++;
  if (b[start] === 0x6e) return values; // null: nothing to do, no error
  if (b[start] !== 0x7b) return null;
  let failed = false;
  for (const [key, raw] of members(b, start)) {
    const field = fields.find((f) => f.name === key) ?? fields.find((f) => goFoldName(f.name) === goFoldName(key));
    if (field === undefined) continue;
    const first = raw[0];
    if (first === 0x6e) {
      // null: a no-op for a string, nil for a pointer.
      if (field.kind === "float-pointer") values.set(field.name, undefined);
      continue;
    }
    if (field.kind === "string") {
      if (first === 0x22) values.set(field.name, parseGo(raw) as string);
      else failed = true;
      continue;
    }
    if (first === 0x2d || isDigit(first ?? 0)) {
      // strconv.ParseFloat: out of range is an error (JSON.parse would say Infinity).
      const n = Number(raw.toString("latin1"));
      if (Number.isFinite(n)) values.set(field.name, n);
      else failed = true;
    } else {
      failed = true;
    }
  }
  return failed ? null : values;
}

/** json.Unmarshal: the whole of `b` is one value with nothing but whitespace after it, else an error (null). */
export function unmarshalGo(b: Buffer, fields: readonly GoField[]): Map<string, string | number | undefined> | null {
  let start = 0;
  while (start < b.length && isWs(b[start] ?? 0)) start++;
  const scanned = scanValue(b, start, true);
  if (typeof scanned === "string") return null;
  for (let i = scanned.end; i < b.length; i++) if (!isWs(b[i] ?? 0)) return null;
  return decodeGoStruct(b.subarray(start, scanned.end), fields);
}
