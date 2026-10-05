/**
 * @file Go's `encoding/json` (Go 1.22), as far as the vault's decoding depends on it: what the operator routes accept
 * as a request body (`json.NewDecoder(r.Body).Decode(&body)`) and what is read out of SpaceTraders' answers
 * (`json.Unmarshal`). `JSON.parse` answers differently from both (contract README note 22), so neither is used for these.
 *
 *  - **Decoder**: the FIRST JSON value of the stream is decoded and whatever follows it is never read; a top-level
 *    literal or number ends at the first byte that cannot continue it (`nulls` is null, `42x` is 42). Nothing at all
 *    is `EOF`, a value cut short `unexpected EOF`.
 *  - **Unmarshal**: the whole input must be one value with only whitespace around it.
 *  - Into a struct: object keys match a field exactly, else case-insensitively by simple case folding (KELVIN SIGN
 *    matches `k`, LONG S matches `s`, the Turkish i's match nothing); unknown keys are ignored; a repeated key's
 *    last value wins; `null` leaves a field (or the whole struct) as it is. A value of the wrong type is an error, and
 *    decoding goes on (Go reports the first such error after the whole value is read), so any type error fails it.
 *  - Strings: invalid UTF-8 becomes U+FFFD per byte, a `\u` escape of a lone surrogate becomes U+FFFD, raw control
 *    characters are a syntax error.
 *  - Ints (`credits`): `strconv.ParseInt(literal, 10, 64)`, so `1.0` and `1e2` are type errors; a bigint.
 *
 * Error messages are Go's in shape; their wording is not pinned (the epic's accepted deviation 1) beyond the
 * `invalid request body: ` prefix the routes put in front.
 */
import { decodeRune } from "./http/goForm";

/** A decode failure: a syntax error, an early end, or a value of the wrong type. */
export class GoJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GoJsonError";
  }
}

type Value =
  | { readonly kind: "object"; readonly entries: readonly (readonly [string, Value])[] }
  | { readonly kind: "array" }
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "number"; readonly text: string }
  | { readonly kind: "bool" }
  | { readonly kind: "null" };

/** Go's quoteChar, for a syntax error's message. */
function quoteChar(c: number): string {
  if (c === 0x27) return `'\\''`;
  if (c === 0x22) return `'"'`;
  if (c < 0x20 || c >= 0x7f) return `'\\x${c.toString(16).padStart(2, "0")}'`;
  return `'${String.fromCharCode(c)}'`;
}

const isWhite = (c: number | undefined): boolean => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
const isDigit = (c: number | undefined): boolean => c !== undefined && c >= 0x30 && c <= 0x39;
const hexValue = (c: number | undefined): number => {
  if (c === undefined) return -1;
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x37;
  if (c >= 0x61 && c <= 0x66) return c - 0x57;
  return -1;
};

/** Thrown inside the parser for an input that ended inside a value. */
class Truncated extends Error {}

class Parser {
  private i = 0;
  constructor(private readonly b: Buffer) {}

  get position(): number {
    return this.i;
  }

  private peek(): number | undefined {
    return this.b[this.i];
  }

  /** The next byte, or Truncated at the end of the input. */
  private need(): number {
    const c = this.b[this.i];
    if (c === undefined) throw new Truncated();
    return c;
  }

  private fail(c: number, context: string): never {
    throw new GoJsonError(`invalid character ${quoteChar(c)} ${context}`);
  }

  skipWhite(): void {
    while (isWhite(this.peek())) this.i++;
  }

  atEnd(): boolean {
    return this.i >= this.b.length;
  }

  /**
   * One value. A literal or a number ends at the first byte that cannot continue it, which is all a Decoder's
   * top-level value needs; inside a container the caller then checks that byte.
   */
  value(): Value {
    this.skipWhite();
    const c = this.need();
    if (c === 0x7b) return this.object();
    if (c === 0x5b) return this.array();
    if (c === 0x22) return { kind: "string", value: this.string() };
    if (c === 0x2d || isDigit(c)) return { kind: "number", text: this.number() };
    if (c === 0x74) return this.literal("true", { kind: "bool" });
    if (c === 0x66) return this.literal("false", { kind: "bool" });
    if (c === 0x6e) return this.literal("null", { kind: "null" });
    return this.fail(c, "looking for beginning of value");
  }

  private literal(word: string, v: Value): Value {
    this.i++;
    for (let k = 1; k < word.length; k++) {
      const c = this.need();
      if (c !== word.charCodeAt(k)) this.fail(c, `in literal ${word} (expecting ${quoteChar(word.charCodeAt(k))})`);
      this.i++;
    }
    return v;
  }

  private number(): string {
    const start = this.i;
    if (this.peek() === 0x2d) {
      this.i++;
      const c = this.need();
      if (!isDigit(c)) this.fail(c, "in numeric literal");
    }
    if (this.peek() === 0x30) this.i++;
    else while (isDigit(this.peek())) this.i++;
    if (this.peek() === 0x2e) {
      this.i++;
      const c = this.need();
      if (!isDigit(c)) this.fail(c, "after decimal point in numeric literal");
      while (isDigit(this.peek())) this.i++;
    }
    if (this.peek() === 0x65 || this.peek() === 0x45) {
      this.i++;
      if (this.peek() === 0x2b || this.peek() === 0x2d) this.i++;
      const c = this.need();
      if (!isDigit(c)) this.fail(c, "in exponent of numeric literal");
      while (isDigit(this.peek())) this.i++;
    }
    return this.b.toString("latin1", start, this.i);
  }

  /** A string literal, unquoted as Go's unquote does it. */
  private string(): string {
    this.i++; // the opening quote
    let out = "";
    const latin1 = (from: number, to: number): string => this.b.toString("latin1", from, to);
    for (;;) {
      const c = this.need();
      if (c === 0x22) {
        this.i++;
        return out;
      }
      if (c < 0x20) this.fail(c, "in string literal");
      if (c === 0x5c) {
        this.i++;
        const e = this.need();
        const simple: Record<number, string> = { 0x22: '"', 0x5c: "\\", 0x2f: "/", 0x62: "\b", 0x66: "\f", 0x6e: "\n", 0x72: "\r", 0x74: "\t" };
        const s = simple[e];
        if (s !== undefined) {
          out += s;
          this.i++;
          continue;
        }
        if (e !== 0x75) this.fail(e, "in string escape code");
        this.i++;
        const r = this.hex4();
        if (r >= 0xd800 && r < 0xe000) {
          // A surrogate: combined with an escaped low surrogate right after it, U+FFFD otherwise (Go's utf16.DecodeRune).
          if (r < 0xdc00 && this.b[this.i] === 0x5c && this.b[this.i + 1] === 0x75) {
            const save = this.i;
            this.i += 2;
            const r2 = this.hex4();
            if (r2 >= 0xdc00 && r2 < 0xe000) {
              out += String.fromCodePoint(0x10000 + ((r - 0xd800) << 10) + (r2 - 0xdc00));
              continue;
            }
            this.i = save;
          }
          out += "�";
          continue;
        }
        out += String.fromCharCode(r);
        continue;
      }
      if (c < 0x80) {
        out += String.fromCharCode(c);
        this.i++;
        continue;
      }
      // UTF-8 as Go's utf8.DecodeRune reads it: each byte of an invalid sequence is one U+FFFD.
      const [rune, width] = decodeRune(latin1(this.i, Math.min(this.i + 4, this.b.length)), 0);
      out += String.fromCodePoint(rune);
      this.i += width;
    }
  }

  private hex4(): number {
    let r = 0;
    for (let k = 0; k < 4; k++) {
      const c = this.need();
      const h = hexValue(c);
      if (h < 0) this.fail(c, "in \\u hexadecimal character escape");
      r = r * 16 + h;
      this.i++;
    }
    return r;
  }

  private object(): Value {
    this.i++;
    const entries: (readonly [string, Value])[] = [];
    this.skipWhite();
    if (this.need() === 0x7d) {
      this.i++;
      return { kind: "object", entries };
    }
    for (;;) {
      this.skipWhite();
      const q = this.need();
      if (q !== 0x22) this.fail(q, "looking for beginning of object key string");
      const key = this.string();
      this.skipWhite();
      const colon = this.need();
      if (colon !== 0x3a) this.fail(colon, "after object key");
      this.i++;
      entries.push([key, this.value()]);
      this.skipWhite();
      const next = this.need();
      this.i++;
      if (next === 0x7d) return { kind: "object", entries };
      if (next !== 0x2c) this.fail(next, "after object key:value pair");
    }
  }

  private array(): Value {
    this.i++;
    this.skipWhite();
    if (this.need() === 0x5d) {
      this.i++;
      return { kind: "array" };
    }
    for (;;) {
      this.value();
      this.skipWhite();
      const next = this.need();
      this.i++;
      if (next === 0x5d) return { kind: "array" };
      if (next !== 0x2c) this.fail(next, "after array element");
    }
  }
}

/** `json.NewDecoder(body).Decode(&v)`'s read: the first value, the rest never looked at. */
function decoderValue(body: Buffer): Value {
  const p = new Parser(body);
  p.skipWhite();
  if (p.atEnd()) throw new GoJsonError("EOF");
  try {
    return p.value();
  } catch (err) {
    if (err instanceof Truncated) throw new GoJsonError("unexpected EOF");
    throw err;
  }
}

/** `json.Unmarshal(data, &v)`'s read: exactly one value. */
function unmarshalValue(data: Buffer): Value {
  const p = new Parser(data);
  let v: Value;
  try {
    v = p.value();
  } catch (err) {
    if (err instanceof Truncated) throw new GoJsonError("unexpected end of JSON input");
    throw err;
  }
  p.skipWhite();
  const extra = data[p.position];
  if (extra !== undefined) throw new GoJsonError(`invalid character ${quoteChar(extra)} after top-level value`);
  return v;
}

// ---------------------------------------------------------------------------------------------------------------------
// Into a struct.

/** A struct's fields by their JSON names, each a string, an int, or a nested struct. */
export interface Shape {
  readonly [name: string]: "string" | "int" | Shape;
}

/** What decoding a Shape gives: every field present, "" / 0 / the empty struct where the JSON said nothing. */
export type Decoded<S extends Shape> = { -readonly [K in keyof S]: S[K] extends "string" ? string : S[K] extends "int" ? bigint : S[K] extends Shape ? Decoded<S[K]> : never };

/**
 * The case-insensitive key match, as Go 1.22 makes it: ASCII letters by case, and Unicode simple case folding, under
 * which U+212A KELVIN SIGN is a `k` and U+017F LONG S an `s`. Field names are ASCII, so those are the only non-ASCII
 * runes that can match one; the Turkish dotted and dotless i (U+0130, U+0131) do NOT fold onto `i` (recorded against
 * Go, go-vault-verdicts.json). Any other non-ASCII rune is kept, and can then never equal a field's folded name.
 */
function foldName(s: string): string {
  let out = "";
  for (const ch of s) {
    const r = ch.codePointAt(0) ?? 0;
    if (r === 0x212a) out += "K";
    else if (r === 0x17f) out += "S";
    else if (r < 0x80) out += ch.toUpperCase();
    else out += ch;
  }
  return out;
}

function zero<S extends Shape>(shape: S): Decoded<S> {
  const out: Record<string, unknown> = {};
  for (const [name, type] of Object.entries(shape)) out[name] = type === "string" ? "" : type === "int" ? 0n : zero(type);
  return out as Decoded<S>;
}

const MIN_INT64 = -(2n ** 63n);
const MAX_INT64 = 2n ** 63n - 1n;

const typeOf = (v: Value): string => (v.kind === "bool" ? "bool" : v.kind);

/** Decodes `v` into a struct of `shape`, filling `into`; returns the first type error (Go's saveError) or null. */
function fill(v: Value, shape: Shape, into: Record<string, unknown>, path: string, typeName: string): string | null {
  if (v.kind === "null") return null;
  if (v.kind !== "object") return `json: cannot unmarshal ${typeOf(v)} into Go value of type ${typeName}`;
  let first: string | null = null;
  const names = Object.keys(shape);
  for (const [key, value] of v.entries) {
    const name = names.find((n) => n === key) ?? names.find((n) => foldName(n) === foldName(key));
    if (name === undefined) continue;
    const type = shape[name];
    if (type === undefined) continue;
    const where = `${path}${path === "" ? "" : "."}${name}`;
    let error: string | null = null;
    if (value.kind === "null") {
      // null leaves the field as it is.
    } else if (type === "string") {
      if (value.kind === "string") into[name] = value.value;
      else error = `json: cannot unmarshal ${typeOf(value)} into Go struct field ${typeName}.${where} of type string`;
    } else if (type === "int") {
      const n = value.kind === "number" && /^-?[0-9]+$/.test(value.text) ? BigInt(value.text) : null;
      if (n !== null && n >= MIN_INT64 && n <= MAX_INT64) into[name] = n;
      else error = `json: cannot unmarshal ${value.kind === "number" ? `number ${value.text}` : typeOf(value)} into Go struct field ${typeName}.${where} of type int`;
    } else {
      error = fill(value, type, into[name] as Record<string, unknown>, where, typeName);
    }
    first ??= error;
  }
  return first;
}

function decodeInto<S extends Shape>(v: Value, shape: S, typeName: string): Decoded<S> {
  const out = zero(shape);
  const error = fill(v, shape, out, "", typeName);
  if (error !== null) throw new GoJsonError(error);
  return out;
}

/** `json.NewDecoder(body).Decode(&v)` into a struct of `shape`. Throws GoJsonError. */
export function decodeFirst<S extends Shape>(body: Buffer, shape: S, typeName: string): Decoded<S> {
  return decodeInto(decoderValue(body), shape, typeName);
}

/** `json.Unmarshal(data, &v)` into a struct of `shape`. Throws GoJsonError. */
export function unmarshal<S extends Shape>(data: Buffer, shape: S, typeName: string): Decoded<S> {
  return decodeInto(unmarshalValue(data), shape, typeName);
}

/**
 * Whether the first JSON value of `body` is complete: false when the decoder would need more input. Lets a caller read
 * a body only as far as Go's Decoder would.
 */
export function firstValueComplete(body: Buffer): boolean {
  try {
    decoderValue(body);
    return true;
  } catch (err) {
    return !(err instanceof GoJsonError && (err.message === "EOF" || err.message === "unexpected EOF"));
  }
}
