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

/**
 * What a struct has for a value: a string, an int, or a nested struct. The parser keeps only the values a field of the
 * struct is for (and the objects on the way to them): anything else is read for its syntax and dropped, so the cost of a
 * body does not depend on how much of it the struct ignores.
 */
type FieldType = Shape[string];

const EMPTY_OBJECT: Value = { kind: "object", entries: [] };
const EMPTY_ARRAY: Value = { kind: "array" };
const BOOL: Value = { kind: "bool" };
const NULL: Value = { kind: "null" };
/** A value that was read and dropped: nothing looks at it. */
const SKIPPED: Value = { kind: "null" };

/**
 * Go's quoteChar, for a syntax error's message: the byte read as the rune of the same number, quoted as strconv.Quote
 * quotes it (so a UTF-8 BOM's first byte is 'ï', and 0x85 is '\u0085').
 */
function quoteChar(c: number): string {
  if (c === 0x27) return `'\\''`;
  if (c === 0x22) return `'"'`;
  const named: Record<number, string> = { 0x07: "a", 0x08: "b", 0x09: "t", 0x0a: "n", 0x0b: "v", 0x0c: "f", 0x0d: "r", 0x5c: "\\" };
  const name = named[c];
  if (name !== undefined) return `'\\${name}'`;
  if (c < 0x20 || c === 0x7f) return `'\\x${c.toString(16).padStart(2, "0")}'`;
  // strconv.IsPrint is false for the C1 controls, NO-BREAK SPACE and SOFT HYPHEN.
  if ((c >= 0x80 && c <= 0xa0) || c === 0xad) return `'\\u00${c.toString(16).padStart(2, "0")}'`;
  return `'${String.fromCharCode(c)}'`;
}

/** Go's scanner refuses nesting deeper than this (maxNestingDepth): the 10001st open bracket is a syntax error. */
export const MAX_NESTING_DEPTH = 10000;

const isDigit = (c: number | undefined): boolean => c !== undefined && c >= 0x30 && c <= 0x39;
const hexValue = (c: number | undefined): number => {
  if (c === undefined) return -1;
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x37;
  if (c >= 0x61 && c <= 0x66) return c - 0x57;
  return -1;
};

/** The single-character escapes (`\n` and the like), by the byte after the backslash. */
const SIMPLE_ESCAPE: (string | undefined)[] = [];
SIMPLE_ESCAPE[0x22] = '"';
SIMPLE_ESCAPE[0x5c] = "\\";
SIMPLE_ESCAPE[0x2f] = "/";
SIMPLE_ESCAPE[0x62] = "\b";
SIMPLE_ESCAPE[0x66] = "\f";
SIMPLE_ESCAPE[0x6e] = "\n";
SIMPLE_ESCAPE[0x72] = "\r";
SIMPLE_ESCAPE[0x74] = "\t";

/**
 * The width of the valid UTF-8 sequence that starts at `i` (a byte of 0x80 or more), or 0 when it is not valid, which
 * is Go's utf8.DecodeRune answering U+FFFD of width 1. Overlongs, surrogates and anything past U+10FFFF are invalid.
 */
function utf8Width(b: Buffer, i: number): number {
  const b0 = b[i] ?? 0;
  const b1 = b[i + 1];
  if (b1 === undefined || b1 < 0x80 || b1 > 0xbf) return 0;
  if (b0 >= 0xc2 && b0 <= 0xdf) return 2;
  const b2 = b[i + 2];
  if (b0 >= 0xe0 && b0 <= 0xef) {
    if ((b0 === 0xe0 && b1 < 0xa0) || (b0 === 0xed && b1 > 0x9f)) return 0;
    return b2 !== undefined && b2 >= 0x80 && b2 <= 0xbf ? 3 : 0;
  }
  if (b0 >= 0xf0 && b0 <= 0xf4) {
    if ((b0 === 0xf0 && b1 < 0x90) || (b0 === 0xf4 && b1 > 0x8f)) return 0;
    const b3 = b[i + 3];
    return b2 !== undefined && b2 >= 0x80 && b2 <= 0xbf && b3 !== undefined && b3 >= 0x80 && b3 <= 0xbf ? 4 : 0;
  }
  return 0;
}

/** Thrown inside the parser for an input that ended inside a value. */
class Truncated extends Error {}

class Parser {
  private i = 0;
  /**
   * `eofIsSpace`: Unmarshal's end of input. Go's scanner then feeds one more byte, a space, so input that ends inside a
   * literal or a number is a syntax error about that space (`invalid character ' ' in exponent of numeric literal`), and
   * only input that ends elsewhere is "unexpected end of JSON input". A Decoder reports any early end as "unexpected EOF".
   */
  constructor(
    private readonly b: Buffer,
    private readonly shape: Shape,
    private readonly eofIsSpace = false,
  ) {}

  /** The next byte inside a literal or a number, where the end of input reads as a space under Unmarshal. */
  private needIn(context: string): number {
    const c = this.b[this.i];
    if (c !== undefined) return c;
    if (this.eofIsSpace) this.fail(0x20, context);
    throw new Truncated();
  }

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
    const b = this.b;
    let i = this.i;
    for (let c = b[i]; c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d; c = b[i]) i++;
    this.i = i;
  }

  atEnd(): boolean {
    return this.i >= this.b.length;
  }

  /**
   * One value, without recursion: containers are kept on an explicit stack, so a deeply nested body cannot exhaust the
   * call stack (Go's scanner refuses more than MAX_NESTING_DEPTH levels, and so does this). A literal or a number ends at
   * the first byte that cannot continue it, which is all a Decoder's top-level value needs; inside a container the byte
   * after a value is checked here.
   */
  value(): Value {
    type Open =
      | { kind: "object"; entries: (readonly [string, Value])[]; key: string | undefined; shape: Shape | undefined }
      | { kind: "array" };
    const stack: Open[] = [];
    for (;;) {
      // A value starts here. `want` is what the struct has for it: nothing when it is an array's element or the value of
      // a key no field matches, and then it is read for its syntax only.
      this.skipWhite();
      const c = this.need();
      const top0 = stack[stack.length - 1];
      const want: FieldType | undefined =
        top0 === undefined ? this.shape : top0.kind === "object" && top0.key !== undefined ? top0.shape?.[top0.key] : undefined;
      let v: Value | undefined;
      if (c === 0x7b || c === 0x5b) {
        if (stack.length >= MAX_NESTING_DEPTH) this.fail(c, "exceeded max depth");
        this.i++;
        this.skipWhite();
        if (c === 0x7b) {
          if (this.need() === 0x7d) {
            this.i++;
            v = EMPTY_OBJECT;
          } else {
            const shape = typeof want === "object" ? want : undefined;
            stack.push({ kind: "object", entries: [], key: this.key(shape), shape });
            continue;
          }
        } else if (this.need() === 0x5d) {
          this.i++;
          v = EMPTY_ARRAY;
        } else {
          stack.push({ kind: "array" });
          continue;
        }
      } else if (c === 0x22) v = want === undefined ? (this.string(false), SKIPPED) : { kind: "string", value: this.string(true) };
      else if (c === 0x2d || isDigit(c)) v = want === undefined ? (this.number(false), SKIPPED) : { kind: "number", text: this.number(true) };
      else if (c === 0x74) v = this.literal("true", BOOL);
      else if (c === 0x66) v = this.literal("false", BOOL);
      else if (c === 0x6e) v = this.literal("null", NULL);
      else this.fail(c, "looking for beginning of value");

      // A value ended: hand it to the container it is in, and close containers as long as they end.
      for (;;) {
        const top = stack[stack.length - 1];
        if (top === undefined) return v;
        if (top.kind === "object" && top.key !== undefined) top.entries.push([top.key, v]);
        this.skipWhite();
        const next = this.need();
        this.i++;
        if (top.kind === "object") {
          if (next === 0x2c) {
            top.key = this.key(top.shape);
            break;
          }
          if (next !== 0x7d) this.fail(next, "after object key:value pair");
          v = top.shape === undefined ? EMPTY_OBJECT : { kind: "object", entries: top.entries };
        } else {
          if (next === 0x2c) break;
          if (next !== 0x5d) this.fail(next, "after array element");
          v = EMPTY_ARRAY;
        }
        stack.pop();
      }
    }
  }

  /** An object key and its colon; the name of the field of `shape` it matches, if any. */
  private key(shape: Shape | undefined): string | undefined {
    this.skipWhite();
    const q = this.need();
    if (q !== 0x22) this.fail(q, "looking for beginning of object key string");
    let key: string | undefined;
    if (shape === undefined) this.string(false);
    else {
      // A key of plain ASCII, of a length no field has, is no field's: passed over without being made a string.
      const b = this.b;
      let j = this.i + 1;
      for (let x = b[j]; x !== undefined && x >= 0x20 && x < 0x80 && x !== 0x22 && x !== 0x5c; x = b[j]) j++;
      if (b[j] === 0x22 && !matcherFor(shape).lengths.has(j - this.i - 1)) this.i = j + 1;
      else key = matchField(shape, this.string(true));
    }
    this.skipWhite();
    const colon = this.need();
    if (colon !== 0x3a) this.fail(colon, "after object key");
    this.i++;
    return key;
  }

  private literal(word: string, v: Value): Value {
    this.i++;
    for (let k = 1; k < word.length; k++) {
      const c = this.b[this.i];
      if (c === word.charCodeAt(k)) {
        this.i++;
        continue;
      }
      // The error's context is made only when there is an error (it is not free).
      const context = `in literal ${word} (expecting ${quoteChar(word.charCodeAt(k))})`;
      return this.fail(this.needIn(context), context);
    }
    return v;
  }

  private number(keep: boolean): string {
    const start = this.i;
    // The common number: digits and nothing after them that a number goes on with. (Anything else takes the full path.)
    if (!keep) {
      const b = this.b;
      let j = this.i;
      let c = b[j];
      if (c !== undefined && c >= 0x31 && c <= 0x39) {
        do c = b[++j];
        while (c !== undefined && c >= 0x30 && c <= 0x39);
        if (c !== 0x2e && c !== 0x65 && c !== 0x45) {
          this.i = j;
          return "";
        }
      }
    }
    if (this.peek() === 0x2d) {
      this.i++;
      const c = this.needIn("in numeric literal");
      if (!isDigit(c)) this.fail(c, "in numeric literal");
    }
    if (this.peek() === 0x30) this.i++;
    else while (isDigit(this.peek())) this.i++;
    if (this.peek() === 0x2e) {
      this.i++;
      const c = this.needIn("after decimal point in numeric literal");
      if (!isDigit(c)) this.fail(c, "after decimal point in numeric literal");
      while (isDigit(this.peek())) this.i++;
    }
    if (this.peek() === 0x65 || this.peek() === 0x45) {
      this.i++;
      if (this.peek() === 0x2b || this.peek() === 0x2d) this.i++;
      const c = this.needIn("in exponent of numeric literal");
      if (!isDigit(c)) this.fail(c, "in exponent of numeric literal");
      while (isDigit(this.peek())) this.i++;
    }
    return keep ? this.b.toString("latin1", start, this.i) : "";
  }

  /**
   * A string literal, unquoted as Go's unquote does it. Linear: plain bytes are found by a scan and handed over a run
   * at a time (one `toString` per run, never one append per character), and a non-ASCII sequence is checked as UTF-8
   * the way Go's utf8.DecodeRune reads it, each byte of an invalid sequence becoming one U+FFFD.
   */
  private string(keep: boolean): string {
    const b = this.b;
    this.i++; // the opening quote
    let out = "";
    let start = this.i; // where the run of bytes that go in as they are begins
    for (;;) {
      let j = this.i;
      while (j < b.length) {
        const x = b[j] ?? 0;
        if (x === 0x22 || x === 0x5c || x < 0x20 || x >= 0x80) break;
        j++;
      }
      this.i = j;
      const c = this.need();
      if (c === 0x22) {
        if (keep) out += b.toString("utf8", start, this.i);
        this.i++;
        return out;
      }
      if (c < 0x20) this.fail(c, "in string literal");
      if (c >= 0x80) {
        const width = utf8Width(b, this.i);
        if (width > 0) this.i += width;
        else if (!keep) this.i++;
        else {
          // Invalid UTF-8 in a string that is kept: the rest of this run of raw bytes is copied into one buffer, a
          // U+FFFD (EF BF BD) for each invalid byte, and decoded once (not once per invalid byte).
          let end = this.i;
          while (end < b.length && b[end] !== 0x22 && b[end] !== 0x5c && (b[end] ?? 0) >= 0x20) end++;
          const run = Buffer.allocUnsafe((end - start) * 3);
          let w = 0;
          let from = start;
          for (let k = this.i; k < end; ) {
            if ((b[k] ?? 0) < 0x80) {
              k++;
              continue;
            }
            const wd = utf8Width(b, k);
            if (wd > 0) {
              k += wd;
              continue;
            }
            w += b.copy(run, w, from, k);
            run[w++] = 0xef;
            run[w++] = 0xbf;
            run[w++] = 0xbd;
            k++;
            from = k;
          }
          w += b.copy(run, w, from, end);
          out += run.toString("utf8", 0, w);
          this.i = end;
          start = end;
        }
        continue;
      }
      // A backslash.
      if (keep) out += b.toString("utf8", start, this.i);
      this.i++;
      const e = this.needIn("in string escape code");
      const s = SIMPLE_ESCAPE[e];
      if (s !== undefined) {
        if (keep) out += s;
        this.i++;
      } else {
        if (e !== 0x75) this.fail(e, "in string escape code");
        this.i++;
        const r = this.hex4();
        if (r >= 0xd800 && r < 0xe000) {
          // A surrogate: combined with an escaped low surrogate right after it, U+FFFD otherwise (Go's utf16.DecodeRune).
          let pair = false;
          if (r < 0xdc00 && b[this.i] === 0x5c && b[this.i + 1] === 0x75) {
            const save = this.i;
            this.i += 2;
            const r2 = this.hex4();
            if (r2 >= 0xdc00 && r2 < 0xe000) {
              if (keep) out += String.fromCodePoint(0x10000 + ((r - 0xd800) << 10) + (r2 - 0xdc00));
              pair = true;
            } else this.i = save;
          }
          if (keep && !pair) out += "\ufffd";
        } else if (keep) out += String.fromCharCode(r);
      }
      start = this.i;
    }
  }

  private hex4(): number {
    let r = 0;
    for (let k = 0; k < 4; k++) {
      const c = this.needIn("in \\u hexadecimal character escape");
      const h = hexValue(c);
      if (h < 0) this.fail(c, "in \\u hexadecimal character escape");
      r = r * 16 + h;
      this.i++;
    }
    return r;
  }
}

/** `json.NewDecoder(body).Decode(&v)`'s read: the first value, the rest never looked at. */
function decoderValue(body: Buffer, shape: Shape): Value {
  const p = new Parser(body, shape);
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
function unmarshalValue(data: Buffer, shape: Shape): Value {
  const p = new Parser(data, shape, true);
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
  if (!/[\u0080-\uffff]/.test(s)) return s.toUpperCase(); // all ASCII
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

interface Matcher {
  readonly exact: ReadonlyMap<string, string>;
  readonly folded: ReadonlyMap<string, string>;
  readonly lengths: ReadonlySet<number>;
}
const matchers = new WeakMap<Shape, Matcher>();

/**
 * The field of `shape` that object key `key` is for, or undefined: the field named exactly so, else the first whose
 * folded name is the key's folded name (Go's order). A fold keeps the length (one UTF-16 unit for one), so a key of a
 * length no field has is turned away without being folded.
 */
function matcherFor(shape: Shape): Matcher {
  let m = matchers.get(shape);
  if (m === undefined) {
    const exact = new Map<string, string>();
    const folded = new Map<string, string>();
    const lengths = new Set<number>();
    for (const name of Object.keys(shape)) {
      exact.set(name, name);
      const f = foldName(name);
      if (!folded.has(f)) folded.set(f, name);
      lengths.add(name.length);
    }
    m = { exact, folded, lengths };
    matchers.set(shape, m);
  }
  return m;
}

function matchField(shape: Shape, key: string): string | undefined {
  const m = matcherFor(shape);
  const hit = m.exact.get(key);
  if (hit !== undefined) return hit;
  return m.lengths.has(key.length) ? m.folded.get(foldName(key)) : undefined;
}

function zero<S extends Shape>(shape: S): Decoded<S> {
  const out: Record<string, unknown> = {};
  for (const [name, type] of Object.entries(shape)) out[name] = type === "string" ? "" : type === "int" ? 0n : zero(type);
  return out as Decoded<S>;
}

const MIN_INT64 = -(2n ** 63n);
const MAX_INT64 = 2n ** 63n - 1n;

const typeOf = (v: Value): string => (v.kind === "bool" ? "bool" : v.kind);

/**
 * The Go type of an anonymous struct of `shape`, as reflect prints it in an UnmarshalTypeError: each field is the JSON
 * name capitalised (how the Go service's types name them), its type, and its tag quoted
 * (`struct { Next string "json:\"next\""; Frequency string "json:\"frequency\"" }`).
 */
function goStructType(shape: Shape): string {
  const fields = Object.entries(shape).map(([name, type]) => {
    const goType = type === "string" ? "string" : type === "int" ? "int" : goStructType(type);
    return `${name.charAt(0).toUpperCase()}${name.slice(1)} ${goType} ${JSON.stringify(`json:"${name}"`)}`;
  });
  return `struct { ${fields.join("; ")} }`;
}

/**
 * Decodes `v` into a struct of `shape`, filling `into`; returns the first type error (Go's saveError) or null.
 * The wording is Go 1.22's UnmarshalTypeError: "Go value of type <package.Type>" for the whole value, and for a field
 * "Go struct field <S>.<path from the top>", where <S> is the name of the struct the field is in (empty for the
 * anonymous structs nested in the upstream types).
 */
function fill(v: Value, shape: Shape, into: Record<string, unknown>, path: string, structName: string): string | null {
  let first: string | null = null;
  if (v.kind !== "object") return null;
  // The parser kept the entries a field matched, under the field's name.
  for (const [name, value] of v.entries) {
    const type = shape[name];
    if (type === undefined) continue;
    const where = `${path}${path === "" ? "" : "."}${name}`;
    const field = (what: string, goType: string): string => `json: cannot unmarshal ${what} into Go struct field ${structName}.${where} of type ${goType}`;
    let error: string | null = null;
    if (value.kind === "null") {
      // null leaves the field as it is.
    } else if (type === "string") {
      if (value.kind === "string") into[name] = value.value;
      else error = field(typeOf(value), "string");
    } else if (type === "int") {
      // Longer than any int64 (19 digits and a sign) is out of range, without the BigInt of a megabyte of digits.
      const n = value.kind === "number" && value.text.length <= 20 && /^-?[0-9]+$/.test(value.text) ? BigInt(value.text) : null;
      if (n !== null && n >= MIN_INT64 && n <= MAX_INT64) into[name] = n;
      else error = field(value.kind === "number" ? `number ${value.text}` : typeOf(value), "int");
    } else if (value.kind !== "object") {
      error = field(typeOf(value), goStructType(type));
    } else {
      error = fill(value, type, into[name] as Record<string, unknown>, where, "");
    }
    first ??= error;
  }
  return first;
}

function decodeInto<S extends Shape>(v: Value, shape: S, typeName: string): Decoded<S> {
  const out = zero(shape);
  if (v.kind !== "object" && v.kind !== "null") throw new GoJsonError(`json: cannot unmarshal ${typeOf(v)} into Go value of type ${typeName}`);
  const error = fill(v, shape, out, "", typeName.slice(typeName.lastIndexOf(".") + 1));
  if (error !== null) throw new GoJsonError(error);
  return out;
}

/** `json.NewDecoder(body).Decode(&v)` into a struct of `shape`. Throws GoJsonError. */
export function decodeFirst<S extends Shape>(body: Buffer, shape: S, typeName: string): Decoded<S> {
  return decodeInto(decoderValue(body, shape), shape, typeName);
}

/** `json.Unmarshal(data, &v)` into a struct of `shape`. Throws GoJsonError. */
export function unmarshal<S extends Shape>(data: Buffer, shape: S, typeName: string): Decoded<S> {
  return decodeInto(unmarshalValue(data, shape), shape, typeName);
}
