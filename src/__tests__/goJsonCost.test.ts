/**
 * What decoding an operator body costs (auth-service#25): a body at the 1 MiB cap used to hold the event loop for about
 * 110 ms, and for several hundred when it was many small keys, which stalls introspection for every other service.
 *
 * The compiled build (dist/, which `npm test` builds first) is what is measured, not the ts-jest transform of the
 * source, which runs this code about ten times slower. Each case is its best run, and its bound is several
 * times what the build takes on a development machine (most cases 5 to 20 times), so a loaded CI machine passes and only
 * a regression in kind (a quadratic or per-character cost) fails. Correctness of the decoder is vaultParity.test.ts's and the Go fuzz.
 */
import { join } from "node:path";

import type * as GoJson from "../goJson";
import { MAX_OPERATOR_BODY } from "../vault";

// eslint-disable-next-line @typescript-eslint/no-require-imports -- the compiled build, by path, is what is measured
const { decodeFirst, unmarshal } = require(join(__dirname, "..", "..", "dist", "goJson.js")) as typeof GoJson;

const BS = "\\";
const REGISTER = { accountToken: "string", symbol: "string", faction: "string", email: "string" } as const;
const REGISTERED = { data: { token: "string", agent: { symbol: "string", credits: "int" } } } as const;

/** `head`, then `unit` repeated to fill MAX_OPERATOR_BODY bytes, then `tail`. */
function body(head: string, unit: string, tail: string): Buffer {
  const reps = Math.floor((MAX_OPERATOR_BODY - head.length - tail.length) / Buffer.byteLength(unit));
  return Buffer.from(head + unit.repeat(reps) + tail, "utf8");
}

function millis(f: () => void): number {
  const t = process.hrtime.bigint();
  f();
  return Number(process.hrtime.bigint() - t) / 1e6;
}

const key = (n: number): string => `"k${String(n)}":0`;
const INVALID_UTF8 = Buffer.concat([Buffer.from('{"accountToken":"'), Buffer.from("a\xff".repeat(MAX_OPERATOR_BODY / 4), "latin1"), Buffer.from('"}')]);

/** Name, body, bound in ms. */
const CASES: [string, Buffer, number][] = [
  ["one long string", body('{"accountToken":"', "a", '"}'), 100],
  ["a string of escapes", body('{"accountToken":"', `${BS}u00e9`, '"}'), 150],
  ["a string of surrogate pairs", body('{"accountToken":"', `${BS}ud83d${BS}ude00`, '"}'), 150],
  ["a string of raw multi-byte UTF-8", body('{"accountToken":"', "é\u{1F600}", '"}'), 100],
  ["a string of invalid UTF-8, every other byte", INVALID_UTF8, 100],
  ["an array of numbers", body('{"x":[', "1,", "1]}"), 150],
  ["an array of objects", body('{"x":[', "{},", "{}]}"), 150],
  ["an array of nulls", body('{"x":[', "null,", "null]}"), 100],
  ["an array of true", body('{"x":[', "true,", "true]}"), 100],
  ["an array of false", body('{"x":[', "false,", "false]}"), 100],
  ["a key of null, repeated", body("{", '"k":null,', '"symbol":"b"}'), 100],
  ["many unknown keys", body("{", '"k":1,', '"symbol":"b"}'), 100],
  ["many distinct unknown keys", Buffer.from(`{${Array.from({ length: 60000 }, (_, i) => key(i)).join(",")},"symbol":"b"}`), 100],
  ["one key repeated, folded", body("{", '"ACCOUNTTOKEN":"a",', '"symbol":"b"}'), 100],
  ["a number of a million digits", body('{"x":', "9", "}"), 100],
  ["whitespace", body("", " ", '{"accountToken":"a"}'), 100],
];

/**
 * The fastest of up to ten runs, stopping at the first under `limit`, after one untimed run (the first is the cold one,
 * when the code is still being compiled). A machine too busy to run the code is slow on every run in a stretch, so a run
 * is repeated; code that is slow in kind is slow on all ten.
 */
function best(f: () => void, limit: number): number {
  f();
  let took = Infinity;
  for (let run = 0; run < 10 && took >= limit; run++) took = Math.min(took, millis(f));
  return took;
}

describe("decoding a body of the operator cap's size", () => {
  it.each(CASES)("%s: decodeFirst", (_name, buf, limit) => {
    expect(buf.length).toBeLessThanOrEqual(MAX_OPERATOR_BODY + 20);
    expect(best(() => decodeFirst(buf, REGISTER, "api.registerRequest"), limit)).toBeLessThan(limit);
  });

  it.each(CASES)("%s: unmarshal", (_name, buf, limit) => {
    const run = (): void => {
      try {
        unmarshal(buf, REGISTERED, "spacetraders.rawRegisterResponse");
      } catch {
        // a body that is not an answer of that shape fails; what is measured is the way there
      }
    };
    expect(best(run, limit)).toBeLessThan(limit);
  });

  it("an int field of a million digits is out of range without a BigInt of it", () => {
    const digits = body('{"data":{"agent":{"credits":', "9", "}}}");
    let error = "";
    const run = (): void => {
      try {
        unmarshal(digits, REGISTERED, "spacetraders.rawRegisterResponse");
      } catch (err) {
        error = (err as Error).message;
      }
    };
    expect(best(run, 40)).toBeLessThan(40);
    expect(error).toMatch(/^json: cannot unmarshal number 9+ into Go struct field /);
  });

  it("keeps what the struct is for, wherever the body spreads", () => {
    const buf = Buffer.from(`{"x":[1,"s",{"accountToken":"inner"}],"AccountToken":"outer","y":{"symbol":"no"},"SYMBOL":"S","faction":null}`);
    expect(decodeFirst(buf, REGISTER, "api.registerRequest")).toEqual({ accountToken: "outer", symbol: "S", faction: "", email: "" });
  });

  it("turns each invalid byte of a kept string into one U+FFFD", () => {
    const buf = Buffer.concat([Buffer.from('{"accountToken":"a'), Buffer.from([0xff, 0xc3, 0x28, 0xe2, 0x82, 0xc3, 0xa9]), Buffer.from('b\\n"}')]);
    expect(decodeFirst(buf, REGISTER, "api.registerRequest").accountToken).toBe("a��(��éb\n");
  });

  it("reports input cut off inside an escape as Go's scanner does (a space follows the end of an Unmarshal's input)", () => {
    const cut = (text: string): string => {
      try {
        unmarshal(Buffer.from(text), REGISTERED, "x.y");
        return "";
      } catch (err) {
        return (err as Error).message;
      }
    };
    expect(cut('"\\')).toBe("invalid character ' ' in string escape code");
    expect(cut('"\\u12')).toBe("invalid character ' ' in \\u hexadecimal character escape");
    expect(cut('{"a":"\\ud800\\')).toBe("invalid character ' ' in string escape code");
    expect(() => decodeFirst(Buffer.from('"\\'), REGISTER, "x.y")).toThrow("unexpected EOF");
  });
});
