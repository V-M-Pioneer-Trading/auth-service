/**
 * What decoding an operator body costs (auth-service#25): a body at the 1 MiB cap used to hold the event loop for about
 * 110 ms, and for several hundred when it was many small keys, which stalls introspection for every other service.
 * The bounds are generous (a slow CI machine runs several times slower than a development one, and the first run of
 * each shape is cold) and sit well under what the quadratic or per-character code cost, so only a regression in kind
 * trips them. Correctness of the decoder itself is vaultParity.test.ts's and the fuzz against Go's.
 */
import { decodeFirst, unmarshal } from "../goJson";
import { MAX_OPERATOR_BODY } from "../vault";

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

const CASES: [string, Buffer, number][] = [
  ["one long string", body('{"accountToken":"', "a", '"}'), 120],
  ["a string of escapes", body('{"accountToken":"', `${BS}u00e9`, '"}'), 120],
  ["a string of surrogate pairs", body('{"accountToken":"', `${BS}ud83d${BS}ude00`, '"}'), 120],
  ["a string of raw multi-byte UTF-8", body('{"accountToken":"', "é\u{1F600}", '"}'), 120],
  ["a string of invalid UTF-8", Buffer.concat([Buffer.from('{"accountToken":"'), Buffer.alloc(MAX_OPERATOR_BODY - 20, 0xff), Buffer.from('"}')]), 250],
  ["an array of numbers", body('{"x":[', "1,", "1]}"), 250],
  ["an array of objects", body('{"x":[', "{},", "{}]}"), 250],
  ["many unknown keys", body("{", '"k":1,', '"symbol":"b"}'), 250],
  ["many distinct unknown keys", Buffer.from(`{${Array.from({ length: 60000 }, (_, i) => `"k${String(i)}":0`).join(",")},"symbol":"b"}`), 250],
  ["one key repeated, folded", body("{", '"ACCOUNTTOKEN":"a",', '"symbol":"b"}'), 400],
  ["a number of a million digits", body('{"x":', "9", "}"), 120],
  ["whitespace", body("", " ", '{"accountToken":"a"}'), 120],
];

describe("decoding a body of the operator cap's size", () => {
  it.each(CASES)("%s: decodeFirst", (_name, buf, limit) => {
    expect(buf.length).toBeLessThanOrEqual(MAX_OPERATOR_BODY + 20);
    let took = Infinity;
    for (let run = 0; run < 3; run++) took = Math.min(took, millis(() => decodeFirst(buf, REGISTER, "api.registerRequest")));
    expect(took).toBeLessThan(limit);
  });

  it.each(CASES)("%s: unmarshal", (_name, buf, limit) => {
    let took = Infinity;
    for (let run = 0; run < 3; run++) {
      took = Math.min(
        took,
        millis(() => {
          try {
            unmarshal(buf, REGISTERED, "spacetraders.rawRegisterResponse");
          } catch {
            // a body that is not an answer of that shape fails; what is measured is the way there
          }
        }),
      );
    }
    expect(took).toBeLessThan(limit);
  });

  it("an int field of a million digits is out of range without a BigInt of it", () => {
    const digits = body('{"data":{"agent":{"credits":', "9", "}}}");
    let error = "";
    const took = millis(() => {
      try {
        unmarshal(digits, REGISTERED, "spacetraders.rawRegisterResponse");
      } catch (err) {
        error = (err as Error).message;
      }
    });
    expect(error).toMatch(/^json: cannot unmarshal number 9+ into Go struct field /);
    expect(took).toBeLessThan(120);
  });

  it("keeps what the struct is for, wherever the body spreads", () => {
    const buf = Buffer.from(`{"x":[1,"s",{"accountToken":"inner"}],"AccountToken":"outer","y":{"symbol":"no"},"SYMBOL":"S","faction":null}`);
    expect(decodeFirst(buf, REGISTER, "api.registerRequest")).toEqual({ accountToken: "outer", symbol: "S", faction: "", email: "" });
  });
});
