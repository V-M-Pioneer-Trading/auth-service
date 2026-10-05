/**
 * The vault's Go-compatible readers held to the Go service's own answers, recorded by running its code on a corpus
 * (fixtures/SOURCE.txt, go-vault-recorder.go.txt): what the operator routes decode from a request body
 * (`json.NewDecoder(r.Body).Decode`), what is read out of SpaceTraders' answers (`json.Unmarshal`), and what a
 * SpaceTraders date is (`parseFlexibleTime`). A reader that drifts from Go changes what an operator's request does, or
 * whether a poll sees a wipe.
 */
import { decodeFirst, GoJsonError, MAX_NESTING_DEPTH, unmarshal, type Shape } from "../goJson";
import { formatRfc3339 } from "../goTime";
import { parseFlexibleTime } from "../spacetraders/client";
import verdicts from "./fixtures/go-vault-verdicts.json";

interface BodyVerdict {
  restore: string;
  register: string;
  root: string;
  registerResponse: string;
}

const hex = (s: string): string => Buffer.from(s, "utf8").toString("hex");

/** The verdict in the recorder's spelling: "error", or name=hex pairs. */
function verdictOf(read: () => Record<string, unknown>, names: readonly string[][]): string {
  let value: Record<string, unknown>;
  try {
    value = read();
  } catch (err) {
    if (err instanceof GoJsonError) return "error";
    throw err;
  }
  return names
    .map((path) => {
      let v: unknown = value;
      for (const p of path) v = (v as Record<string, unknown>)[p];
      return `${path[path.length - 1] ?? ""}=${hex(String(v))}`;
    })
    .join(" ");
}

const RESTORE: Shape = { agentToken: "string" };
const REGISTER: Shape = { accountToken: "string", symbol: "string", faction: "string", email: "string" };
const ROOT: Shape = { resetDate: "string", serverResets: { next: "string", frequency: "string" } };
const REGISTER_RESPONSE: Shape = { data: { token: "string", agent: { symbol: "string", credits: "int" } } };

describe("encoding/json as the vault uses it", () => {
  const cases = verdicts.bodies as unknown as [string, BodyVerdict][];

  it("has a corpus worth the name", () => {
    expect(cases.length).toBeGreaterThan(150);
  });

  it("decodes every recorded body as Go does, in each of the four places it is decoded", () => {
    const mismatches: string[] = [];
    for (const [input, go] of cases) {
      const body = Buffer.from(input, "hex");
      const mine: BodyVerdict = {
        restore: verdictOf(() => decodeFirst(body, RESTORE, "t"), [["agentToken"]]),
        register: verdictOf(() => decodeFirst(body, REGISTER, "t"), [["accountToken"], ["symbol"], ["faction"], ["email"]]),
        root: verdictOf(() => unmarshal(body, ROOT, "t"), [["resetDate"], ["serverResets", "next"], ["serverResets", "frequency"]]),
        registerResponse: verdictOf(() => unmarshal(body, REGISTER_RESPONSE, "t"), [["data", "token"], ["data", "agent", "symbol"], ["data", "agent", "credits"]]),
      };
      for (const key of ["restore", "register", "root", "registerResponse"] as const) {
        if (mine[key] !== go[key]) mismatches.push(`${key} of ${JSON.stringify(body.toString("latin1"))}: Go says ${go[key]}, this says ${mine[key]}`);
      }
    }
    expect(mismatches).toEqual([]);
  });

  // Go 1.22's own texts for these inputs, printed by the same types (wording is not pinned by the contract).
  const why = (s: string, shape: Shape = RESTORE, typeName = "api.restoreTokenRequest", read = decodeFirst): string => {
    try {
      read(Buffer.from(s, "latin1"), shape, typeName);
      return "ok";
    } catch (err) {
      return (err as Error).message;
    }
  };

  it.each([
    ["", "EOF"],
    ["{", "unexpected EOF"],
    ["not json", "invalid character 'o' in literal null (expecting 'u')"],
    ['{"agentToken":5}', "json: cannot unmarshal number into Go struct field restoreTokenRequest.agentToken of type string"],
    ['{"agentToken":true}', "json: cannot unmarshal bool into Go struct field restoreTokenRequest.agentToken of type string"],
    ['{"agentToken":{}}', "json: cannot unmarshal object into Go struct field restoreTokenRequest.agentToken of type string"],
    ["[]", "json: cannot unmarshal array into Go value of type api.restoreTokenRequest"],
    ['"s"', "json: cannot unmarshal string into Go value of type api.restoreTokenRequest"],
    ["42", "json: cannot unmarshal number into Go value of type api.restoreTokenRequest"],
    ["\xef\xbb\xbf{}", "invalid character 'ï' looking for beginning of value"],
    ["\x01", "invalid character '\\x01' looking for beginning of value"],
    ["\x7f", "invalid character '\\x7f' looking for beginning of value"],
    ["\x85", "invalid character '\\u0085' looking for beginning of value"],
    ["\xa0", "invalid character '\\u00a0' looking for beginning of value"],
    ["\xad", "invalid character '\\u00ad' looking for beginning of value"],
    ['{"a"\n}', "invalid character '}' after object key"],
  ])("says why as Go does: %j", (input, go) => {
    expect(why(input)).toBe(go);
  });

  it.each([
    ['{"data":{"agent":{"credits":1.5}}}', "json: cannot unmarshal number 1.5 into Go struct field .data.agent.credits of type int"],
    ['{"data":{"agent":{"credits":"1"}}}', "json: cannot unmarshal string into Go struct field .data.agent.credits of type int"],
    ['{"data":{"token":5}}', "json: cannot unmarshal number into Go struct field .data.token of type string"],
    ["[]", "json: cannot unmarshal array into Go value of type spacetraders.rawRegisterResponse"],
    ["x", "invalid character 'x' looking for beginning of value"],
  ])("says why as Go's Unmarshal does: %j", (input, go) => {
    expect(why(input, REGISTER_RESPONSE, "spacetraders.rawRegisterResponse", unmarshal)).toBe(go);
  });

  it("never repeats the body", () => {
    expect(why('{"agentToken":"secret-value" "x"}')).not.toContain("secret-value");
  });

  it("refuses nesting deeper than Go's 10000 levels with Go's error, iteratively (no stack overflow at any depth)", () => {
    const open = (n: number, c = "["): string => c.repeat(n);
    // 10000 levels are read (the value is then cut short, as Go's answer for the same bytes says); 10001 are refused.
    expect(why(open(10000))).toBe("unexpected EOF");
    expect(why(open(10001))).toBe("invalid character '[' exceeded max depth");
    expect(why(open(10000) + "]".repeat(10000), RESTORE, "api.restoreTokenRequest")).toBe("json: cannot unmarshal array into Go value of type api.restoreTokenRequest");
    expect(why(`{"agentToken":"deep","x":${open(9999)}${"]".repeat(9999)}}`)).toBe("ok");
    expect(why(`{"x":${open(10000)}${"]".repeat(10000)}}`)).toBe("invalid character '[' exceeded max depth");
    expect(why(open(9000, '{"a":'))).toBe("unexpected EOF");
    expect(why(open(2_000_000))).toBe("invalid character '[' exceeded max depth");
    expect(MAX_NESTING_DEPTH).toBe(10000);
  });
});

describe("parseFlexibleTime: SpaceTraders' resetDate and serverResets.next", () => {
  it("has the verdicts of Go on every recorded input, to the nanosecond", () => {
    const cases = verdicts.flexibleTimes as [string, string][];
    expect(cases.length).toBeGreaterThan(30);
    const mismatches: string[] = [];
    for (const [input, go] of cases) {
      const text = Buffer.from(input, "hex").toString("utf8");
      const t = parseFlexibleTime(text);
      const mine = t === null ? "zero" : `${formatRfc3339(t)} ${String(Math.floor(t.ms / 1000))} ${String(t.nanos)}`;
      if (mine !== go) mismatches.push(`${JSON.stringify(text)}: Go says ${go}, this says ${mine}`);
    }
    expect(mismatches).toEqual([]);
  });
});
