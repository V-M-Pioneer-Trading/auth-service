/**
 * The vault's Go-compatible readers held to the Go service's own answers, recorded by running its code on a corpus
 * (fixtures/SOURCE.txt, go-vault-recorder.go.txt): what the operator routes decode from a request body
 * (`json.NewDecoder(r.Body).Decode`), what is read out of SpaceTraders' answers (`json.Unmarshal`), and what a
 * SpaceTraders date is (`parseFlexibleTime`). A reader that drifts from Go changes what an operator's request does, or
 * whether a poll sees a wipe.
 */
import { decodeFirst, GoJsonError, unmarshal, type Shape } from "../goJson";
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

  it("says why, in the shape of Go's messages, without repeating the body", () => {
    const why = (s: string): string => {
      try {
        decodeFirst(Buffer.from(s, "latin1"), RESTORE, "api.restoreTokenRequest");
        return "ok";
      } catch (err) {
        return (err as Error).message;
      }
    };
    expect(why("")).toBe("EOF");
    expect(why("{")).toBe("unexpected EOF");
    expect(why("not json")).toBe("invalid character 'o' in literal null (expecting 'u')");
    expect(why('{"agentToken": 5}')).toBe("json: cannot unmarshal number into Go struct field api.restoreTokenRequest.agentToken of type string");
    expect(why('{"agentToken":"secret-value" "x"}')).not.toContain("secret-value");
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
