/**
 * goMarshal: the bytes Go's json.Encoder writes for the answers of every route (token, status, register, restore,
 * errors, introspection, machine tokens all go through http/json.ts). Expected strings are Go 1.22's output for the
 * same values.
 */
import { goMarshal } from "../http/json";

const B = String.fromCharCode(0x5c);
const ch = (code: number): string => String.fromCharCode(code);

describe("goMarshal", () => {
  it("escapes <, > and & and the two line separators, inside keys and values, and nothing else", () => {
    expect(goMarshal({ agentToken: `<>&${ch(0x2028)}${ch(0x2029)}'"${ch(0x7f)}é` })).toBe(
      `{"agentToken":"${B}u003c${B}u003e${B}u0026${B}u2028${B}u2029'${B}"${ch(0x7f)}é"}`,
    );
    expect(goMarshal({ "a<b": 1 })).toBe(`{"a${B}u003cb":1}`);
    expect(goMarshal({ active: false })).toBe('{"active":false}');
  });

  it("writes a lone surrogate as U+FFFD's escape, as Go writes invalid UTF-8, and leaves an escaped backslash alone", () => {
    expect(goMarshal({ s: `${ch(0xd800)}x` })).toBe(`{"s":"${B}ufffdx"}`);
    expect(goMarshal({ s: `${B}ud800` })).toBe(`{"s":"${B}${B}ud800"}`);
    expect(goMarshal({ s: `${B}${ch(0xdc00)}` })).toBe(`{"s":"${B}${B}${B}ufffd"}`);
    expect(goMarshal({ s: "😀" })).toBe('{"s":"😀"}');
  });
});
