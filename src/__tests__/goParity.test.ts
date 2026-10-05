/**
 * The TypeScript readers held to the Go service's own answers, recorded by running its functions on a corpus
 * (fixtures/SOURCE.txt says how). A reader that drifts from Go changes what the service refuses to start with, or what
 * a stored date is called, so each table is the contract of one function.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { clerkTokensUrlFromEnv, ConfigError } from "../config";
import { formatRfc3339, isZeroTime, parseRfc3339 } from "../goTime";
import { goTrimSpace } from "../goText";
import { parseRsaPrivateKey, parseRsaPublicKey, samePublicKey } from "../keys";
import { parseMediaType, parseQuery } from "../http/goForm";
import { MEDIA_TYPE_CASES, QUERY_CASES } from "../testSupport/formCases";
import { keyCases } from "../testSupport/keyCases";
import verdicts from "./fixtures/go-verdicts.json";

describe("clerkURLFromEnv: CLERK_API_BASE_URL", () => {
  it("has the verdicts of Go on every recorded input", () => {
    expect(verdicts.urls.length).toBeGreaterThan(100);
    const mismatches: string[] = [];
    for (const [input, goVerdict] of verdicts.urls as [string, string][]) {
      let mine: string;
      try {
        const parsed = clerkTokensUrlFromEnv(input);
        mine = parsed === undefined ? "unset" : `ok ${parsed.scheme}://${parsed.host} -> ${parsed.url}`;
      } catch (err) {
        if (!(err instanceof ConfigError)) throw err;
        mine = "refused";
      }
      if (mine !== goVerdict) mismatches.push(`${JSON.stringify(input)}: Go says ${goVerdict}, this says ${mine}`);
    }
    expect(mismatches).toEqual([]);
  });

  it("never repeats the value in its refusal", () => {
    expect(() => clerkTokensUrlFromEnv("http://user:hunter2@stub.example")).toThrow(/^CLERK_API_BASE_URL must be/);
    try {
      clerkTokensUrlFromEnv("http://user:hunter2@stub.example");
    } catch (err) {
      expect(String(err)).not.toContain("hunter2");
    }
  });
});

describe("time.Parse(time.RFC3339) and Format: the credential row's dates", () => {
  it("has the verdicts of Go on every recorded input", () => {
    expect(verdicts.times.length).toBeGreaterThan(80);
    const mismatches: string[] = [];
    for (const [input, goVerdict] of verdicts.times as [string, string][]) {
      const parsed = parseRfc3339(input);
      const mine = parsed === null || isZeroTime(parsed) ? "zero" : `${formatRfc3339(parsed)} ${String(parsed.ms)}`;
      if (mine !== goVerdict) mismatches.push(`${JSON.stringify(input)}: Go says ${goVerdict}, this says ${mine}`);
    }
    expect(mismatches).toEqual([]);
  });

  it("keeps the offset a date arrived with and drops the fraction (the contract's note 29)", () => {
    const t = parseRfc3339("2026-09-28T14:00:00.987+02:00");
    expect(t === null ? "" : formatRfc3339(t)).toBe("2026-09-28T14:00:00+02:00");
  });
});

describe("strings.TrimSpace: the whitespace the M2M caller secrets are checked against", () => {
  it("strips exactly the code points Go strips", () => {
    const goSpaces = new Set(verdicts.spaces);
    const mismatches: string[] = [];
    for (let c = 0; c <= 0x3100; c++) {
      if (c >= 0xd800 && c <= 0xdfff) continue;
      const char = String.fromCodePoint(c);
      if ((goTrimSpace(char) === "") !== goSpaces.has(c)) mismatches.push(c.toString(16));
    }
    for (const c of [0xfeff, 0x180e, 0x200b, 0x2060, 0xe000, 0x10000, 0x1f600]) {
      if ((goTrimSpace(String.fromCodePoint(c)) === "") !== goSpaces.has(c)) mismatches.push(c.toString(16));
    }
    expect(mismatches).toEqual([]);
  });

  it("trims both ends and nothing inside", () => {
    expect(goTrimSpace(" \t a b 　\n")).toBe("a b");
    expect(goTrimSpace("﻿a")).toBe("﻿a");
    expect(goTrimSpace("\u0085a\u0085")).toBe("a");
  });
});

describe("golang-jwt's key readers: CLERK_JWT_KEY and DEV_M2M_SIGNING_KEY_FILE", () => {
  const cases = keyCases();

  it("has a recorded Go verdict for every case, and no stale one", () => {
    expect(Object.keys(verdicts.keys).sort()).toEqual(cases.map((c) => c.name).sort());
  });

  it.each(cases.map((c) => [c.name, c.pem] as const))("%s: public", (name, pem) => {
    const go = (verdicts.keys as Record<string, { public: string; private: string }>)[name];
    expect(parseRsaPublicKey(pem) === null ? "refused" : "ok").toBe(go?.public);
  });

  it.each(cases.map((c) => [c.name, c.pem] as const))("%s: private", (name, pem) => {
    const go = (verdicts.keys as Record<string, { public: string; private: string }>)[name];
    expect(parseRsaPrivateKey(pem) === null ? "refused" : "ok").toBe(go?.private);
  });

  it("reads the key the PEM holds, not a lookalike", () => {
    const pem = cases.find((c) => c.name === "rsa-spki")?.pem ?? "";
    const key = parseRsaPublicKey(pem);
    expect(key).not.toBeNull();
    expect(key?.asymmetricKeyType).toBe("rsa");
    expect(createPublicKey(pem).equals(key ?? createPublicKey(pem))).toBe(true);
  });

  it("tells whether a private key belongs to a public one", () => {
    const private1 = parseRsaPrivateKey(cases.find((c) => c.name === "rsa-pkcs8-private")?.pem ?? "");
    const public1 = parseRsaPublicKey(cases.find((c) => c.name === "rsa-spki")?.pem ?? "");
    const other = createPrivateKey(parseRsaPrivateKey(cases.find((c) => c.name === "rsa-512-pkcs8-private")?.pem ?? "")?.export({ type: "pkcs8", format: "pem" }) ?? "");
    expect(private1).not.toBeNull();
    expect(public1).not.toBeNull();
    // keyCases() makes one pair and writes it both ways.
    expect(private1 !== null && public1 !== null && samePublicKey(private1, public1)).toBe(true);
    expect(private1 !== null && samePublicKey(private1, createPublicKey(private1))).toBe(true);
    expect(private1 !== null && samePublicKey(other, createPublicKey(private1))).toBe(false);
  });
});

describe("mime.ParseMediaType: whether POST /auth/v1/introspect reads its body as a form, and whether it fails", () => {
  it("has the verdicts of Go on every recorded input, and a recorded verdict for every case", () => {
    const recorded = verdicts.mediaTypes as [string, { mediaType: string; failed: boolean }][];
    expect(recorded.map(([input]) => input)).toEqual([...MEDIA_TYPE_CASES]);
    const mismatches: string[] = [];
    for (const [input, go] of recorded) {
      const mine = parseMediaType(input);
      if (mine.mediaType !== go.mediaType || mine.failed !== go.failed) {
        mismatches.push(`${JSON.stringify(input)}: Go says ${JSON.stringify(go)}, this says ${JSON.stringify(mine)}`);
      }
    }
    expect(mismatches).toEqual([]);
  });
});

describe("url.ParseQuery: the form body and the URL query", () => {
  const hex = (s: string): string => Buffer.from(s, "latin1").toString("hex");

  it("has the verdicts of Go on every recorded input, and a recorded verdict for every case", () => {
    const recorded = verdicts.queries as [string, { values: string[][]; failed: boolean }][];
    expect(recorded.map(([input]) => input)).toEqual([...QUERY_CASES]);
    const mismatches: string[] = [];
    for (const [input, go] of recorded) {
      const parsed = parseQuery(input);
      // Go's sort.Strings orders by bytes; so does comparing the hex of latin1 strings.
      const values = [...parsed.values.entries()].map(([k, vs]) => [hex(k), ...vs.map(hex)]).sort((a, b) => ((a[0] ?? "") < (b[0] ?? "") ? -1 : 1));
      const mine = { values, failed: parsed.failed };
      if (JSON.stringify(mine) !== JSON.stringify(go)) mismatches.push(`${JSON.stringify(input)}: Go says ${JSON.stringify(go)}, this says ${JSON.stringify(mine)}`);
    }
    expect(mismatches).toEqual([]);
  });
});
