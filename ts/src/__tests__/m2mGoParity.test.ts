/**
 * The machine-token readers held to the Go service's own answers, recorded by running src/api/m2m.go's code on the
 * corpus of testSupport/m2mCases.ts (fixtures/SOURCE.txt says how): what a minted token is worth caching, what Clerk's
 * answer yields, and which proxy a mint goes through.
 */
import { createHash } from "node:crypto";

import { clerkAnswer, MAX_CLERK_ANSWER } from "../m2m/clerk";
import { goFoldName } from "../m2m/goJson";
import { proxyConfigFrom, proxyFor } from "../m2m/proxy";
import { cacheEntryFrom, MintFailed } from "../m2m/token";
import { parseClerkBaseUrl } from "../goUrl";
import { BODY_CASES, M2M_CASES_NOW_MS, PROXY_ENVS, PROXY_URLS, TOKEN_CASES } from "../testSupport/m2mCases";
import verdicts from "./fixtures/go-m2m-verdicts.json";

/** The recorder's input, byte for byte as go-m2m-recorder-input.mjs writes it. */
const recorderInput = JSON.stringify({
  nowMs: M2M_CASES_NOW_MS,
  tokens: TOKEN_CASES,
  bodies: BODY_CASES.map((s) => Buffer.from(s, "latin1").toString("base64")),
  envs: PROXY_ENVS,
  urls: PROXY_URLS,
});

it("the verdicts were recorded on exactly this corpus", () => {
  expect(createHash("sha256").update(recorderInput).digest("hex")).toBe(verdicts.inputSha256);
  expect(verdicts.tokens).toHaveLength(TOKEN_CASES.length);
  expect(verdicts.bodies).toHaveLength(BODY_CASES.length);
  expect(verdicts.proxies).toHaveLength(PROXY_ENVS.length);
});

describe("cacheEntryFrom: what a minted token is worth caching", () => {
  it("has the verdicts of Go on every recorded token", () => {
    expect(TOKEN_CASES.length).toBeGreaterThan(70);
    const mismatches: string[] = [];
    TOKEN_CASES.forEach((token, i) => {
      let mine: string;
      try {
        const entry = cacheEntryFrom(token, M2M_CASES_NOW_MS);
        mine = `ok ${String(entry.expiresAt)} ${String(entry.refreshAt)}`;
      } catch (err) {
        if (!(err instanceof MintFailed)) throw err;
        mine = "refused";
      }
      if (mine !== verdicts.tokens[i]) mismatches.push(`#${String(i)} ${token.slice(0, 120)}: Go says ${String(verdicts.tokens[i])}, this says ${mine}`);
    });
    expect(mismatches).toEqual([]);
  });
});

describe("Clerk's answer: json.NewDecoder(io.LimitReader(body, 64 KiB)).Decode", () => {
  const verdictOf = (body: Buffer): string => {
    const answer = clerkAnswer(body.subarray(0, MAX_CLERK_ANSWER), true);
    if (answer.kind !== "token") return "refused";
    const bytes = Buffer.from(answer.token, "utf8");
    return bytes.length <= 200 ? `token ${bytes.toString("base64")}` : `token sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  };

  it("has the verdicts of Go on every recorded body", () => {
    expect(BODY_CASES.length).toBeGreaterThan(50);
    const mismatches: string[] = [];
    BODY_CASES.forEach((body, i) => {
      const mine = verdictOf(Buffer.from(body, "latin1"));
      if (mine !== verdicts.bodies[i]) mismatches.push(`#${String(i)} ${JSON.stringify(body.slice(0, 80))}: Go says ${String(verdicts.bodies[i])}, this says ${mine}`);
    });
    expect(mismatches).toEqual([]);
  });

  it("decides as soon as the first value is complete, and waits while it is not", () => {
    expect(clerkAnswer(Buffer.from('{"token":"a.b.c"}'), false)).toEqual({ kind: "token", token: "a.b.c" });
    expect(clerkAnswer(Buffer.from('{"token":"a.b.c"'), false)).toEqual({ kind: "more" });
    expect(clerkAnswer(Buffer.from('{"token":"a.b.c"'), true).kind).toBe("failed");
    // A number is complete only when something follows it, or at the end.
    expect(clerkAnswer(Buffer.from("123"), false)).toEqual({ kind: "more" });
    expect(clerkAnswer(Buffer.from("123"), true).kind).toBe("failed");
  });

  it("folds field names as encoding/json does: the Kelvin sign is a K, the dotless i is not an I", () => {
    expect(goFoldName(`to${String.fromCodePoint(0x212a)}en`)).toBe("TOKEN");
    expect(goFoldName(`${String.fromCodePoint(0x17f)}ub`)).toBe("SUB");
    expect(goFoldName(`${String.fromCodePoint(0x131)}at`)).not.toBe("IAT");
  });
});

describe("ProxyFromEnvironment: which proxy a mint goes through", () => {
  it("has the verdicts of Go on every recorded environment and URL", () => {
    const mismatches: string[] = [];
    let compared = 0;
    PROXY_ENVS.forEach((env, i) => {
      const cfg = proxyConfigFrom(env);
      PROXY_URLS.forEach((url, j) => {
        const parsed = parseClerkBaseUrl(url);
        if (parsed === null) throw new Error(`not a mint URL: ${url}`);
        const decision = proxyFor(cfg, parsed.scheme, parsed.host);
        const mine =
          decision.kind === "direct"
            ? "direct"
            : decision.kind === "refused"
              ? "refused"
              : `proxy ${decision.proxy.scheme} ${decision.proxy.host} ${decision.proxy.username === undefined ? "-" : `u=${decision.proxy.username}`} ${decision.proxy.password === undefined ? "-" : `p=${decision.proxy.password}`}`;
        const go = verdicts.proxies[i]?.[j];
        compared++;
        if (mine !== go) mismatches.push(`${JSON.stringify(env)} ${url}: Go says ${String(go)}, this says ${mine}`);
      });
    });
    expect(compared).toBeGreaterThan(1000);
    expect(mismatches).toEqual([]);
  });
});
