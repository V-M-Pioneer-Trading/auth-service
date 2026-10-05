/**
 * @file The inputs of the token-verification differential test (verifyToken.test.ts): one name per way a JWT can be
 * built, spelled or broken. What the Go service's own verifyToken (src/api/introspect.go, golang-jwt v5.3.1) answers
 * on each name is recorded in `__tests__/fixtures/go-verdicts.json` ("jwt"); the keys are generated per run, so no
 * private key and no signed token is committed. A verdict depends on the token's bytes and the clock, never on which
 * key signed it (every signature in a case is either made with the configured key or deliberately is not), so the
 * recorded answers hold for any key. Erasable TypeScript importing only node: modules, so a plain `node` can run it
 * to record the verdicts (fixtures/SOURCE.txt).
 *
 * `deviation` marks the cases where the TypeScript verifier is deliberately stricter than Go (decision 23 and the
 * notes in src/jwt/verify.ts): Go answers active, this service answers {"active":false}. Every other case must be
 * answered exactly as Go answers it.
 */
import { constants, createHmac, createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";

/** The clock every case is judged at: 2026-10-04T12:00:00.500Z, half a second past a whole second on purpose. */
export const JWT_CASES_NOW_MS = 1791115200500;
const N = 1791115200;
export const JWT_CASES_ISSUER = "https://clerk.corpus.example";

export type JwtCaseKey = "main" | "small" | "e3" | "big";

export interface JwtCase {
  readonly name: string;
  readonly token: string;
  /** The verification key (CLERK_JWT_KEY) this case is judged with. */
  readonly key: JwtCaseKey;
  /** CLERK_ISSUER for this case; "" is unset. */
  readonly issuer: string;
  /** Why this service answers {"active":false} where Go answers active. */
  readonly deviation?: string;
}

export interface JwtCaseKeys {
  readonly main: KeyObject;
  readonly foreign: KeyObject;
  readonly small: KeyObject;
  readonly e3: KeyObject;
  readonly big: KeyObject;
}

/** Private keys, generated per run. The public halves are what the verifier is configured with. */
export function jwtCaseKeys(): JwtCaseKeys {
  const rsa = (modulusLength: number, publicExponent = 65537): KeyObject =>
    generateKeyPairSync("rsa", { modulusLength, publicExponent }).privateKey;
  return { main: rsa(2048), foreign: rsa(2048), small: rsa(1024), e3: rsa(2048, 3), big: rsa(4096) };
}

const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");

type Alg = "RS256" | "RS384" | "RS512" | "PS256";

function signature(alg: Alg, input: string, key: KeyObject): Buffer {
  const data = Buffer.from(input, "latin1");
  const hash = alg === "RS384" ? "sha384" : alg === "RS512" ? "sha512" : "sha256";
  if (alg === "PS256") return sign(hash, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
  return sign(hash, data, key);
}

interface Build {
  /** Header object, or its JSON text, or its raw bytes. Default {alg:"RS256",typ:"JWT"}. */
  header?: Record<string, unknown> | string | Buffer;
  /** Payload object, or its JSON text, or its raw bytes. Default: a valid operator token. */
  payload?: Record<string, unknown> | string | Buffer;
  /** Segments used verbatim instead of encoding header / payload (they are still what is signed). */
  headerSeg?: string;
  payloadSeg?: string;
  alg?: Alg;
  key?: KeyObject;
  /** Applied to the finished token (after signing). */
  after?: (token: string) => string;
}

const json = (v: Record<string, unknown> | string | Buffer): Buffer => (Buffer.isBuffer(v) ? v : Buffer.from(typeof v === "string" ? v : JSON.stringify(v), "utf8"));

export const VALID_CLAIMS = { sub: "user_corpus", scope: "agent:reset", iat: N - 10, exp: N + 3600 } as const;

export function jwtCases(keys: JwtCaseKeys): JwtCase[] {
  const build = (b: Build = {}): string => {
    const h = b.headerSeg ?? b64u(json(b.header ?? { alg: b.alg ?? "RS256", typ: "JWT" }));
    const p = b.payloadSeg ?? b64u(json(b.payload ?? VALID_CLAIMS));
    const input = `${h}.${p}`;
    const token = `${input}.${b64u(signature(b.alg ?? "RS256", input, b.key ?? keys.main))}`;
    return b.after === undefined ? token : b.after(token);
  };
  const claims = (extra: Record<string, unknown>, drop: string[] = []): Record<string, unknown> => {
    const out: Record<string, unknown> = { ...VALID_CLAIMS, ...extra };
    return Object.fromEntries(Object.entries(out).filter(([k]) => !drop.includes(k)));
  };
  const withPayloadJson = (text: string): string => build({ payload: text });
  const cases: JwtCase[] = [];
  const add = (name: string, token: string, more: Partial<Omit<JwtCase, "name" | "token">> = {}): void => {
    cases.push({ name, token, key: more.key ?? "main", issuer: more.issuer ?? "", ...(more.deviation === undefined ? {} : { deviation: more.deviation }) });
  };

  // What verifies, and its answer.
  add("valid-operator", build());
  add("valid-machine", build({ payload: claims({ sub: "mch_corpus" }) }));
  for (const sub of ["user_", "user", "USER_x", " user_x", "usr_x", "x", "user_é", "mch_ "]) add(`kind-of-sub-${JSON.stringify(sub)}`, build({ payload: claims({ sub }) }));
  add("extra-claims-do-not-leak", build({ payload: claims({ email: "someone@example.com", azp: "https://app.example", sid: "sess_1", org_id: "org_1", nested: { a: [1, 2] } }) }));
  add("aud-iat-azp-typ-kid-unchecked", build({ header: { alg: "RS256", typ: "at+jwt", kid: "unrelated" }, payload: claims({ aud: ["someone-else"], azp: "x", iat: N + 7200 }) }));
  add("header-without-typ", build({ header: { alg: "RS256" } }));

  // scope: verbatim, joined, defaulted.
  for (const [label, scope] of [
    ["irregular-whitespace", "a  b\tc "],
    ["leading-space", " lead"],
    ["unicode", "ünï:cøde"],
    ["vertical-tab-and-nbsp", "a\u000bb c"],
    ["empty-string", ""],
    ["array", ["a:b", "c:d"]],
    ["empty-array", []],
    ["array-with-non-strings", ["a", 1, null, "b", { x: 1 }, true, ["c"]]],
    ["array-of-strings-with-spaces", ["a b", " c"]],
    ["null", null],
    ["number", 7],
    ["object", { a: 1 }],
    ["true", true],
  ] as const) {
    add(`scope-${label}`, build({ payload: claims({ scope }) }));
  }
  add("scope-absent", build({ payload: claims({}, ["scope"]) }));

  // Strings Go decodes differently from JSON.parse: a lone surrogate escape is U+FFFD in Go.
  add("sub-with-lone-surrogate-escape", withPayloadJson(`{"sub":"user_\\ud800x","scope":"s","exp":${String(N + 3600)}}`));
  add("sub-with-surrogate-pair-escape", withPayloadJson(`{"sub":"user_\\ud83d\\ude00","scope":"s","exp":${String(N + 3600)}}`));
  add("scope-with-lone-low-surrogate", withPayloadJson(`{"sub":"user_x","scope":"a\\udc00b","exp":${String(N + 3600)}}`));
  add("scope-array-with-lone-surrogate", withPayloadJson(`{"sub":"user_x","scope":["a","\\ud800"],"exp":${String(N + 3600)}}`));
  add("sub-with-escaped-key", withPayloadJson(`{"s\\u0075b":"user_escaped_key","exp":${String(N + 3600)}}`));
  add("payload-invalid-utf8-in-sub", build({ payload: Buffer.concat([Buffer.from(`{"sub":"user_`), Buffer.from([0xff, 0xfe]), Buffer.from(`","exp":${String(N + 3600)}}`)]) }), {
    deviation: "invalid UTF-8 in the claims: Go replaces it with U+FFFD, jose's strict decoder refuses the token",
  });

  // sub.
  add("sub-absent", build({ payload: claims({}, ["sub"]) }));
  for (const [label, sub] of [["empty", ""], ["number", 42], ["null", null], ["array", ["user_x"]], ["object", { id: "user_x" }], ["true", true]] as const) {
    add(`sub-${label}`, build({ payload: claims({ sub }) }));
  }

  // exp: required, numeric, 60 s leeway, truncated, and Go's int64 arithmetic at the edges.
  add("exp-absent", build({ payload: claims({}, ["exp"]) }));
  for (const [label, exp] of [
    ["zero", 0],
    ["null", null],
    ["string", String(N + 3600)],
    ["true", true],
    ["array", [N + 3600]],
    ["object", { t: N + 3600 }],
    ["negative", -5],
    ["minus-59-active", N - 59],
    ["minus-60-inactive", N - 60],
    ["minus-61", N - 61],
    ["minus-59.5-truncates-to-minus-60", N - 59.5],
    ["minus-58.1-truncates-to-minus-59", N - 58.1],
    ["minus-30", N - 30],
    ["minus-90", N - 90],
    ["fraction-far-future", N + 3600.9],
    ["tiny-positive", 5e-324],
    ["2^53", 2 ** 53],
    ["1e18", 1e18],
    ["2^62", 2 ** 62],
    ["2^63", 2 ** 63],
    ["1e19", 1e19],
    ["1e300", 1e300],
    ["-1e300", -1e300],
    ["-2^63", -(2 ** 63)],
  ] as const) {
    add(`exp-${label}`, build({ payload: claims({ exp }) }));
  }
  // Go: exp + 62135596800 (its internal epoch) wraps above MaxInt64 - 62135596800; Add(60 s) saturates.
  const wrapAt = 9223372036854775807n - 62135596800n;
  const below = nextDown(Number(wrapAt), wrapAt);
  add("exp-largest-double-before-go-wraps", build({ payload: claims({ exp: below }) }));
  add("exp-smallest-double-where-go-wraps", build({ payload: claims({ exp: nextUp(below) }) }));
  add("exp-written-1e400-overflows", withPayloadJson(`{"sub":"user_x","exp":1e400}`));
  add("exp-written-1e-400-is-zero", withPayloadJson(`{"sub":"user_x","exp":1e-400}`));
  add("exp-written-with-exponent", withPayloadJson(`{"sub":"user_x","exp":1.7911188e9}`));
  add("exp-written-negative-zero", withPayloadJson(`{"sub":"user_x","exp":-0}`));

  // nbf: optional, numeric, 60 s leeway.
  for (const [label, nbf, deviation] of [
    ["zero", 0, undefined],
    ["null", null, undefined],
    ["string", String(N), undefined],
    ["negative", -5, undefined],
    ["past", N - 3600, undefined],
    ["plus-30", N + 30, undefined],
    ["plus-59.5", N + 59.5, undefined],
    ["plus-60", N + 60, undefined],
    ["plus-60.5", N + 60.5, "a fractional nbf inside the last second of the leeway: Go truncates it to N+60 (valid), jose compares N+60.5 > N+60"],
    ["plus-61", N + 61, undefined],
    ["plus-120", N + 120, undefined],
    ["1e300", 1e300, "Go's int64 conversion of a huge nbf overflows to the distant past (valid); jose compares the number"],
  ] as const) {
    add(`nbf-${label}`, build({ payload: claims({ nbf }) }), deviation === undefined ? {} : { deviation });
  }
  add("nbf-written-1e400-overflows", withPayloadJson(`{"sub":"user_x","exp":${String(N + 3600)},"nbf":1e400}`));

  // iat: Go never reads it; jose type-checks it when present.
  add("iat-absent", build({ payload: claims({}, ["iat"]) }));
  add("iat-future", build({ payload: claims({ iat: N + 86400 }) }));
  add("iat-string", build({ payload: claims({ iat: "yesterday" }) }), { deviation: "a non-numeric iat: Go never reads iat, jose refuses a present iat that is not a number" });
  add("iat-null", build({ payload: claims({ iat: null }) }), { deviation: "a null iat: Go never reads iat, jose refuses a present iat that is not a number" });

  // iss, with CLERK_ISSUER unset and set.
  add("iss-anything-when-unset", build({ payload: claims({ iss: "https://anything.example" }) }));
  add("iss-number-when-unset", build({ payload: claims({ iss: 7 }) }));
  const issuer = JWT_CASES_ISSUER;
  for (const [label, iss] of [
    ["match", issuer],
    ["trailing-slash", `${issuer}/`],
    ["other", "https://evil.example"],
    ["empty", ""],
    ["case", issuer.toUpperCase()],
    ["null", null],
    ["number", 7],
    ["array-holding-it", [issuer]],
  ] as const) {
    add(`issuer-set-iss-${label}`, build({ payload: claims({ iss }) }), { issuer });
  }
  add("issuer-set-iss-absent", build(), { issuer });

  // The algorithm pin, and keys that are not the configured one.
  add("alg-none", `${b64u(JSON.stringify({ alg: "none", typ: "JWT" }))}.${b64u(JSON.stringify(VALID_CLAIMS))}.`);
  add("alg-HS256-keyed-with-the-public-pem", (() => {
    const input = `${b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64u(JSON.stringify(VALID_CLAIMS))}`;
    const pem = createPublicKey(keys.main).export({ type: "spki", format: "pem" }).toString();
    return `${input}.${b64u(createHmac("sha256", pem).update(input).digest())}`;
  })());
  add("alg-RS384", build({ alg: "RS384" }));
  add("alg-RS512", build({ alg: "RS512" }));
  add("alg-PS256", build({ alg: "PS256" }));
  add("alg-rs256-lowercase", build({ header: { alg: "rs256", typ: "JWT" } }));
  add("alg-with-trailing-space", build({ header: { alg: "RS256 ", typ: "JWT" } }));
  add("alg-absent", build({ header: { typ: "JWT" } }));
  add("alg-number", build({ header: { alg: 256, typ: "JWT" } }));
  add("alg-duplicate-last-is-none", build({ header: `{"alg":"RS256","alg":"none"}` }));
  add("alg-duplicate-last-is-RS256", build({ header: `{"alg":"none","alg":"RS256"}` }));
  add("foreign-key", build({ key: keys.foreign }));
  add("foreign-key-with-embedded-jwk", build({ key: keys.foreign, header: { alg: "RS256", jwk: createPublicJwk(keys.foreign) } }));
  add("foreign-key-with-jku", build({ key: keys.foreign, header: { alg: "RS256", jku: "https://evil.example/jwks.json", kid: "x" } }));
  add("foreign-key-with-x5u", build({ key: keys.foreign, header: { alg: "RS256", x5u: "https://evil.example/cert.pem" } }));
  add("own-key-with-embedded-foreign-jwk", build({ header: { alg: "RS256", jwk: createPublicJwk(keys.foreign) } }));
  add("small-key-1024-bit", build({ key: keys.small }), { key: "small", deviation: "an RSA key under 2048 bits: Go verifies with it, jose refuses it for RS256 (decision 23)" });
  add("key-with-exponent-3", build({ key: keys.e3 }), { key: "e3" });
  add("key-4096-bit", build({ key: keys.big }), { key: "big" });
  add("signed-with-main-judged-with-small", build(), { key: "small" });

  // crit (decision 23: rejected here, accepted by Go), b64.
  add("crit-unknown-extension", build({ header: { alg: "RS256", crit: ["exp"], exp: 1 } }), { deviation: "crit names an extension jose does not recognise (decision 23)" });
  add("crit-unknown-absent-parameter", build({ header: { alg: "RS256", crit: ["x-custom"] } }), { deviation: "crit names an extension jose does not recognise (decision 23)" });
  add("crit-empty-array", build({ header: { alg: "RS256", crit: [] } }), { deviation: "crit is not a non-empty array of names (decision 23)" });
  add("crit-a-string", build({ header: { alg: "RS256", crit: "b64" } }), { deviation: "crit is not a non-empty array of names (decision 23)" });
  add("crit-b64-true", build({ header: { alg: "RS256", crit: ["b64"], b64: true } }));
  add("crit-b64-false", build({ header: { alg: "RS256", crit: ["b64"], b64: false } }), { deviation: "an unencoded payload (crit b64:false) is refused for a JWT by jose; Go ignores b64 (decision 23)" });
  add("b64-false-without-crit", build({ header: { alg: "RS256", b64: false } }));

  // Header and payload JSON: what Go's encoding/json refuses and JSON.parse would take.
  add("header-with-bom", build({ header: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`{"alg":"RS256"}`)]) }));
  add("payload-with-bom", build({ payload: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), json(VALID_CLAIMS)]) }));
  add("header-with-overflowing-number", build({ header: `{"alg":"RS256","x":1e400}` }));
  add("payload-with-overflowing-number-in-another-claim", withPayloadJson(`{"sub":"user_x","exp":${String(N + 3600)},"x":[1,{"y":-2e308}]}`));
  add("payload-with-largest-double", withPayloadJson(`{"sub":"user_x","exp":${String(N + 3600)},"x":1.7976931348623157e308}`));
  add("payload-with-just-past-largest-double", withPayloadJson(`{"sub":"user_x","exp":${String(N + 3600)},"x":1.7976931348623159e308}`));
  add("payload-with-underflowing-number", withPayloadJson(`{"sub":"user_x","exp":${String(N + 3600)},"x":1e-400}`));
  add("header-not-json", build({ header: "not json" }));
  add("header-json-array", build({ header: `["RS256"]` }));
  add("header-json-null", build({ header: "null" }));
  add("header-empty", build({ headerSeg: "" }));
  add("header-trailing-garbage", build({ header: `{"alg":"RS256"}x` }));
  add("payload-not-json", build({ payload: "not json" }));
  add("payload-json-array", build({ payload: "[1]" }));
  add("payload-json-null", build({ payload: "null" }));
  add("payload-json-string", build({ payload: `"user_x"` }));
  add("payload-empty", build({ payloadSeg: "" }));
  add("payload-trailing-garbage", withPayloadJson(`${JSON.stringify(VALID_CLAIMS)}x`));
  add("payload-surrounding-whitespace", withPayloadJson(` \n${JSON.stringify(VALID_CLAIMS)}\t\r\n`));
  add("payload-duplicate-sub-last-wins", withPayloadJson(`{"sub":"user_first","sub":"mch_last","exp":${String(N + 3600)}}`));
  add("payload-duplicate-exp-last-wins-expired", withPayloadJson(`{"sub":"user_x","exp":${String(N + 3600)},"exp":${String(N - 3600)}}`));
  add("payload-proto-key", withPayloadJson(`{"__proto__":{"sub":"user_proto"},"exp":${String(N + 3600)}}`));
  add("payload-sub-under-proto-and-own", withPayloadJson(`{"__proto__":{"x":1},"sub":"user_own","exp":${String(N + 3600)}}`));
  add("payload-deeply-nested", withPayloadJson(`{"sub":"user_x","exp":${String(N + 3600)},"d":${"[".repeat(400)}${"]".repeat(400)}}`));
  add("payload-control-character-in-string", withPayloadJson(`{"sub":"user_\u0001","exp":${String(N + 3600)}}`));

  // Base64url as Go's RawURLEncoding reads it: no padding, no other alphabet, \r and \n skipped, other whitespace not.
  const validHeaderSeg = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const validPayloadSeg = b64u(JSON.stringify(VALID_CLAIMS));
  const padded = (seg: string): string => seg + "=".repeat((4 - (seg.length % 4)) % 4);
  /** The encoding of the first of make(""), make("x"), make("xx") whose length is not a multiple of 4 (so it has padding to add). */
  const partial = (make: (filler: string) => Record<string, unknown>): string => {
    for (let filler = ""; ; filler += "x") {
      const seg = b64u(JSON.stringify(make(filler)));
      if (seg.length % 4 !== 0) return seg;
    }
  };
  add("payload-segment-padded", build({ payloadSeg: padded(partial((pad) => ({ ...VALID_CLAIMS, pad }))) }));
  add("header-segment-padded", build({ headerSeg: padded(partial((p) => ({ alg: "RS256", p }))) }));
  add("payload-segment-standard-alphabet", build({ payloadSeg: Buffer.from(JSON.stringify({ ...VALID_CLAIMS, s: "ûÿþ>>>???" })).toString("base64").replace(/=+$/, "") }));
  add("payload-segment-with-newline", build({ payloadSeg: `${validPayloadSeg.slice(0, 8)}\n${validPayloadSeg.slice(8)}` }));
  add("payload-segment-with-crlf", build({ payloadSeg: `${validPayloadSeg.slice(0, 8)}\r\n${validPayloadSeg.slice(8)}` }));
  add("header-segment-with-trailing-newline", build({ headerSeg: `${validHeaderSeg}\n` }));
  add("payload-segment-with-space", build({ payloadSeg: `${validPayloadSeg.slice(0, 8)} ${validPayloadSeg.slice(8)}` }));
  add("payload-segment-with-tab", build({ payloadSeg: `${validPayloadSeg.slice(0, 8)}\t${validPayloadSeg.slice(8)}` }));
  add("payload-segment-with-form-feed", build({ payloadSeg: `${validPayloadSeg.slice(0, 8)}\f${validPayloadSeg.slice(8)}` }));
  add("payload-segment-length-1-mod-4", build({ payloadSeg: `${(() => {
    let seg = validPayloadSeg;
    while (seg.length % 4 !== 0) seg = b64u(JSON.stringify({ ...VALID_CLAIMS, f: "y".repeat(seg.length) }));
    return seg;
  })()}A` }));
  add("payload-segment-nonzero-trailing-bits", build({ payloadSeg: nonCanonical(partial((t) => ({ ...VALID_CLAIMS, t }))) }));
  add("payload-segment-non-ascii", build({ payloadSeg: `${validPayloadSeg}é` }));

  // The signature segment.
  add("signature-one-byte-short", build({ after: (t) => withSig(t, (s) => s.subarray(1)) }));
  add("signature-with-a-leading-zero-byte", build({ after: (t) => withSig(t, (s) => Buffer.concat([Buffer.from([0]), s])) }));
  add("signature-empty", build({ after: (t) => t.slice(0, t.lastIndexOf(".") + 1) }));
  add("signature-padded", build({ after: (t) => padded(t) }));
  add("signature-with-newline", build({ after: (t) => `${t.slice(0, -4)}\n${t.slice(-4)}` }));
  add("signature-standard-alphabet", build({ after: (t) => withSigText(t, (s) => s.toString("base64").replace(/=+$/, "")) }));
  add("signature-of-another-payload", build({ after: (t) => {
    const [h, , s] = t.split(".");
    return `${h ?? ""}.${b64u(JSON.stringify({ ...VALID_CLAIMS, sub: "user_admin" }))}.${s ?? ""}`;
  } }));

  // Segments.
  add("empty-token", "");
  add("one-segment", "abc");
  add("two-segments", build({ after: (t) => t.slice(0, t.lastIndexOf(".")) }));
  add("four-segments", build({ after: (t) => `${t}.x` }));
  add("trailing-dot", build({ after: (t) => `${t}.` }));
  add("leading-space", build({ after: (t) => ` ${t}` }));
  add("trailing-space", build({ after: (t) => `${t} ` }));
  add("trailing-newline", build({ after: (t) => `${t}\n` }));
  add("only-dots", "..");

  return cases;
}

function createPublicJwk(privateKey: KeyObject): Record<string, unknown> {
  return createPublicKey(privateKey).export({ format: "jwk" });
}

/** A segment whose last character carries non-zero unused bits: the same bytes for a lenient decoder. */
function nonCanonical(seg: string): string {
  if (seg.length % 4 === 0) throw new Error("needs a partial last group");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(seg.slice(-1));
  return seg.slice(0, -1) + (alphabet[last | 1] ?? "");
}

function withSig(token: string, f: (sig: Buffer) => Buffer): string {
  const at = token.lastIndexOf(".");
  return `${token.slice(0, at)}.${b64u(f(Buffer.from(token.slice(at + 1), "base64url")))}`;
}

function withSigText(token: string, f: (sig: Buffer) => string): string {
  const at = token.lastIndexOf(".");
  return `${token.slice(0, at)}.${f(Buffer.from(token.slice(at + 1), "base64url"))}`;
}

/** The largest double not above `limit` (a double near it, `approx`). */
function nextDown(approx: number, limit: bigint): number {
  let d = approx;
  while (BigInt(d) > limit) d = stepDouble(d, -1);
  while (BigInt(stepDouble(d, 1)) <= limit) d = stepDouble(d, 1);
  return d;
}

function nextUp(d: number): number {
  return stepDouble(d, 1);
}

function stepDouble(d: number, dir: 1 | -1): number {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, d);
  view.setBigUint64(0, view.getBigUint64(0) + BigInt(dir));
  return view.getFloat64(0);
}
