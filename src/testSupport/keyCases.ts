/**
 * @file The inputs of the key-reading differential test (keys.test.ts): one name per way a PEM can be spelled or
 * broken. The verdicts of the Go service's golang-jwt readers on each name are recorded in
 * `__tests__/fixtures/go-verdicts.json`; the keys are generated per run, so no private key is committed (the
 * certificates are public data). Erasable TypeScript only, so a plain `node` can run it to record the verdicts.
 */
import { generateKeyPairSync } from "node:crypto";

export const CERT_RSA_PEM = `-----BEGIN CERTIFICATE-----
MIIC0TCCAbkCFHZt/jYPgeB/6AAeSrUw50EX2IIQMA0GCSqGSIb3DQEBCwUAMCQx
IjAgBgNVBAMMGWF1dGgtc2VydmljZS10ZXN0LWZpeHR1cmUwIBcNMjYxMDA0MjEz
NDEyWhgPMjEyNjA5MTAyMTM0MTJaMCQxIjAgBgNVBAMMGWF1dGgtc2VydmljZS10
ZXN0LWZpeHR1cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNbZXd
a+VxbJFxQnUmWWIjn2UFldO3abgzd6ULXlh9fCbctfFpq9KACDAUoGVidrSLGYle
wh8uG6e2RNskcCstxWmYr9M6/Ox7ZTkmUTYehFOIBThWW9AmKAJxoKC7kP5VikhD
RcFJd4f8lo3BQtWW8baizdFHE4gDQ7V6/GPidaNb7Wqcei++emQd5v4ZIJ8V+zaf
cTkeLmaH2Aqlfk76AICag7u/ouv8EowtgxzlLwgi6UVoxfRHz4+VlZaQ0rBObHa9
IEq7PoXK/ch8Y6hOXszhnli/En0tYDkyUs5UQRgDmAataDcuAyELES94d/ncMAvf
jwiSu5sCfLpERaDhAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEODzgeaGZ6x1Lmx
ABG55OLg90l7KEPKTMF5Y1sKXaLsmXizHqUa7tPJseKUd1ILqVnGRoPDanHlY2Tu
67lS0BZcQjDf5T0W7FrzYmtsP4HHucpmUcSROkrAHKf0/Pn/4X1MvHSX8qWfLaZw
YJLIHHIR+JnMgvucuwNqezhS2oMUJrrPv5QnJUa9E47uk03VtU53EOmTwP/te9lh
SxuqzgxugyGD9685cC1g0lkRqx9pBVE7wUznfroiZHo5FzC4ifT4+kTxdPm1cnoo
1X15dcEajIK0DBYQ501ZXADQ4qeVjBLxBuzJvs0t8eRZXEgxcBCEDQM7oMzVEceN
v43S/GY=
-----END CERTIFICATE-----
`;

export const CERT_EC_PEM = `-----BEGIN CERTIFICATE-----
MIIBQzCB6wIULS6s1z3Cja2f+QA/ZxSMhMWc6vYwCgYIKoZIzj0EAwIwJDEiMCAG
A1UEAwwZYXV0aC1zZXJ2aWNlLXRlc3QtZml4dHVyZTAgFw0yNjEwMDQyMTM0MTJa
GA8yMTI2MDkxMDIxMzQxMlowJDEiMCAGA1UEAwwZYXV0aC1zZXJ2aWNlLXRlc3Qt
Zml4dHVyZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDpkDLgQkpq2Syb3zrD+
BuHYpKsMZo1X7Y1oK3+5fEXFcv6+FWJn61RErz68ucsVhNxV3eyl68AaBgTmV0DQ
iRkwCgYIKoZIzj0EAwIDRwAwRAIge4QByaJCHYL3QRUIaOZuc5rhO4u5Bxm+HOdo
oWmlpYMCIGxrQSTN65ntgm1CTt8RuftIbrHFTN19AMz8nyvfbTCS
-----END CERTIFICATE-----
`;

export interface KeyCase {
  readonly name: string;
  readonly pem: string;
}

/** A DER length: minimal, or one byte longer than it needs to be (long form for a short length, a leading zero byte). */
function derLength(n: number, minimal = true): Buffer {
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  if (minimal) return n < 0x80 ? Buffer.from([n]) : Buffer.from([0x80 | bytes.length, ...bytes]);
  return n < 0x80 ? Buffer.from([0x81, n]) : Buffer.from([0x80 | (bytes.length + 1), 0, ...bytes]);
}

function derElementOf(tag: number, content: Buffer, minimal = true): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length, minimal), content]);
}

/** BER's indefinite length (0x80, the content, then 00 00), which DER forbids. */
function indefinite(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag, 0x80]), content, Buffer.from([0, 0])]);
}

/** The elements directly inside a constructed element that is itself DER (as every generated key is). */
function derChildren(der: Buffer): { tag: number; content: Buffer }[] {
  const at = (i: number): { tag: number; start: number; end: number } => {
    const first = der[i + 1] ?? 0;
    const count = first & 0x80 ? first & 0x7f : 0;
    let length = first & 0x80 ? 0 : first;
    for (let k = 0; k < count; k++) length = length * 256 + (der[i + 2 + k] ?? 0);
    const start = i + 2 + count;
    return { tag: der[i] ?? 0, start, end: start + length };
  };
  const outer = at(0);
  const out: { tag: number; content: Buffer }[] = [];
  for (let i = outer.start; i < outer.end; ) {
    const e = at(i);
    out.push({ tag: e.tag, content: der.subarray(e.start, e.end) });
    i = e.end;
  }
  return out;
}

/** The content octets of a DER element, rebuilt from its children. */
const contentOf = (der: Buffer): Buffer => Buffer.concat(derChildren(der).map((c) => derElementOf(c.tag, c.content)));

function armor(label: string, der: Buffer, eol = "\n"): string {
  const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----${eol}${lines.join(eol)}${eol}-----END ${label}-----${eol}`;
}

export function keyCases(): KeyCase[] {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaPublicSpki = rsa.publicKey.export({ type: "spki", format: "der" });
  const rsaPublicPkcs1 = rsa.publicKey.export({ type: "pkcs1", format: "der" });
  const rsaPrivatePkcs8 = rsa.privateKey.export({ type: "pkcs8", format: "der" });
  const rsaPrivatePkcs1 = rsa.privateKey.export({ type: "pkcs1", format: "der" });
  const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const ed = generateKeyPairSync("ed25519");
  const pss = generateKeyPairSync("rsa-pss", { modulusLength: 2048 });
  const small = generateKeyPairSync("rsa", { modulusLength: 512 });
  const e3 = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 3 });
  const good = armor("PUBLIC KEY", rsaPublicSpki);
  const goodBody = rsaPublicSpki.toString("base64");
  const [algId, bitString] = derChildren(rsaPublicSpki);
  const [modulus, exponent] = derChildren(rsaPublicPkcs1);
  if (algId === undefined || bitString === undefined || modulus === undefined || exponent === undefined) throw new Error("unexpected key shape");
  const spki = (...parts: Buffer[]): Buffer => derElementOf(0x30, Buffer.concat(parts));
  const algIdDer = derElementOf(0x30, algId.content);
  const bitStringDer = derElementOf(0x03, bitString.content);
  const endLine = (ending: string): string => good.replace("-----END PUBLIC KEY-----\n", `-----END PUBLIC KEY-----${ending}`);

  return [
    { name: "rsa-spki", pem: good },
    { name: "rsa-pkcs1-public", pem: armor("RSA PUBLIC KEY", rsaPublicPkcs1) },
    { name: "rsa-pkcs8-private", pem: armor("PRIVATE KEY", rsaPrivatePkcs8) },
    { name: "rsa-pkcs1-private", pem: armor("RSA PRIVATE KEY", rsaPrivatePkcs1) },
    { name: "ec-spki", pem: armor("PUBLIC KEY", ec.publicKey.export({ type: "spki", format: "der" })) },
    { name: "ec-pkcs8-private", pem: armor("PRIVATE KEY", ec.privateKey.export({ type: "pkcs8", format: "der" })) },
    { name: "ed25519-spki", pem: armor("PUBLIC KEY", ed.publicKey.export({ type: "spki", format: "der" })) },
    { name: "ed25519-pkcs8-private", pem: armor("PRIVATE KEY", ed.privateKey.export({ type: "pkcs8", format: "der" })) },
    { name: "rsa-pss-spki", pem: armor("PUBLIC KEY", pss.publicKey.export({ type: "spki", format: "der" })) },
    { name: "rsa-pss-pkcs8-private", pem: armor("PRIVATE KEY", pss.privateKey.export({ type: "pkcs8", format: "der" })) },
    { name: "rsa-512-spki", pem: armor("PUBLIC KEY", small.publicKey.export({ type: "spki", format: "der" })) },
    { name: "rsa-512-pkcs8-private", pem: armor("PRIVATE KEY", small.privateKey.export({ type: "pkcs8", format: "der" })) },
    { name: "rsa-e3-spki", pem: armor("PUBLIC KEY", e3.publicKey.export({ type: "spki", format: "der" })) },
    { name: "certificate-rsa", pem: CERT_RSA_PEM },
    { name: "certificate-ec", pem: CERT_EC_PEM },
    // The label is not read: the bytes decide.
    { name: "pkcs1-public-under-PUBLIC-KEY", pem: armor("PUBLIC KEY", rsaPublicPkcs1) },
    { name: "spki-under-RSA-PUBLIC-KEY", pem: armor("RSA PUBLIC KEY", rsaPublicSpki) },
    { name: "spki-under-CERTIFICATE", pem: armor("CERTIFICATE", rsaPublicSpki) },
    { name: "spki-under-a-made-up-label", pem: armor("WHATEVER", rsaPublicSpki) },
    { name: "pkcs8-private-under-PUBLIC-KEY", pem: armor("PUBLIC KEY", rsaPrivatePkcs8) },
    { name: "pkcs1-private-under-RSA-PUBLIC-KEY", pem: armor("RSA PUBLIC KEY", rsaPrivatePkcs1) },
    { name: "pkcs1-private-under-PUBLIC-KEY", pem: armor("PUBLIC KEY", rsaPrivatePkcs1) },
    { name: "pkcs1-public-under-PRIVATE-KEY", pem: armor("PRIVATE KEY", rsaPublicPkcs1) },
    { name: "pkcs8-private-under-RSA-PRIVATE-KEY", pem: armor("RSA PRIVATE KEY", rsaPrivatePkcs8) },
    { name: "pkcs1-private-under-PRIVATE-KEY", pem: armor("PRIVATE KEY", rsaPrivatePkcs1) },
    // What surrounds the block.
    { name: "leading-text", pem: `this is not part of the key\n${good}` },
    { name: "trailing-text", pem: `${good}and some text after it\n` },
    { name: "crlf-line-endings", pem: armor("PUBLIC KEY", rsaPublicSpki, "\r\n") },
    { name: "indented-begin", pem: ` ${good}` },
    { name: "begin-not-at-line-start", pem: `text ${good}` },
    { name: "no-trailing-newline", pem: good.trimEnd() },
    { name: "blank-lines-around", pem: `\n\n${good}\n\n` },
    { name: "spaces-and-tabs-in-body", pem: good.replace(/\n(?=[A-Za-z0-9+/])/g, "\n  \t") },
    { name: "one-long-line-body", pem: `-----BEGIN PUBLIC KEY-----\n${goodBody}\n-----END PUBLIC KEY-----\n` },
    { name: "body-on-the-begin-line", pem: `-----BEGIN PUBLIC KEY-----${goodBody}\n-----END PUBLIC KEY-----\n` },
    { name: "trailing-spaces-after-end", pem: good.replace("-----END PUBLIC KEY-----", "-----END PUBLIC KEY-----   ") },
    { name: "text-after-end-on-its-line", pem: good.replace("-----END PUBLIC KEY-----", "-----END PUBLIC KEY----- x") },
    // Broken blocks.
    { name: "garbage", pem: "this is not a PEM" },
    { name: "empty", pem: "" },
    { name: "whitespace-only", pem: "  \n\t\n" },
    { name: "empty-body", pem: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n" },
    { name: "bad-base64-character", pem: good.replace(/[A-Z]/, "!") },
    { name: "unpadded-base64", pem: armor("PUBLIC KEY", rsaPublicSpki.subarray(0, rsaPublicSpki.length - 1)).replace(/=+\n/, "\n") },
    { name: "truncated-der", pem: armor("PUBLIC KEY", rsaPublicSpki.subarray(0, 100)) },
    { name: "missing-end", pem: good.replace("-----END PUBLIC KEY-----\n", "") },
    { name: "mismatched-end-label", pem: good.replace("-----END PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----") },
    { name: "proc-type-header", pem: good.replace("-----BEGIN PUBLIC KEY-----\n", "-----BEGIN PUBLIC KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n") },
    { name: "garbage-block-then-the-key", pem: `-----BEGIN JUNK-----\n!!!!\n-----END JUNK-----\n${good}` },
    { name: "valid-ec-block-then-the-rsa-key", pem: `${armor("PUBLIC KEY", ec.publicKey.export({ type: "spki", format: "der" }))}${good}` },
    { name: "two-keys", pem: `${good}${armor("PUBLIC KEY", small.publicKey.export({ type: "spki", format: "der" }))}` },
    { name: "private-then-public", pem: `${armor("PRIVATE KEY", rsaPrivatePkcs8)}${good}` },
    // Bytes after the structure: Go's x509 parsers refuse them, OpenSSL's ignore them.
    { name: "spki-trailing-zero-byte", pem: armor("PUBLIC KEY", Buffer.concat([rsaPublicSpki, Buffer.from([0])])) },
    { name: "pkcs1-public-trailing-zero-byte", pem: armor("RSA PUBLIC KEY", Buffer.concat([rsaPublicPkcs1, Buffer.from([0])])) },
    { name: "pkcs8-private-trailing-zero-byte", pem: armor("PRIVATE KEY", Buffer.concat([rsaPrivatePkcs8, Buffer.from([0])])) },
    { name: "pkcs1-private-trailing-zero-byte", pem: armor("RSA PRIVATE KEY", Buffer.concat([rsaPrivatePkcs1, Buffer.from([0])])) },
    { name: "spki-trailing-garbage", pem: armor("PUBLIC KEY", Buffer.concat([rsaPublicSpki, Buffer.from("garbage")])) },
    // The END line must start a line, and the first END decides.
    { name: "end-marker-on-the-body-line", pem: `-----BEGIN PUBLIC KEY-----\n${goodBody}-----END PUBLIC KEY-----\n` },
    { name: "end-marker-indented", pem: good.replace("-----END", " -----END") },
    { name: "wrong-end-label-then-the-right-one", pem: good.replace("-----END PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----\n-----END PUBLIC KEY-----") },
    { name: "literal-backslash-n-one-line", pem: good.trim().replaceAll("\n", "\\n") },
    // The END line as Go's getLine reads it: one \r is dropped only right before the \n, then trailing spaces and tabs.
    { name: "end-line-cr-at-end-of-input", pem: `${good.trimEnd()}\r` },
    { name: "end-line-two-crs", pem: endLine("\r\r\n") },
    { name: "end-line-cr-then-space", pem: endLine("\r \n") },
    { name: "end-line-cr-then-tab", pem: endLine("\r\t\n") },
    { name: "end-line-space-then-crlf", pem: endLine(" \r\n") },
    { name: "end-line-tab-then-crlf", pem: endLine("\t\r\n") },
    { name: "end-line-spaces-at-end-of-input", pem: `${good.trimEnd()} \t ` },
    // DER lengths: Go's parsers take the minimal encoding only, and BER's indefinite length is not DER.
    { name: "spki-outer-length-not-minimal", pem: armor("PUBLIC KEY", derElementOf(0x30, contentOf(rsaPublicSpki), false)) },
    {
      name: "spki-outer-length-in-five-bytes",
      pem: armor("PUBLIC KEY", Buffer.concat([Buffer.from([0x30, 0x85, 0, 0, 0]), derLength(contentOf(rsaPublicSpki).length).subarray(1), contentOf(rsaPublicSpki)])),
    },
    { name: "spki-algorithm-length-not-minimal", pem: armor("PUBLIC KEY", spki(derElementOf(0x30, algId.content, false), bitStringDer)) },
    { name: "spki-bit-string-length-not-minimal", pem: armor("PUBLIC KEY", spki(algIdDer, derElementOf(0x03, bitString.content, false))) },
    {
      name: "spki-inner-key-length-not-minimal",
      pem: armor("PUBLIC KEY", spki(algIdDer, derElementOf(0x03, Buffer.concat([Buffer.from([0]), derElementOf(0x30, contentOf(rsaPublicPkcs1), false)])))),
    },
    { name: "spki-indefinite-length", pem: armor("PUBLIC KEY", indefinite(0x30, contentOf(rsaPublicSpki))) },
    { name: "pkcs1-public-outer-length-not-minimal", pem: armor("RSA PUBLIC KEY", derElementOf(0x30, contentOf(rsaPublicPkcs1), false)) },
    {
      name: "pkcs1-public-exponent-length-not-minimal",
      pem: armor("RSA PUBLIC KEY", derElementOf(0x30, Buffer.concat([derElementOf(0x02, modulus.content), derElementOf(0x02, exponent.content, false)]))),
    },
    { name: "pkcs1-public-indefinite-length", pem: armor("RSA PUBLIC KEY", indefinite(0x30, contentOf(rsaPublicPkcs1))) },
    { name: "pkcs8-private-outer-length-not-minimal", pem: armor("PRIVATE KEY", derElementOf(0x30, contentOf(rsaPrivatePkcs8), false)) },
    { name: "pkcs8-private-indefinite-length", pem: armor("PRIVATE KEY", indefinite(0x30, contentOf(rsaPrivatePkcs8))) },
    { name: "pkcs1-private-outer-length-not-minimal", pem: armor("RSA PRIVATE KEY", derElementOf(0x30, contentOf(rsaPrivatePkcs1), false)) },
    { name: "pkcs1-private-indefinite-length", pem: armor("RSA PRIVATE KEY", indefinite(0x30, contentOf(rsaPrivatePkcs1))) },
  ];
}
