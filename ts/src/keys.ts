/**
 * @file The two key readers the Go service got from golang-jwt v5.3.1 (`ParseRSAPublicKeyFromPEM` and
 * `ParseRSAPrivateKeyFromPEM`), reproduced on node:crypto.
 *
 * What matters is what they accept, because the contract suite pins the spellings and a startup refusal depends on
 * the rest:
 *
 *  - the PEM label is ignored: the first block that decodes is used, whatever it is called;
 *  - a public key is PKIX, else a certificate (its key), else PKCS#1, tried in that order on the DER bytes;
 *  - a private key is PKCS#1, else PKCS#8;
 *  - the key must be RSA (not RSA-PSS, not EC), and a private key is never a public key.
 *
 * Errors carry no key material, and no caller prints one.
 */
import { createPrivateKey, createPublicKey, X509Certificate, type KeyObject } from "node:crypto";

// At the start of a line, as pem.Decode requires.
const BEGIN = /(?<![^\n])-----BEGIN ([^\r\n]*?)-----[ \t]*\r?\n/g;

/** The DER bytes of the first PEM block that is well formed, as Go's pem.Decode finds it; null if there is none. */
export function firstPemBlock(text: string): Buffer | null {
  for (const begin of text.matchAll(BEGIN)) {
    const label = begin[1] ?? "";
    // Header lines ("Proc-Type: 4,ENCRYPTED"): any line with a colon, before the first one without. Go reads and ignores them.
    let bodyStart = begin.index + begin[0].length;
    for (;;) {
      const newline = text.indexOf("\n", bodyStart);
      const line = text.slice(bodyStart, newline < 0 ? text.length : newline);
      if (!line.includes(":") || newline < 0) break;
      bodyStart = newline + 1;
    }
    const marker = `-----END ${label}-----`;
    const end = text.indexOf(marker, bodyStart);
    if (end < 0) continue;
    // The rest of the END line must be whitespace.
    const lineEnd = text.indexOf("\n", end);
    if (!/^[ \t\r]*$/.test(text.slice(end + marker.length, lineEnd < 0 ? text.length : lineEnd))) continue;
    const body = text.slice(bodyStart, end).replace(/[ \t\r\n]/g, "");
    // Go's base64.StdEncoding: padded, no stray characters.
    if (body.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(body)) continue;
    return Buffer.from(body, "base64");
  }
  return null;
}

/** One DER element at `at`: its tag, the content bounds and where it ends; null if it does not fit (long lengths up to 4 bytes). */
function derElement(der: Buffer, at: number): { tag: number; start: number; end: number } | null {
  const tag = der[at];
  const first = der[at + 1];
  if (tag === undefined || first === undefined) return null;
  let length = first;
  let start = at + 2;
  if (first >= 0x80) {
    const count = first & 0x7f;
    if (count < 1 || count > 4) return null;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + (der[start + i] ?? 0);
    start += count;
  }
  const end = start + length;
  return end > der.length ? null : { tag, start, end };
}

/**
 * Go's ParsePKCS1PublicKey takes exactly `SEQUENCE { INTEGER n, INTEGER e }`. OpenSSL's reader is laxer and reads a
 * PKCS#1 *private* key as a public one, so the shape is checked first: a private key is never a public key.
 */
function isPkcs1PublicDer(der: Buffer): boolean {
  const seq = derElement(der, 0);
  if (seq?.tag !== 0x30 || seq.end !== der.length) return false;
  const n = derElement(der, seq.start);
  if (n?.tag !== 0x02) return false;
  const e = derElement(der, n.end);
  return e?.tag === 0x02 && e.end === seq.end;
}

/** golang-jwt's ParseRSAPublicKeyFromPEM; null when it would return an error. */
export function parseRsaPublicKey(pem: string): KeyObject | null {
  const der = firstPemBlock(pem);
  if (der === null) return null;
  let key: KeyObject | undefined;
  try {
    key = createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    try {
      key = new X509Certificate(der).publicKey;
    } catch {
      if (!isPkcs1PublicDer(der)) return null;
      try {
        key = createPublicKey({ key: der, format: "der", type: "pkcs1" });
      } catch {
        return null;
      }
    }
  }
  return key.asymmetricKeyType === "rsa" ? key : null;
}

/** golang-jwt's ParseRSAPrivateKeyFromPEM; null when it would return an error. */
export function parseRsaPrivateKey(pem: string): KeyObject | null {
  const der = firstPemBlock(pem);
  if (der === null) return null;
  let key: KeyObject | undefined;
  for (const type of ["pkcs1", "pkcs8"] as const) {
    try {
      key = createPrivateKey({ key: der, format: "der", type });
      break;
    } catch {
      // try the next encoding
    }
  }
  return key?.asymmetricKeyType === "rsa" ? key : null;
}

/** Whether a private key belongs to a public one (Go's `PublicKey.Equal`). */
export function samePublicKey(privateKey: KeyObject, publicKey: KeyObject): boolean {
  const spki = (k: KeyObject): Buffer => k.export({ type: "spki", format: "der" });
  return spki(createPublicKey(privateKey)).equals(spki(publicKey));
}
