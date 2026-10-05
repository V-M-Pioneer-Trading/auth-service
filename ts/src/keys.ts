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
    // The END line starts a line (Go looks for "\n-----END ", or finds it at once after an empty body) and, like Go,
    // the FIRST one decides: one with another label ends this block's chance, however many follow.
    const marker = `-----END ${label}-----`;
    const end = text.startsWith("-----END ", bodyStart) ? bodyStart : text.indexOf("\n-----END ", bodyStart) + 1;
    if (end < 1 || !text.startsWith(marker, end)) continue;
    // The rest of the END line must be empty as Go's getLine reads it: up to the first \n, one \r dropped only when it
    // is right before that \n, then trailing spaces and tabs trimmed. A \r anywhere else is not whitespace.
    const lineEnd = text.indexOf("\n", end);
    let restOfLine = text.slice(end + marker.length, lineEnd < 0 ? text.length : lineEnd);
    if (lineEnd >= 0 && restOfLine.endsWith("\r")) restOfLine = restOfLine.slice(0, -1);
    if (!/^[ \t]*$/.test(restOfLine)) continue;
    const body = text.slice(bodyStart, end).replace(/[ \t\r\n]/g, "");
    // Go's base64.StdEncoding: padded, no stray characters.
    if (body.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(body)) continue;
    return Buffer.from(body, "base64");
  }
  return null;
}

interface DerElement {
  /** Where the element (its tag) starts. */
  readonly at: number;
  readonly tag: number;
  readonly start: number;
  readonly end: number;
}

/**
 * One DER element at `at`: its tag, the content bounds and where it ends; null if it does not fit, or if it is not
 * DER the way Go's parsers (encoding/asn1, cryptobyte) require: a single-byte tag, a definite length (BER's
 * indefinite 0x80 is refused), and the minimal length encoding (the short form below 128, no leading zero byte in
 * the long form). Long lengths up to 4 bytes. OpenSSL takes all of these, so they are refused here, before it.
 */
function derElement(der: Buffer, at: number): DerElement | null {
  const tag = der[at];
  const first = der[at + 1];
  if (tag === undefined || first === undefined || (tag & 0x1f) === 0x1f) return null;
  let length = first;
  let start = at + 2;
  if (first >= 0x80) {
    const count = first & 0x7f;
    if (count < 1 || count > 4 || der[start] === 0) return null;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + (der[start + i] ?? 0);
    if (length < 0x80) return null;
    start += count;
  }
  const end = start + length;
  return end > der.length ? null : { at, tag, start, end };
}

/** The elements between `start` and `end`, which they must fill exactly; null if they do not. */
function derElements(der: Buffer, start: number, end: number): DerElement[] | null {
  const out: DerElement[] = [];
  for (let at = start; at < end; ) {
    const e = derElement(der, at);
    if (e === null || e.end > end) return null;
    out.push(e);
    at = e.end;
  }
  return out;
}

/** Every element from `start` to `end` is DER, and so is everything inside each constructed one, all the way down. */
function isStrictDer(der: Buffer, start = 0, end = der.length): boolean {
  const elements = derElements(der, start, end);
  return elements?.every((e) => (e.tag & 0x20) === 0 || isStrictDer(der, e.start, e.end)) ?? false;
}

/**
 * A SubjectPublicKeyInfo's key, which sits inside a BIT STRING (a primitive, so isStrictDer does not open it): Go
 * parses it as DER too. `at` is where the SubjectPublicKeyInfo starts.
 */
function isStrictSpkiKey(der: Buffer, at: number): boolean {
  const spki = derElement(der, at);
  const parts = spki === null ? null : derElements(der, spki.start, spki.end);
  const bits = parts?.[1];
  if (bits?.tag !== 0x03 || der[bits.start] !== 0) return false;
  return isStrictDer(der, bits.start + 1, bits.end);
}

/** Where a certificate's SubjectPublicKeyInfo starts: TBSCertificate's sixth field, seventh with the [0] version. */
function certificateSpkiAt(der: Buffer): number | null {
  const cert = derElement(der, 0);
  const tbs = cert === null ? null : derElement(der, cert.start);
  const fields = tbs === null ? null : derElements(der, tbs.start, tbs.end);
  return fields?.[fields[0]?.tag === 0xa0 ? 6 : 5]?.at ?? null;
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

/**
 * Go's x509 parsers refuse bytes after the structure (all but ParsePKCS8PrivateKey); OpenSSL's reader ignores them.
 * Every key here is one outer SEQUENCE, so it must span the whole DER.
 */
function isOneSequence(der: Buffer): boolean {
  const seq = derElement(der, 0);
  return seq?.tag === 0x30 && seq.end === der.length;
}

/** golang-jwt's ParseRSAPublicKeyFromPEM; null when it would return an error. */
export function parseRsaPublicKey(pem: string): KeyObject | null {
  const der = firstPemBlock(pem);
  if (der === null || !isOneSequence(der) || !isStrictDer(der)) return null;
  let key: KeyObject | undefined;
  try {
    key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (!isStrictSpkiKey(der, 0)) return null;
  } catch {
    try {
      key = new X509Certificate(der).publicKey;
      const spkiAt = certificateSpkiAt(der);
      if (spkiAt === null || !isStrictSpkiKey(der, spkiAt)) return null;
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
  // Both of Go's readers take DER only; what follows the key is another matter (below).
  const first = derElement(der, 0);
  if (first === null || !isStrictDer(der, 0, first.end)) return null;
  for (const type of ["pkcs1", "pkcs8"] as const) {
    // Go: ParsePKCS1PrivateKey refuses bytes after the key, ParsePKCS8PrivateKey does not (recorded: go-verdicts.json).
    if (type === "pkcs1" && !isOneSequence(der)) continue;
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
