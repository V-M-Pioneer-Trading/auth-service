// Everything cryptographic in the suite is generated per run. No key or secret
// in this repository is real, and none is ever printed.
import { createHmac, generateKeyPairSync, randomBytes, sign as nodeSign, verify as nodeVerify, constants } from "node:crypto";
import type { KeyObject } from "node:crypto";

export interface RsaKeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  privatePem: string;
  publicPem: string;
}

export function generateRsa(): RsaKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privateKey,
    publicKey,
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/** A random value shaped like a secret; unique per call, never reused across runs. */
export function randomSecret(label: string): string {
  return `${label}-${randomBytes(18).toString("hex")}`;
}

export function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export type Claims = Record<string, unknown>;

export interface SignOptions {
  key: KeyObject;
  alg?: "RS256" | "RS384" | "RS512" | "PS256";
  header?: Record<string, unknown>;
}

export function signJwt(claims: Claims, opts: SignOptions): string {
  const alg = opts.alg ?? "RS256";
  const header = { alg, typ: "JWT", ...opts.header };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const hash = alg.endsWith("384") ? "sha384" : alg.endsWith("512") ? "sha512" : "sha256";
  const signature =
    alg === "PS256"
      ? nodeSign(hash, Buffer.from(signingInput), {
          key: opts.key,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        })
      : nodeSign(hash, Buffer.from(signingInput), opts.key);
  return `${signingInput}.${b64url(signature)}`;
}

/** alg "none" token: header.payload. with an empty signature. */
export function unsignedJwt(claims: Claims): string {
  return `${b64url(JSON.stringify({ alg: "none", typ: "JWT" }))}.${b64url(JSON.stringify(claims))}.`;
}

/** The classic alg-confusion token: HS256 keyed with the RSA public key PEM. */
export function hs256Jwt(claims: Claims, secret: string): string {
  const signingInput = `${b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64url(JSON.stringify(claims))}`;
  return `${signingInput}.${b64url(createHmac("sha256", secret).update(signingInput).digest())}`;
}

/** Decode a JWT's payload without verifying it (the suite checks signatures separately). */
export function jwtPayload(token: string): Claims {
  const part = token.split(".")[1] ?? "";
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Claims;
}

export function jwtHeader(token: string): Claims {
  const part = token.split(".")[0] ?? "";
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Claims;
}

/** True when `token` is an RS256 JWT signed by the private half of `publicKey`. */
export function verifyRs256(token: string, publicKey: KeyObject): boolean {
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) return false;
  return nodeVerify("sha256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url"));
}
