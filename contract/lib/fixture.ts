// The vendored introspection fixture (src/api/testdata/introspection.json) is a
// verbatim copy of meta's. Its sha256 is pinned in SOURCE.txt beside it.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const FIXTURE_DIR = join(here, "..", "..", "src", "api", "testdata");

export interface FixtureCase {
  name: string;
  request: { authorization: string | string[] | null };
  center: { notCalled?: boolean; status?: number; body?: string; delayMs?: number; transport?: string };
}

export interface Fixture {
  version: number;
  contract: {
    endpoint: { method: string; path: string; contentType: string; bodyTemplate: string; secretHeader: string };
    env: { url: string; secret: string };
  };
  cases: FixtureCase[];
  gatewayCases: FixtureCase[];
}

export function fixtureBytes(): Buffer {
  return readFileSync(join(FIXTURE_DIR, "introspection.json"));
}

export function loadFixture(): Fixture {
  return JSON.parse(fixtureBytes().toString("utf8")) as Fixture;
}

export function fixtureSha256(): string {
  return createHash("sha256").update(fixtureBytes()).digest("hex");
}

/** The `sha256:` line of SOURCE.txt. */
export function recordedSha256(): string {
  const source = readFileSync(join(FIXTURE_DIR, "SOURCE.txt"), "utf8");
  for (const line of source.split(/\r?\n/)) {
    const m = /^\s*sha256:\s*([0-9a-f]{64})\s*$/.exec(line);
    if (m) return m[1] as string;
  }
  throw new Error("SOURCE.txt has no `sha256:` line");
}

/**
 * The raw members of a top-level JSON object in order, repeats included, which
 * JSON.parse would silently collapse to the last one.
 */
export function topLevelMembers(body: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  let i = 0;
  const ws = () => {
    while (i < body.length && /\s/.test(body[i] as string)) i++;
  };
  const readString = (): string => {
    const start = i;
    i++; // opening quote
    while (body[i] !== '"') {
      if (body[i] === "\\") i++;
      i++;
    }
    i++;
    return body.slice(start, i);
  };
  ws();
  if (body[i] !== "{") throw new Error(`not a JSON object: ${body}`);
  i++;
  ws();
  while (body[i] !== "}") {
    ws();
    const key = JSON.parse(readString()) as string;
    ws();
    if (body[i] !== ":") throw new Error("expected ':'");
    i++;
    ws();
    const start = i;
    let depth = 0;
    while (i < body.length) {
      const c = body[i] as string;
      if (c === '"') {
        readString();
        continue;
      }
      if (c === "{" || c === "[") depth++;
      if (c === "}" || c === "]") {
        if (depth === 0) break;
        depth--;
      }
      if (c === "," && depth === 0) break;
      i++;
    }
    out.push([key, body.slice(start, i).trim()]);
    if (body[i] === ",") i++;
    ws();
  }
  return out;
}

export function firstOccurrenceTwin(body: string): Record<string, unknown> {
  const seen = new Set<string>();
  const doc: Record<string, unknown> = {};
  for (const [k, raw] of topLevelMembers(body)) {
    if (seen.has(k)) continue;
    seen.add(k);
    doc[k] = JSON.parse(raw);
  }
  return doc;
}

export function hasDuplicateKey(body: string): string | undefined {
  const seen = new Set<string>();
  for (const [k] of topLevelMembers(body)) {
    if (seen.has(k)) return k;
    seen.add(k);
  }
  return undefined;
}
