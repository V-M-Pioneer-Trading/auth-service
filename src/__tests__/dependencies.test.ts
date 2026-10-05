import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

interface Entry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  devOptional?: boolean;
  optional?: boolean;
  hasInstallScript?: boolean;
  os?: string[];
  cpu?: string[];
  link?: boolean;
}
interface Pkg {
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  [key: string]: unknown;
}
interface Lock {
  lockfileVersion: number;
  packages: Record<string, Entry>;
}
interface Checker {
  check: (pkg: Pkg, lock: Lock, allow: string, snapshot: string, opts?: { npmrc?: boolean }) => string[];
  computeSnapshot: (lock: Lock) => Map<string, string>;
  renderSnapshot: (snapshot: Map<string, string>) => string;
  KNOWN_ALIASES: Record<string, unknown>;
}

const { check, computeSnapshot, renderSnapshot, KNOWN_ALIASES } = createRequire(__filename)("../../scripts/check-dependencies.cjs") as Checker;

const root = path.join(__dirname, "..", "..");
const read = (f: string): string => fs.readFileSync(path.join(root, f), "utf8");
const allow = read("allowed-dependencies.txt");
// A Windows checkout with autocrlf has CRLF; the checker reads both, the tests below split on LF.
const snapshot = read("dependency-snapshot.txt").replaceAll("\r\n", "\n");
const fresh = (): { pkg: Pkg; lock: Lock } => ({ pkg: JSON.parse(read("package.json")) as Pkg, lock: JSON.parse(read("package-lock.json")) as Lock });
const entry = (lock: Lock, where: string): Entry => {
  const found = lock.packages[where];
  if (found === undefined) throw new Error(`the lockfile has no ${where}`);
  return found;
};
const problems = (pkg: Pkg, lock: Lock, opts?: { npmrc?: boolean }, snap = snapshot): string => check(pkg, lock, allow, snap, opts).join("\n");

const ESLINT_CONFIG = "@v-m-pioneer-trading/eslint-config";

describe("the direct-dependency check", () => {
  it("passes on the repository as committed", () => {
    const { pkg, lock } = fresh();
    expect(check(pkg, lock, allow, snapshot)).toEqual([]);
  });

  it("refuses an npm: alias spec for an allowed name", () => {
    const { pkg, lock } = fresh();
    pkg.devDependencies.supertest = "npm:evil-pkg@1.0.0";
    expect(problems(pkg, lock)).toMatch(/supertest: "npm:evil-pkg@1.0.0" is not a plain semver range/);
  });

  it.each(["github:attacker/jest", "git+https://example.test/jest.git", "file:../jest", "https://example.test/jest.tgz", "latest", "*"])("refuses the spec %s", (spec) => {
    const { pkg, lock } = fresh();
    pkg.devDependencies.jest = spec;
    expect(problems(pkg, lock)).toMatch(/jest: ".*" is not a plain semver range/);
  });

  it("refuses a dev dependency moved into dependencies (it would ship in the image)", () => {
    const { pkg, lock } = fresh();
    pkg.dependencies.typescript = pkg.devDependencies.typescript ?? "";
    delete pkg.devDependencies.typescript;
    expect(problems(pkg, lock)).toMatch(/typescript is in dependencies but not in the \[dependencies\] section/);
  });

  it("refuses a name that is not on the allowlist, and an allowlisted name that is gone", () => {
    const { pkg, lock } = fresh();
    pkg.dependencies.leftpad = "^1.0.0";
    delete pkg.dependencies.express;
    const out = problems(pkg, lock);
    expect(out).toMatch(/leftpad is in dependencies but not in the/);
    expect(out).toMatch(/express is on the \[dependencies\] allowlist but is not in dependencies/);
  });

  it("refuses clerk-client: auth-service is the verifier, not a client of itself", () => {
    const { pkg, lock } = fresh();
    pkg.dependencies["@v-m-pioneer-trading/clerk-client"] = "^2.0.0";
    expect(problems(pkg, lock)).toMatch(/clerk-client is in dependencies but not in the/);
  });

  it("refuses express 5", () => {
    const { pkg, lock } = fresh();
    pkg.dependencies.express = "^5.0.0";
    expect(problems(pkg, lock)).toMatch(/express must stay on major version 4/);
  });

  it("refuses overrides and resolutions, which rewrite what a name resolves to", () => {
    for (const key of ["overrides", "resolutions"]) {
      const { pkg, lock } = fresh();
      pkg[key] = { "body-parser": "npm:left-pad@1.3.0" };
      expect(problems(pkg, lock)).toContain(`package.json has ${key}`);
    }
  });

  it("refuses an .npmrc", () => {
    const { pkg, lock } = fresh();
    expect(problems(pkg, lock, { npmrc: true })).toMatch(/\.npmrc exists/);
    expect(check(pkg, lock, allow, snapshot, { npmrc: false })).toEqual([]);
  });

  it.each([true, ["express"], { express: "^4" }, "express"])("refuses bundleDependencies / bundledDependencies in any truthy form: %j", (form) => {
    for (const key of ["bundleDependencies", "bundledDependencies"]) {
      const { pkg, lock } = fresh();
      pkg[key] = form;
      expect(problems(pkg, lock)).toContain(`package.json has ${key}`);
    }
  });

  it("refuses optionalDependencies and peerDependencies", () => {
    for (const key of ["optionalDependencies", "peerDependencies"]) {
      const { pkg, lock } = fresh();
      pkg[key] = { fsevents: "^2.0.0" };
      expect(problems(pkg, lock)).toContain(`package.json has ${key}`);
    }
  });

  it("refuses a lockfile that is not version 3", () => {
    const { pkg, lock } = fresh();
    lock.lockfileVersion = 2;
    expect(problems(pkg, lock)).toMatch(/lockfileVersion 2/);
  });
});

describe("where the lockfile resolves from", () => {
  it("refuses an entry resolved from anywhere but the registry or the admitted release", () => {
    const { pkg, lock } = fresh();
    entry(lock, "node_modules/supertest").resolved = "https://evil.example.test/supertest-6.3.4.tgz";
    expect(problems(pkg, lock)).toMatch(/node_modules\/supertest resolves from https:\/\/evil\.example\.test/);
  });

  it("refuses an entry installed under another name (what an override writes)", () => {
    const { pkg, lock } = fresh();
    const body = entry(lock, "node_modules/body-parser");
    body.name = "left-pad";
    body.resolved = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    expect(problems(pkg, lock)).toMatch(/node_modules\/body-parser is installed as "left-pad" under another name/);
  });

  it("refuses a resolved URL of another package even when the name field is absent", () => {
    const { pkg, lock } = fresh();
    entry(lock, "node_modules/body-parser").resolved = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    expect(problems(pkg, lock)).toMatch(/node_modules\/body-parser is "body-parser@[0-9.]+" but resolves from .*left-pad/);
  });

  it("pins the five aliases by path, name and version", () => {
    const a = fresh();
    for (const where of Object.keys(KNOWN_ALIASES)) expect(a.lock.packages[where]).toBeDefined();
    entry(a.lock, "node_modules/strip-ansi-cjs").name = "left-pad";
    expect(problems(a.pkg, a.lock)).toMatch(/strip-ansi-cjs is installed as "left-pad"/);

    const b = fresh();
    b.lock.packages["node_modules/evil-alias"] = { ...entry(b.lock, "node_modules/strip-ansi-cjs") };
    expect(problems(b.pkg, b.lock)).toMatch(/node_modules\/evil-alias is installed as "strip-ansi" under another name/);

    const c = fresh();
    entry(c.lock, "node_modules/wrap-ansi-cjs").version = "9.9.9";
    expect(problems(c.pkg, c.lock)).toMatch(/wrap-ansi-cjs is installed as "wrap-ansi" under another name/);
  });

  it.each([undefined, "sha1-abc=", "sha256-abc=", "md5-abc"])("requires a sha512 integrity on every resolved entry: %s", (integrity) => {
    const { pkg, lock } = fresh();
    const express = entry(lock, "node_modules/express");
    if (integrity === undefined) delete express.integrity;
    else express.integrity = integrity;
    expect(problems(pkg, lock)).toMatch(/node_modules\/express has no sha512 integrity/);
  });
});

describe("the eslint-config release tarball (devDependencies only)", () => {
  const good = "https://github.com/V-M-Pioneer-Trading/eslint-config/releases/download/v1.0.0/v-m-pioneer-trading-eslint-config-1.0.0.tgz";

  it("is what package.json and the lockfile hold", () => {
    const { pkg, lock } = fresh();
    expect(pkg.devDependencies[ESLINT_CONFIG]).toBe(good);
    expect(entry(lock, `node_modules/${ESLINT_CONFIG}`).resolved).toBe(good);
  });

  it.each([
    ["another repository", "https://github.com/attacker/eslint-config/releases/download/v1.0.0/v-m-pioneer-trading-eslint-config-1.0.0.tgz"],
    ["another host", "https://example.test/V-M-Pioneer-Trading/eslint-config/releases/download/v1.0.0/v-m-pioneer-trading-eslint-config-1.0.0.tgz"],
    ["a tag that is not the file's version", "https://github.com/V-M-Pioneer-Trading/eslint-config/releases/download/v1.0.0/v-m-pioneer-trading-eslint-config-9.9.9.tgz"],
    ["another file", "https://github.com/V-M-Pioneer-Trading/eslint-config/releases/download/v1.0.0/evil.tgz"],
    ["a git spec", "github:V-M-Pioneer-Trading/eslint-config"],
    ["a plain range", "^1.0.0"],
  ])("refuses %s", (_name, spec) => {
    const { pkg, lock } = fresh();
    pkg.devDependencies[ESLINT_CONFIG] = spec;
    expect(problems(pkg, lock)).toMatch(/must be its GitHub release tarball URL/);
  });

  it("refuses it in dependencies, where it would ship", () => {
    const { pkg, lock } = fresh();
    pkg.dependencies[ESLINT_CONFIG] = good;
    expect(problems(pkg, lock)).toMatch(/eslint-config is in dependencies but not in the \[dependencies\] section/);
    expect(problems(pkg, lock)).toMatch(/must be its GitHub release tarball URL/);
  });

  it("refuses a lockfile entry for it resolved from anywhere else, or at a nested path", () => {
    const a = fresh();
    entry(a.lock, `node_modules/${ESLINT_CONFIG}`).resolved = "https://github.com/attacker/eslint-config/releases/download/v1.0.0/v-m-pioneer-trading-eslint-config-1.0.0.tgz";
    expect(problems(a.pkg, a.lock)).toMatch(/must resolve from the @v-m-pioneer-trading\/eslint-config release tarball package\.json names, not https:\/\/github\.com\/attacker/);

    const b = fresh();
    b.lock.packages["node_modules/foo/node_modules/@v-m-pioneer-trading/eslint-config"] = { ...entry(b.lock, `node_modules/${ESLINT_CONFIG}`) };
    expect(problems(b.pkg, b.lock)).toMatch(/not at the top level/);
  });

  it("is not admitted for any other package name", () => {
    const { pkg, lock } = fresh();
    entry(lock, "node_modules/supertest").resolved = good;
    expect(problems(pkg, lock)).toMatch(/node_modules\/supertest resolves from a GitHub release asset/);
  });

  // npm ci downloads package.json's URL when it differs from the lockfile's `resolved`, and then does not check the
  // lockfile's integrity: a lockfile-only edit to another tag of the same repository would void the pin.
  const other = "https://github.com/V-M-Pioneer-Trading/eslint-config/releases/download/v1.0.1/v-m-pioneer-trading-eslint-config-1.0.1.tgz";

  it("refuses a lockfile resolved that is another release of the same repository than package.json names", () => {
    const a = fresh();
    entry(a.lock, `node_modules/${ESLINT_CONFIG}`).resolved = other;
    expect(problems(a.pkg, a.lock)).toMatch(/resolves from .*v1\.0\.1.*which is not the URL package\.json's devDependencies names/);

    // Even when the version field is moved along with it.
    const b = fresh();
    Object.assign(entry(b.lock, `node_modules/${ESLINT_CONFIG}`), { resolved: other, version: "1.0.1" });
    expect(problems(b.pkg, b.lock)).toMatch(/which is not the URL package\.json's devDependencies names/);
  });

  it("refuses package.json moved to another release while the lockfile stays on the old one", () => {
    const { pkg, lock } = fresh();
    pkg.devDependencies[ESLINT_CONFIG] = other;
    expect(problems(pkg, lock)).toMatch(/which is not the URL package\.json's devDependencies names/);
  });

  it("refuses a lockfile version that is not the release's version", () => {
    const { pkg, lock } = fresh();
    entry(lock, `node_modules/${ESLINT_CONFIG}`).version = "1.0.1";
    expect(problems(pkg, lock)).toMatch(/is version "1\.0\.1" but resolves from the v1\.0\.0 release tarball/);
  });

  it("refuses its top-level entry resolved from the registry instead of the release package.json names", () => {
    const { pkg, lock } = fresh();
    entry(lock, `node_modules/${ESLINT_CONFIG}`).resolved = "https://registry.npmjs.org/@v-m-pioneer-trading/eslint-config/-/eslint-config-1.0.0.tgz";
    expect(problems(pkg, lock)).toMatch(/must resolve from the @v-m-pioneer-trading\/eslint-config release tarball package\.json names/);
  });

  it("refuses any other GitHub release asset, for any entry", () => {
    const { pkg, lock } = fresh();
    entry(lock, "node_modules/express").resolved = "https://github.com/V-M-Pioneer-Trading/clerk-client/releases/download/v2.0.0/clerk-client-2.0.0.tgz";
    expect(problems(pkg, lock)).toMatch(/node_modules\/express resolves from a GitHub release asset/);
  });
});

describe("the transitive snapshot", () => {
  it("is exactly what the lockfile computes to, byte for byte (so `npm run snapshot:deps` is a no-op)", () => {
    const { lock } = fresh();
    expect(renderSnapshot(computeSnapshot(lock))).toBe(snapshot.replace(/\r\n/g, "\n"));
  });

  it("separates runtime from dev: what express brings is runtime, what jest brings is dev", () => {
    const text = snapshot;
    const runtime = text.slice(text.indexOf("\n[runtime]\n"), text.indexOf("\n[dev]\n"));
    expect(runtime).toMatch(/^express@4\./m);
    expect(runtime).toMatch(/^@tsoa\/runtime@6\./m);
    expect(runtime).not.toMatch(/^jest@/m);
    expect(text.slice(text.indexOf("\n[dev]\n"))).toMatch(/^jest@30\./m);
  });

  it("fails when the lockfile gains a package that is not in the snapshot (the gate the acceptance criteria ask to see fail)", () => {
    const { pkg, lock } = fresh();
    lock.packages["node_modules/left-pad"] = {
      version: "1.3.0",
      resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      integrity: "sha512-" + "A".repeat(86) + "==",
    };
    const out = problems(pkg, lock);
    expect(out).toMatch(/package-lock\.json gained left-pad@1\.3\.0 \[runtime\], which is not in dependency-snapshot\.txt/);
  });

  it("fails for a new dev package too, and for one nested under another (a second copy of a name)", () => {
    const { pkg, lock } = fresh();
    lock.packages["node_modules/jest/node_modules/left-pad"] = {
      version: "1.3.0",
      dev: true,
      resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      integrity: "sha512-" + "A".repeat(86) + "==",
    };
    expect(problems(pkg, lock)).toMatch(/gained left-pad@1\.3\.0 \[dev\]/);
  });

  it("fails when a package changes version, naming both the one gained and the one gone", () => {
    const { pkg, lock } = fresh();
    const accepts = entry(lock, "node_modules/accepts");
    const old = accepts.version ?? "";
    accepts.version = "9.9.9";
    accepts.resolved = "https://registry.npmjs.org/accepts/-/accepts-9.9.9.tgz";
    const out = problems(pkg, lock);
    expect(out).toContain("gained accepts@9.9.9 [runtime]");
    expect(out).toContain(`lists accepts@${old} [runtime], which package-lock.json no longer has`);
  });

  it("fails when a package keeps its version and changes its bytes", () => {
    const { pkg, lock } = fresh();
    entry(lock, "node_modules/accepts").integrity = "sha512-" + "B".repeat(86) + "==";
    expect(problems(pkg, lock)).toMatch(/accepts@[0-9.]+ \[runtime\] has a different integrity/);
  });

  it("fails when a dev package becomes a runtime one (it would ship)", () => {
    const { pkg, lock } = fresh();
    delete entry(lock, "node_modules/supertest").dev;
    expect(problems(pkg, lock)).toMatch(/gained supertest@[0-9.]+ \[runtime\]/);
  });

  it("fails when the snapshot lists a package the lockfile dropped", () => {
    const { pkg, lock } = fresh();
    delete lock.packages["node_modules/accepts"];
    expect(problems(pkg, lock)).toMatch(/dependency-snapshot\.txt lists accepts@[0-9.]+ \[runtime\], which package-lock\.json no longer has/);
  });

  it("fails on a snapshot that is hand-edited into something unreadable, or lists a name twice", () => {
    const { pkg, lock } = fresh();
    expect(problems(pkg, lock, undefined, snapshot + "\nleft-pad\n")).toMatch(/is not "name@version integrity"/);
    expect(problems(pkg, lock, undefined, "left-pad@1.0.0 sha512-x\n")).toMatch(/outside a \[runtime\] \/ \[dev\] section/);
    const twice = snapshot.replace("\n[dev]\n", "\n[runtime]\nexpress@4.0.0 sha512-x\nexpress@4.0.0 sha512-x\n[dev]\n");
    expect(problems(pkg, lock, undefined, twice)).toMatch(/is listed twice/);
  });

  it("passes when a snapshot is the same set in another order", () => {
    const { pkg, lock } = fresh();
    const lines = snapshot.split("\n");
    const start = lines.indexOf("[runtime]") + 1;
    const end = lines.indexOf("[dev]");
    const reordered = [...lines.slice(0, start), ...lines.slice(start, end).reverse(), ...lines.slice(end)].join("\n");
    expect(check(pkg, lock, allow, reordered)).toEqual([]);
  });
});

describe("what the runtime tree may not hold", () => {
  it.each([
    ["an install script", { hasInstallScript: true }, /runtime package node_modules\/accepts has an install script/],
    ["a platform-specific binary (os)", { os: ["linux"] }, /node_modules\/accepts is platform-specific/],
    ["a platform-specific binary (cpu)", { cpu: ["arm64"] }, /node_modules\/accepts is platform-specific/],
    ["an optional package", { optional: true }, /node_modules\/accepts is optional/],
  ])("refuses %s", (_name, extra, message) => {
    const { pkg, lock } = fresh();
    Object.assign(entry(lock, "node_modules/accepts"), extra);
    expect(problems(pkg, lock)).toMatch(message);
  });

  it("allows all of that in the dev tree (jest's native resolver, never installed with --omit=dev)", () => {
    const { pkg, lock } = fresh();
    const devOnly = Object.entries(lock.packages).find(([where, e]) => where !== "" && e.dev === true && e.hasInstallScript === true);
    expect(devOnly).toBeDefined();
    expect(check(pkg, lock, allow, snapshot)).toEqual([]);
  });
});

describe("a lockfile-only substitution of a package (the resolved URL decides what npm ci installs)", () => {
  /** Every lock path of debug at one version; there are several runtime copies of 2.6.9. */
  const copies = (lock: Lock): string[] => Object.keys(lock.packages).filter((where) => where.endsWith("/debug") && lock.packages[where]?.version === "2.6.9");

  it("has several copies of one name and version, which is what makes the snapshot ambiguous", () => {
    expect(copies(fresh().lock).length).toBeGreaterThan(1);
  });

  it("refuses a resolved URL that walks out of its package's path with .. and installs another package", () => {
    const { pkg, lock } = fresh();
    const where = copies(lock)[0] ?? "";
    const left = entry(lock, where);
    left.resolved = "https://registry.npmjs.org/debug/-/../../left-pad/-/left-pad-1.3.0.tgz";
    left.integrity = "sha512-" + "L".repeat(86) + "==";
    expect(problems(pkg, lock)).toMatch(/is "debug@2\.6\.9" but resolves from .*left-pad.*not https:\/\/registry\.npmjs\.org\/debug\/-\/debug-2\.6\.9\.tgz/);
  });

  it("refuses the same trick without .., installing another version of the same package", () => {
    const { pkg, lock } = fresh();
    const left = entry(lock, copies(lock)[0] ?? "");
    left.resolved = "https://registry.npmjs.org/debug/-/debug-4.4.0.tgz";
    expect(problems(pkg, lock)).toMatch(/resolves from .*debug-4\.4\.0\.tgz, not https:\/\/registry\.npmjs\.org\/debug\/-\/debug-2\.6\.9\.tgz/);
  });

  it.each(["%2e%2e/", "?x=1", "#frag", "//", "/./"])("refuses a resolved URL with %s in it", (junk) => {
    const { pkg, lock } = fresh();
    entry(lock, copies(lock)[0] ?? "").resolved = `https://registry.npmjs.org/debug/-/${junk}debug-2.6.9.tgz`;
    expect(problems(pkg, lock)).toMatch(/not https:\/\/registry\.npmjs\.org\/debug\/-\/debug-2\.6\.9\.tgz/);
  });

  it("refuses a version that is not plain semver, which could steer the URL", () => {
    const { pkg, lock } = fresh();
    entry(lock, copies(lock)[0] ?? "").version = "2.6.9/../../x";
    expect(problems(pkg, lock)).toMatch(/version that is not plain semver/);
  });

  it("holds scoped names to the same exact URL (the scope stays in the path only)", () => {
    const { pkg, lock } = fresh();
    expect(entry(lock, "node_modules/@tsoa/runtime").resolved).toMatch(/^https:\/\/registry\.npmjs\.org\/@tsoa\/runtime\/-\/runtime-6\.[0-9.]+\.tgz$/);
    expect(check(pkg, lock, allow, snapshot)).toEqual([]);
    entry(lock, "node_modules/@tsoa/runtime").resolved = "https://registry.npmjs.org/@tsoa/runtime/-/@tsoa/runtime-6.6.0.tgz";
    expect(problems(pkg, lock)).toMatch(/node_modules\/@tsoa\/runtime is "@tsoa\/runtime@/);
  });

  it("refuses the same name and version with different integrity at two lock paths, instead of letting one overwrite the other", () => {
    const { pkg, lock } = fresh();
    const [first, second] = copies(lock);
    expect(first).toBeDefined();
    entry(lock, second ?? "").integrity = "sha512-" + "Z".repeat(86) + "==";
    const out = problems(pkg, lock);
    expect(out).toMatch(/debug@2\.6\.9 has different integrity at node_modules\/.*debug and at node_modules\/.*debug: one name and version, two sets of bytes/);
  });

  it("refuses it whichever copy is the odd one out, first or last", () => {
    for (const index of [0, copies(fresh().lock).length - 1]) {
      const { pkg, lock } = fresh();
      entry(lock, copies(lock)[index] ?? "").integrity = "sha512-" + "Y".repeat(86) + "==";
      expect(problems(pkg, lock)).toMatch(/two sets of bytes/);
    }
  });
});

describe("what npm ci --omit=dev installs", () => {
  it("counts devOptional as runtime: it is installed (only dev: true is left out)", () => {
    const { pkg, lock } = fresh();
    const jest = entry(lock, "node_modules/supertest");
    delete jest.dev;
    jest.devOptional = true;
    expect(problems(pkg, lock)).toMatch(/gained supertest@[0-9.]+ \[runtime\]/);
  });

  it("holds a devOptional package to the runtime rules (no install script, no platform binary)", () => {
    const { pkg, lock } = fresh();
    const accepts = entry(lock, "node_modules/accepts");
    delete accepts.dev;
    accepts.devOptional = true;
    accepts.hasInstallScript = true;
    expect(problems(pkg, lock)).toMatch(/runtime package node_modules\/accepts has an install script/);
  });
});

describe("local packages", () => {
  it("refuses workspaces in package.json", () => {
    const { pkg, lock } = fresh();
    pkg.workspaces = ["packages/*"];
    expect(problems(pkg, lock)).toMatch(/package\.json has workspaces/);
  });

  it("refuses a link entry in the lockfile, with or without a resolved URL", () => {
    const a = fresh();
    a.lock.packages["node_modules/local-thing"] = { version: "1.0.0", link: true };
    expect(problems(a.pkg, a.lock)).toMatch(/node_modules\/local-thing is a link \(link: true\)/);
    const b = fresh();
    b.lock.packages["node_modules/local-thing"] = { version: "1.0.0", link: true, resolved: "packages/local-thing" };
    expect(problems(b.pkg, b.lock)).toMatch(/is a link/);
  });
});
