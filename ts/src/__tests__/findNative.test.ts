/**
 * scripts/find-native.cjs, which the Dockerfile's deps stage runs over the production tree: compiled code is found by
 * extension and by magic bytes, so renaming a binary does not hide it.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

const script = join(__dirname, "..", "..", "scripts", "find-native.cjs");
const { findNative } = createRequire(__filename)(script) as { findNative: (dir: string) => string[] };

const dirs: string[] = [];
function tree(files: Record<string, Buffer | string>): string {
  const dir = mkdtempSync(join(tmpdir(), "find-native-"));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), content);
  }
  return dir;
}
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const ELF = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);

describe("compiled code in a tree", () => {
  it("finds nothing in plain JavaScript, JSON and text", () => {
    const dir = tree({ "a/index.js": "module.exports = 1;\n", "a/package.json": "{}", "a/README.md": "# a\n", "b/lib/x.mjs": "export {};\n" });
    expect(findNative(dir)).toEqual([]);
  });

  it.each([
    ["addon.node"],
    ["libx.so"],
    ["libx.so.1.2"],
    ["x.dylib"],
    ["x.dll"],
    ["tool.exe"],
    ["module.wasm"],
    ["binding.gyp"],
    ["UPPER.NODE"],
  ])("finds %s by its name", (name) => {
    const dir = tree({ [`pkg/${name}`]: "not really" });
    expect(findNative(dir)).toEqual([`pkg${process.platform === "win32" ? "\\" : "/"}${name}`]);
  });

  it.each([
    ["an ELF binary renamed .js", "index.js", ELF],
    ["an ELF binary with no extension", "bin/tool", ELF],
    ["a Mach-O binary renamed .txt", "notes.txt", Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1])],
    ["a universal Mach-O binary", "fat", Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2])],
    ["WebAssembly renamed .json", "data.json", Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])],
    ["a PE binary renamed .map", "x.map", Buffer.from([0x4d, 0x5a, 0x90, 0x00, 3, 0])],
  ])("finds %s by its magic bytes", (_name, file, content) => {
    const dir = tree({ [`pkg/${file}`]: content, "pkg/clean.js": "1" });
    const found = findNative(dir);
    expect(found).toHaveLength(1);
    expect(found[0]).toContain(file.split("/").pop() ?? "");
  });

  it("does not take a short file or text that merely starts like a header for a binary", () => {
    const dir = tree({ "a.js": Buffer.from([0x7f, 0x45]), "b.js": "ELF", "c.js": Buffer.alloc(0), "d.txt": "ELF is a word" });
    expect(findNative(dir)).toEqual([]);
  });

  it("reports a symbolic link, except npm's own links in .bin", () => {
    const dir = tree({ "pkg/real.js": "1", ".bin/real": "1" });
    try {
      symlinkSync(join(dir, "pkg", "real.js"), join(dir, ".bin", "tool"));
      symlinkSync(join(dir, "pkg", "real.js"), join(dir, "pkg", "escape"));
    } catch {
      return; // creating symbolic links needs a privilege on Windows
    }
    expect(findNative(dir)).toEqual([join("pkg", "escape") + " (symbolic link)"]);
  });

  it("walks every level", () => {
    const dir = tree({ "a/b/c/d/e/deep.js": ELF });
    expect(findNative(dir)).toHaveLength(1);
  });
});

describe("as the Dockerfile runs it", () => {
  it("exits 1 and names the file when there is compiled code, 0 when there is none", () => {
    const bad = spawnSync(process.execPath, [script, tree({ "pkg/hidden.js": ELF })], { encoding: "utf8" });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain("hidden.js");
    const good = spawnSync(process.execPath, [script, tree({ "pkg/ok.js": "1" })], { encoding: "utf8" });
    expect(good.status).toBe(0);
  });

  it("is clean on the production tree this lockfile installs", () => {
    // node_modules here is the full tree (npm ci), so check only what ships: the runtime packages' own directories.
    const root = join(__dirname, "..", "..", "node_modules");
    const runtime = ["express", "@tsoa/runtime", "body-parser", "qs", "send"];
    for (const name of runtime) expect(findNative(join(root, name))).toEqual([]);
  });
});
