// Lists compiled code in a directory tree, for the Dockerfile's `deps` stage (the production tree must hold none:
// node:sqlite is built in, so a native addon there is a dependency that should not be).
//
// A file is compiled code when it has the extension of one (.node, .so and .so.N, .dylib, .dll, .exe, .wasm), is a
// binding.gyp, or starts with a binary executable's magic bytes whatever it is called: ELF (7f 45 4c 46), Mach-O
// (feedface, feedfacf, cefaedfe, cffaedfe, cafebabe), PE and WebAssembly (00 61 73 6d). A PE file starts with "MZ",
// and "MZ followed by a PE header" is too loose to test cheaply, so every file that starts with "MZ" and is not text is
// taken (text: valid UTF-8 with no control character but tab, newline, vertical tab, form feed, carriage return and
// escape, in the first 8 KiB), as are the .exe/.dll extensions.
//
// Symbolic links are reported, not followed, except npm's own links in a `.bin` directory, which must resolve to a
// file inside the scanned tree (it is scanned there like any other); a `.bin` link that leaves the tree, or resolves to
// nothing, is reported.
//
//   node scripts/find-native.cjs <dir>      prints one path per line, exits 1 if there is any
const fs = require("fs");
const path = require("path");

const EXTENSIONS = /\.(node|so|dylib|dll|exe|wasm)$|\.so\.[0-9.]+$|^binding\.gyp$/i;
const MAGICS = [
  Buffer.from([0x7f, 0x45, 0x4c, 0x46]), // ELF
  Buffer.from([0xfe, 0xed, 0xfa, 0xce]), // Mach-O 32
  Buffer.from([0xfe, 0xed, 0xfa, 0xcf]), // Mach-O 64
  Buffer.from([0xce, 0xfa, 0xed, 0xfe]), // Mach-O 32 little endian
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), // Mach-O 64 little endian
  Buffer.from([0xca, 0xfe, 0xba, 0xbe]), // Mach-O universal (and Java class)
  Buffer.from([0x00, 0x61, 0x73, 0x6d]), // WebAssembly
];
const MZ = Buffer.from("MZ", "latin1");
const TEXT_PROBE = 8192;

/** Whether `head` (a file's first bytes, maybe cut mid-character at the end) reads as text. */
function isText(head, truncated) {
  for (const b of head) {
    if (b < 0x20 && !(b >= 0x09 && b <= 0x0d) && b !== 0x1b) return false;
    if (b === 0x7f) return false;
  }
  // A character cut by the probe's end is not a reason to call the file binary.
  let bytes = head;
  if (truncated) {
    let cut = 0;
    while (cut < 3 && cut < bytes.length && (bytes[bytes.length - 1 - cut] & 0xc0) === 0x80) cut++;
    if (cut < bytes.length && bytes[bytes.length - 1 - cut] >= 0xc0) bytes = bytes.subarray(0, bytes.length - 1 - cut);
  }
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function isCompiled(file) {
  const fd = fs.openSync(file, "r");
  try {
    const head = Buffer.alloc(TEXT_PROBE);
    const read = fs.readSync(fd, head, 0, TEXT_PROBE, 0);
    const bytes = head.subarray(0, read);
    if (read >= 4 && MAGICS.some((m) => m.equals(bytes.subarray(0, 4)))) return true;
    return read >= 2 && bytes.subarray(0, 2).equals(MZ) && !isText(bytes, read === TEXT_PROBE);
  } finally {
    fs.closeSync(fd);
  }
}

/** Whether `target` is `root` or inside it. */
function inside(root, target) {
  const rel = path.relative(root, target);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** Every compiled file under `dir`, as paths relative to it, and every symbolic link that is not one of npm's own. */
function findNative(dir) {
  const found = [];
  const root = fs.realpathSync(dir);
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        if (path.basename(current) !== ".bin") {
          found.push(`${path.relative(dir, full)} (symbolic link)`);
          continue;
        }
        // npm's .bin links point into packages, whose files are scanned like any other: only a link that stays in
        // the tree and reaches a file is one.
        let target;
        try {
          target = fs.realpathSync(full);
        } catch {
          found.push(`${path.relative(dir, full)} (symbolic link to nothing)`);
          continue;
        }
        if (!inside(root, target) || !fs.statSync(target).isFile()) found.push(`${path.relative(dir, full)} (symbolic link out of the tree)`);
      } else if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && (EXTENSIONS.test(entry.name) || isCompiled(full))) found.push(path.relative(dir, full));
    }
  };
  walk(dir);
  return found.sort();
}

module.exports = { findNative };

if (require.main === module) {
  const found = findNative(process.argv[2] ?? "node_modules");
  if (found.length > 0) {
    console.error("compiled code in the production tree:");
    for (const f of found) console.error(f);
    process.exit(1);
  }
  console.log("no compiled code in the production tree");
}
