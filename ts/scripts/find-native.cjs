// Lists compiled code in a directory tree, for the Dockerfile's `deps` stage (the production tree must hold none:
// node:sqlite is built in, so a native addon there is a dependency that should not be).
//
// A file is compiled code when it has the extension of one (.node, .so and .so.N, .dylib, .dll, .exe, .wasm), is a
// binding.gyp, or starts with a binary executable's magic bytes whatever it is called: ELF (7f 45 4c 46), Mach-O
// (feedface, feedfacf, cefaedfe, cffaedfe, cafebabe), PE ("MZ" followed by a PE header is too loose to test cheaply, so
// the .exe/.dll extensions and the "MZ" prefix on a file that is not text are both taken) and WebAssembly (00 61 73 6d).
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
  Buffer.from([0x4d, 0x5a, 0x90, 0x00]), // PE, as compilers write it
];

function hasMagic(file) {
  const fd = fs.openSync(file, "r");
  try {
    const head = Buffer.alloc(4);
    const read = fs.readSync(fd, head, 0, 4, 0);
    return read === 4 && MAGICS.some((m) => m.equals(head));
  } finally {
    fs.closeSync(fd);
  }
}

/** Every compiled file under `dir`, as paths relative to it. Symbolic links are reported, not followed. */
function findNative(dir) {
  const found = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      // npm's own .bin links point into packages, whose files are scanned like any other; a link anywhere else could point out of the tree.
      if (entry.isSymbolicLink()) {
        if (path.basename(current) !== ".bin") found.push(`${path.relative(dir, full)} (symbolic link)`);
      }
      else if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && (EXTENSIONS.test(entry.name) || hasMagic(full))) found.push(path.relative(dir, full));
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
