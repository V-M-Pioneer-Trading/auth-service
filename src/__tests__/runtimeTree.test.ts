/**
 * What the built service loads. The image's deps stage deletes node_modules/@hapi and node_modules/@types (declared by
 * @tsoa/runtime for its hapi adapter and its typings; nothing here uses them), so the built server must not require
 * either: this boots dist/server.js in a child process, builds the app, answers a request, and lists what Node loaded.
 * Needs the build (`npm test` builds first, see the pretest script).
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

const dist = join(__dirname, "..", "..", "dist", "server.js");

const PROBE = `
const http = require("node:http");
const { createApp, createHttpServer } = require(${JSON.stringify(dist)});
const { openInMemory } = require(${JSON.stringify(join(__dirname, "..", "..", "dist", "db", "database.js"))});
const { sqliteCredentialStore } = require(${JSON.stringify(join(__dirname, "..", "..", "dist", "db", "credential.js"))});
const app = createApp({ corsAllowedOrigin: "http://x", credentials: sqliteCredentialStore(openInMemory()) });
const server = createHttpServer(app);
server.listen(0, "127.0.0.1", () => {
  const port = server.address().port;
  const get = (path) => new Promise((resolve) => http.get({ port, path }, (res) => { let body = ""; res.on("data", (d) => (body += d)); res.on("end", () => resolve([res.statusCode, body])); }));
  Promise.all([get("/health"), get("/api/auth/v1/status"), get("/nope")]).then((answers) => {
    console.log(JSON.stringify({ answers, loaded: Object.keys(require.cache) }));
    server.close();
    process.exit(0);
  });
});
`;

describe("the built service", () => {
  it("has been built (npm test builds first; a bare jest run does not)", () => {
    expect(existsSync(dist)).toBe(true);
  });

  const run = spawnSync(process.execPath, ["-e", PROBE], { encoding: "utf8", cwd: join(__dirname, "..", "..") });
  const out = run.status === 0 ? (JSON.parse(run.stdout.trim().split("\n").pop() ?? "{}") as { answers: [number, string][]; loaded: string[] }) : undefined;

  it("boots and answers", () => {
    expect(run.stderr.replace(/\(node:\d+\) ExperimentalWarning.*\n|\(Use `node --trace-warnings.*\n/g, "")).toBe("");
    expect(out?.answers.map(([status]) => status)).toEqual([200, 200, 405]);
  });

  it("never requires anything under @hapi or @types, which the image deletes", () => {
    const loaded = out?.loaded ?? [];
    expect(loaded.length).toBeGreaterThan(50);
    expect(loaded.filter((file) => /[\\/]node_modules[\\/]@(hapi|types)[\\/]/.test(file))).toEqual([]);
  });

  it("does load Express and @tsoa/runtime, so the probe is looking at the right tree", () => {
    const loaded = out?.loaded ?? [];
    expect(loaded.some((file) => /[\\/]node_modules[\\/]express[\\/]/.test(file))).toBe(true);
    expect(loaded.some((file) => /[\\/]node_modules[\\/]@tsoa[\\/]runtime[\\/]/.test(file))).toBe(true);
  });
});
