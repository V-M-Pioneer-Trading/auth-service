// Runs the service under test and assumes nothing else about it.
//
//   CONTRACT_IMAGE  the image to run with `docker run` (what CI and the porters use)
//   CONTRACT_BIN    a native executable, for iterating on a machine with no
//                   Docker daemon. Same environment, same HTTP, no container.
//
// The service is configured only through environment variables. Secrets reach
// `docker run` as `-e NAME` with the value in the CLI's own environment, so they
// never appear on a command line.
import { spawn, spawnSync } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { send, sleep } from "./http.ts";

export type Env = Record<string, string | undefined>;

export interface ServiceSpec {
  env: Env;
  /** name -> contents. An env value of "@file:<name>" becomes that file's path inside the service. */
  files?: Record<string, string>;
  volume?: Volume;
}

export interface Volume {
  name: string;
  dir?: string;
}

export interface Service {
  /** Host port the service is reachable on. */
  port: number;
  output(): string;
  /** Kill it hard (SIGKILL): the contract says nothing about graceful shutdown. */
  stop(): Promise<void>;
  /** Resolves with the exit code once the process is gone. */
  exited: Promise<number | null>;
}

const image = process.env.CONTRACT_IMAGE;
const bin = process.env.CONTRACT_BIN;

if (!image && !bin) {
  throw new Error("set CONTRACT_IMAGE (a docker image to run) or, with no Docker daemon, CONTRACT_BIN (a native executable)");
}

export const mode: "docker" | "bin" = image ? "docker" : "bin";
/** How the service reaches the stubs running in the test process. */
export const stubHost = mode === "docker" ? "host.docker.internal" : "127.0.0.1";

const cleanups = new Set<() => void>();
function registerCleanup(fn: () => void): () => void {
  cleanups.add(fn);
  return () => {
    cleanups.delete(fn);
  };
}
// Teardown even when a test throws or the process is interrupted.
process.on("exit", () => {
  for (const fn of [...cleanups]) {
    try {
      fn();
    } catch {
      /* best effort */
    }
  }
});
for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => process.exit(130));
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as AddressInfo;
      s.close(() => resolve(port));
    });
  });
}

function docker(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("docker", args, { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

let counter = 0;
const runId = randomBytes(4).toString("hex");

/** A fresh, empty /data. Survives stop() so a second start can reuse it. */
export function newVolume(): Volume {
  const name = `contract-${runId}-${process.pid}-${++counter}`;
  if (mode === "docker") {
    const r = docker(["volume", "create", name]);
    if (r.status !== 0) throw new Error(`docker volume create failed: ${r.stderr}`);
    registerCleanup(() => {
      docker(["volume", "rm", "-f", name]);
    });
    return { name };
  }
  const dir = mkdtempSync(join(tmpdir(), "contract-data-"));
  registerCleanup(() => rmSync(dir, { recursive: true, force: true }));
  return { name, dir };
}

/** Starts the process and returns without waiting for it to listen. */
async function launch(spec: ServiceSpec): Promise<Service> {
  const fileDir = mkdtempSync(join(tmpdir(), "contract-files-"));
  const hostFiles: Record<string, string> = {};
  for (const [name, content] of Object.entries(spec.files ?? {})) {
    const p = join(fileDir, name);
    // 0644: an image that runs as a non-root user must still be able to read it.
    writeFileSync(p, content, { mode: 0o644 });
    hostFiles[name] = p;
  }
  registerCleanup(() => rmSync(fileDir, { recursive: true, force: true }));

  const containerPort = spec.env.PORT ? Number(spec.env.PORT) : 80;
  const hostPort = await freePort();
  const output: string[] = [];
  const collect = (chunk: Buffer) => output.push(chunk.toString("utf8"));

  // Resolve "@file:name" to wherever that file lives for this runner.
  const fileTarget = (name: string): string => (mode === "docker" ? `/run/contract/${name}` : (hostFiles[name] as string));
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(spec.env)) {
    if (v === undefined) continue;
    env[k] = v.startsWith("@file:") ? fileTarget(v.slice("@file:".length)) : v;
  }

  let child: ChildProcess;
  let kill: () => void;

  if (mode === "docker") {
    const name = `contract-svc-${runId}-${process.pid}-${++counter}`;
    const args = ["run", "--rm", "--name", name, "--add-host=host.docker.internal:host-gateway", "-p", `127.0.0.1:${hostPort}:${containerPort}`];
    if (spec.volume) args.push("-v", `${spec.volume.name}:/data`);
    for (const fname of Object.keys(hostFiles)) args.push("-v", `${hostFiles[fname]}:/run/contract/${fname}:ro`);
    for (const k of Object.keys(env)) args.push("-e", k);
    args.push(image as string);
    child = spawn("docker", args, { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    kill = () => {
      docker(["rm", "-f", name]);
    };
  } else {
    const childEnv: Record<string, string> = { ...env };
    // Windows needs these to start a process at all; they carry nothing the service reads.
    for (const k of ["SYSTEMROOT", "PATH", "TEMP", "TMP"]) if (process.env[k]) childEnv[k] = process.env[k] as string;
    if (spec.volume?.dir) childEnv.SQLITE_DB_PATH = join(spec.volume.dir, "auth.db");
    // A native run binds the free host port directly, so it cannot test the default of 80.
    childEnv.PORT = String(hostPort);
    child = spawn(bin as string, [], { env: childEnv, stdio: ["ignore", "pipe", "pipe"] });
    kill = () => {
      child.kill("SIGKILL");
    };
  }
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);

  const exited = new Promise<number | null>((resolve) => {
    child.on("close", (code) => resolve(code));
    child.on("error", () => resolve(-1));
  });
  const unregister = registerCleanup(kill);
  void exited.then(() => {
    unregister();
    rmSync(fileDir, { recursive: true, force: true });
  });

  return {
    port: hostPort,
    output: () => output.join(""),
    stop: async () => {
      // Keep killing until the process is really gone: stopping while `docker run` is still creating
      // the container would otherwise remove nothing and leave the container to start after us.
      let gone = false;
      void exited.then(() => {
        gone = true;
      });
      while (!gone) {
        kill();
        await Promise.race([exited, sleep(500)]);
      }
    },
    exited,
  };
}

/** Starts the service and waits until GET /health answers. Rejects, with its output, if it exits first. */
export async function startService(spec: ServiceSpec, timeoutMs = 60_000): Promise<Service> {
  // The free port is probed and then released before the service binds it, so another process can
  // take it in between. That shows up as the service dying on a bind error: pick another and retry.
  for (let attempt = 1; ; attempt++) {
    try {
      return await startOnce(spec, timeoutMs);
    } catch (err) {
      if (attempt < 3 && /address already in use|port is already allocated|Bind for .* failed/i.test(String(err))) continue;
      throw err;
    }
  }
}

async function startOnce(spec: ServiceSpec, timeoutMs: number): Promise<Service> {
  const svc = await launch(spec);
  const deadline = Date.now() + timeoutMs;
  let exitedEarly: number | null | undefined;
  void svc.exited.then((c) => {
    exitedEarly = c;
  });
  for (;;) {
    if (exitedEarly !== undefined) {
      throw new Error(`service exited (code ${exitedEarly}) before it became healthy:\n${svc.output()}`);
    }
    try {
      const r = await send(svc.port, { path: "/health", timeoutMs: 2000 });
      if (r.status === 200) return svc;
    } catch {
      /* not listening yet */
    }
    if (Date.now() > deadline) {
      await svc.stop();
      throw new Error(`service did not become healthy within ${timeoutMs} ms:\n${svc.output()}`);
    }
    await sleep(150);
  }
}

export interface FailedStart {
  code: number | null;
  output: string;
}

/** Starts the service expecting it to refuse its configuration and exit. */
export async function startExpectingExit(spec: ServiceSpec, timeoutMs = 30_000): Promise<FailedStart> {
  const svc = await launch(spec);
  const timeout = sleep(timeoutMs).then(() => "timeout" as const);
  const result = await Promise.race([svc.exited, timeout]);
  if (result === "timeout") {
    const out = svc.output();
    await svc.stop();
    throw new Error(`expected the service to exit on startup but it kept running:\n${out}`);
  }
  return { code: result, output: svc.output() };
}
