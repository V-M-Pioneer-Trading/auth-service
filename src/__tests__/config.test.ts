/**
 * Startup configuration: what the service refuses to start with, what it starts with in a fail-closed state, and the
 * defaults. The table of refusals is the Go service's (src/app-runner.go, api.ReadM2MConfig, validateM2MConfig); the
 * contract suite pins the same cases black-box (tests/startup.test.ts), these run in milliseconds and name the message.
 */
import { generateKeyPairSync } from "node:crypto";
import { ConfigError, loadConfig, parsePort, validateM2MConfig, type Config, type Env } from "../config";

const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PUBLIC_PEM = rsa.publicKey.export({ type: "spki", format: "pem" }).toString();
const PRIVATE_PEM = rsa.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const OTHER_PRIVATE_PEM = other.privateKey.export({ type: "pkcs8", format: "pem" }).toString();

const SHARED = "shared-secret-value";
const INTROSPECTION = "introspection-secret-value";
const CALLER_A = "caller-automation-secret";
const CALLER_B = "caller-ai-secret";
const MACHINE_A = "machine-key-automation";
const MACHINE_B = "machine-key-ai";

/** A healthy production-mode environment: Clerk mints. */
const clerkEnv = (): Env => ({
  CLERK_JWT_KEY: PUBLIC_PEM,
  AUTH_SERVICE_SHARED_SECRET: SHARED,
  AUTH_INTROSPECTION_SECRET: INTROSPECTION,
  M2M_CALLER_SECRET_AUTOMATION_SERVICE: CALLER_A,
  M2M_CALLER_SECRET_AI_SERVICE: CALLER_B,
  M2M_MACHINE_KEY_AUTOMATION_SERVICE: MACHINE_A,
  M2M_MACHINE_KEY_AI_SERVICE: MACHINE_B,
});

/** A healthy dev-mode environment: a local key mints. */
const devEnv = (): Env => ({
  CLERK_JWT_KEY: PUBLIC_PEM,
  AUTH_SERVICE_SHARED_SECRET: SHARED,
  AUTH_INTROSPECTION_SECRET: INTROSPECTION,
  M2M_CALLER_SECRET_AUTOMATION_SERVICE: CALLER_A,
  M2M_CALLER_SECRET_AI_SERVICE: CALLER_B,
  DEV_M2M_SIGNING_KEY_FILE: "/run/dev-m2m.pem",
});

const SECRETS = [SHARED, INTROSPECTION, CALLER_A, CALLER_B, MACHINE_A, MACHINE_B, "hunter2"];

interface Run {
  config?: Config;
  error?: ConfigError;
  lines: string[];
}

function run(env: Env, files: Record<string, string> = { "/run/dev-m2m.pem": PRIVATE_PEM }): Run {
  const lines: string[] = [];
  const log = (line: string): void => void lines.push(line);
  const readFile = (path: string): Buffer => {
    const content = files[path];
    if (content === undefined) throw Object.assign(new Error(`ENOENT ${path}`), { code: "ENOENT" });
    return Buffer.from(content);
  };
  try {
    return { config: loadConfig(env, log, { readFile, log }), lines };
  } catch (err) {
    if (!(err instanceof ConfigError)) throw err;
    return { error: err, lines };
  }
}

function expectRefusal(env: Env, mentions: RegExp | undefined, files?: Record<string, string>): void {
  const result = run(env, files);
  expect(result.error).toBeDefined();
  const output = [result.error?.message ?? "", ...result.lines].join("\n");
  if (mentions !== undefined) expect(output).toMatch(mentions);
  // Never a secret, never key material.
  for (const secret of SECRETS) expect(output).not.toContain(secret);
  expect(output).not.toContain("BEGIN");
  expect(output).not.toMatch(/[A-Za-z0-9+/]{60}/);
}

describe("a healthy configuration", () => {
  it("loads in production mode (Clerk mints) with the Go service's defaults", () => {
    const { config, lines } = run(clerkEnv());
    expect(config).toMatchObject({
      port: 80,
      sqlitePath: "./data/auth.db",
      gatewayProxyUrl: "http://localhost:3002/proxy",
      corsAllowedOrigin: "http://localhost:3000",
      clerkIssuer: "",
      sharedSecret: SHARED,
      introspectionSecret: INTROSPECTION,
    });
    expect(config?.m2m.devSigningKey).toBeUndefined();
    expect(config?.m2m.clerkTokensUrl).toBe("");
    expect(config?.m2m.callers.map((c) => [c.name, c.secret, c.machineKey])).toEqual([
      ["automation-service", CALLER_A, MACHINE_A],
      ["ai-service", CALLER_B, MACHINE_B],
    ]);
    expect(lines).toEqual([
      "POST /auth/v1/m2m-token: automation-service mints via Clerk",
      "POST /auth/v1/m2m-token: ai-service mints via Clerk",
    ]);
  });

  it("loads in dev mode, naming the dev key as the source", () => {
    const { config, lines } = run(devEnv());
    expect(config?.m2m.devSigningKey?.asymmetricKeyType).toBe("rsa");
    expect(lines).toEqual([
      "POST /auth/v1/m2m-token: automation-service mints via the local dev key (DEV_M2M_SIGNING_KEY_FILE)",
      "POST /auth/v1/m2m-token: ai-service mints via the local dev key (DEV_M2M_SIGNING_KEY_FILE)",
    ]);
  });

  it("takes every variable it reads", () => {
    const { config } = run({
      ...clerkEnv(),
      PORT: "3005",
      SQLITE_DB_PATH: "/data/auth.db",
      ST_GATEWAY_URL: "http://st-gateway:3002/",
      CORS_ALLOWED_ORIGIN: "https://dashboard.example",
      CLERK_ISSUER: "https://clerk.example",
      CLERK_API_BASE_URL: "http://stub.example:9000/base/",
    });
    expect(config).toMatchObject({
      port: 3005,
      sqlitePath: "/data/auth.db",
      // Go appends "/proxy" to whatever it is given: a trailing slash stays.
      gatewayProxyUrl: "http://st-gateway:3002//proxy",
      corsAllowedOrigin: "https://dashboard.example",
      clerkIssuer: "https://clerk.example",
    });
    expect(config?.m2m).toMatchObject({ issuer: "https://clerk.example", clerkTokensUrl: "http://stub.example:9000/base/v1/m2m_tokens" });
  });

  it("treats an empty variable as unset (Go's getEnv and os.Getenv)", () => {
    const { config } = run({ ...clerkEnv(), PORT: "", SQLITE_DB_PATH: "", ST_GATEWAY_URL: "", CORS_ALLOWED_ORIGIN: "", CLERK_ISSUER: "", CLERK_API_BASE_URL: "" });
    expect(config).toMatchObject({ port: 80, sqlitePath: "./data/auth.db", gatewayProxyUrl: "http://localhost:3002/proxy", corsAllowedOrigin: "http://localhost:3000", clerkIssuer: "" });
    expect(config?.m2m.clerkTokensUrl).toBe("");
  });

  it("logs scheme and host of CLERK_API_BASE_URL in Clerk mode, never its path, and logs nothing about it in dev mode", () => {
    const clerk = run({ ...clerkEnv(), CLERK_API_BASE_URL: "http://stub.example:9000/base-path-sentinel" });
    expect(clerk.lines).toContain("CLERK_API_BASE_URL is set: minting via http://stub.example:9000 instead of api.clerk.com");
    expect(clerk.lines.join("\n")).not.toContain("base-path-sentinel");
    const dev = run({ ...devEnv(), CLERK_API_BASE_URL: "http://stub.example:9000" });
    expect(dev.lines.join("\n")).not.toContain("stub.example");
  });
});

describe("what boots in a fail-closed state (never a refusal)", () => {
  it("no AUTH_INTROSPECTION_SECRET: the route will reject everyone, and the log says so", () => {
    const env = clerkEnv();
    delete env.AUTH_INTROSPECTION_SECRET;
    const { config, lines } = run(env);
    expect(config?.introspectionSecret).toBe("");
    expect(lines).toContain("AUTH_INTROSPECTION_SECRET is not set: POST /auth/v1/introspect will reject every caller");
    expect(run({ ...clerkEnv(), AUTH_INTROSPECTION_SECRET: "" }).config?.introspectionSecret).toBe("");
  });

  it("no M2M caller secrets: the mint route will reject everyone, and the log says so", () => {
    const { config, lines } = run({ CLERK_JWT_KEY: PUBLIC_PEM, AUTH_SERVICE_SHARED_SECRET: SHARED });
    expect(config?.m2m.callers.every((c) => c.secret === "")).toBe(true);
    expect(lines).toContain("no M2M_CALLER_SECRET_* is set: POST /auth/v1/m2m-token will reject every caller");
  });

  it("a machine key with no caller secret: that caller is disabled, not an error", () => {
    const env = clerkEnv();
    delete env.M2M_CALLER_SECRET_AI_SERVICE;
    const { config, lines } = run(env);
    expect(config?.m2m.callers.map((c) => c.secret)).toEqual([CALLER_A, ""]);
    expect(lines).toEqual(["POST /auth/v1/m2m-token: automation-service mints via Clerk"]);
  });

  it("one caller enabled and the other left alone", () => {
    const env = clerkEnv();
    delete env.M2M_CALLER_SECRET_AI_SERVICE;
    delete env.M2M_MACHINE_KEY_AI_SERVICE;
    expect(run(env).error).toBeUndefined();
  });

  it("a dev key that is not the verification key only warns: tokens minted from it will not introspect", () => {
    const { config, lines } = run(devEnv(), { "/run/dev-m2m.pem": OTHER_PRIVATE_PEM });
    expect(config).toBeDefined();
    expect(lines).toContain("DEV_M2M_SIGNING_KEY_FILE does not match the verification key: machine tokens minted here will not introspect as active");
    expect(run(devEnv()).lines.join("\n")).not.toContain("does not match");
  });
});

describe("the Clerk verification key", () => {
  it("is required: neither variable set", () => {
    const env = clerkEnv();
    delete env.CLERK_JWT_KEY;
    expectRefusal(env, /CLERK_JWT_KEY or CLERK_JWT_KEY_FILE must be set/);
    expectRefusal({ ...env, CLERK_JWT_KEY: "" }, /CLERK_JWT_KEY or CLERK_JWT_KEY_FILE must be set/);
  });

  it("must be a PEM public key, never a private key", () => {
    expectRefusal({ ...clerkEnv(), CLERK_JWT_KEY: "this is not a PEM" }, /CLERK_JWT_KEY/);
    expectRefusal({ ...clerkEnv(), CLERK_JWT_KEY: PRIVATE_PEM }, /CLERK_JWT_KEY/);
    expectRefusal({ ...clerkEnv(), CLERK_JWT_KEY: rsa.privateKey.export({ type: "pkcs1", format: "pem" }).toString() }, /CLERK_JWT_KEY/);
    expectRefusal({ ...clerkEnv(), CLERK_JWT_KEY: generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ type: "spki", format: "pem" }).toString() }, /CLERK_JWT_KEY/);
  });

  it("is read from CLERK_JWT_KEY_FILE when the inline variable is absent, and inline wins when both are set", () => {
    const env = clerkEnv();
    delete env.CLERK_JWT_KEY;
    const fromFile = run({ ...env, CLERK_JWT_KEY_FILE: "/run/clerk.pem" }, { "/run/clerk.pem": PUBLIC_PEM });
    expect(fromFile.config?.clerkJwtKey.asymmetricKeyType).toBe("rsa");
    // The file holds the OTHER key; inline names this one: the file is never read (it would not even exist).
    const both = run({ ...clerkEnv(), CLERK_JWT_KEY_FILE: "/nonexistent" }, {});
    expect(both.error).toBeUndefined();
  });

  it("refuses a CLERK_JWT_KEY_FILE that is missing, empty or whitespace, or not a key", () => {
    const env = clerkEnv();
    delete env.CLERK_JWT_KEY;
    expectRefusal({ ...env, CLERK_JWT_KEY_FILE: "/nonexistent/clerk.pem" }, /CLERK_JWT_KEY_FILE/, {});
    expectRefusal({ ...env, CLERK_JWT_KEY_FILE: "/run/clerk.pem" }, /CLERK_JWT_KEY_FILE.*is empty/, { "/run/clerk.pem": "" });
    expectRefusal({ ...env, CLERK_JWT_KEY_FILE: "/run/clerk.pem" }, /CLERK_JWT_KEY_FILE.*is empty/, { "/run/clerk.pem": " \n\t 　\n" });
    expectRefusal({ ...env, CLERK_JWT_KEY_FILE: "/run/clerk.pem" }, /CLERK_JWT_KEY/, { "/run/clerk.pem": "garbage" });
  });

  it("takes one line with literal \\n separators, as production passes it from SSM", () => {
    const oneLine = PUBLIC_PEM.trim().replaceAll("\n", "\\n");
    expect(oneLine).not.toContain("\n");
    expect(run({ ...clerkEnv(), CLERK_JWT_KEY: oneLine }).config?.clerkJwtKey.asymmetricKeyType).toBe("rsa");
  });

  it("takes a PKCS#1 public key", () => {
    const pkcs1 = rsa.publicKey.export({ type: "pkcs1", format: "pem" }).toString();
    expect(run({ ...clerkEnv(), CLERK_JWT_KEY: pkcs1 }).error).toBeUndefined();
  });
});

describe("the shared secret and the introspection secret", () => {
  it("AUTH_SERVICE_SHARED_SECRET is required, and an empty value counts as unset", () => {
    const env = clerkEnv();
    delete env.AUTH_SERVICE_SHARED_SECRET;
    expectRefusal(env, /AUTH_SERVICE_SHARED_SECRET must be set/);
    expectRefusal({ ...env, AUTH_SERVICE_SHARED_SECRET: "" }, /AUTH_SERVICE_SHARED_SECRET must be set/);
  });

  it("is not trimmed or otherwise judged: whitespace around it is the operator's business, as in Go", () => {
    expect(run({ ...clerkEnv(), AUTH_SERVICE_SHARED_SECRET: "  padded  " }).config?.sharedSecret).toBe("  padded  ");
  });

  it("refuses an introspection secret equal to the vault's shared secret, naming both variables and neither value", () => {
    expectRefusal({ ...clerkEnv(), AUTH_INTROSPECTION_SECRET: SHARED }, /AUTH_INTROSPECTION_SECRET must not be the same value as AUTH_SERVICE_SHARED_SECRET/);
  });
});

describe("the M2M mint table (validateM2MConfig)", () => {
  it("refuses two callers with the same secret", () => {
    expectRefusal({ ...clerkEnv(), M2M_CALLER_SECRET_AI_SERVICE: CALLER_A }, /the m2m caller secrets for automation-service and ai-service must differ/);
  });

  it("refuses a caller secret equal to AUTH_SERVICE_SHARED_SECRET", () => {
    expectRefusal({ ...clerkEnv(), M2M_CALLER_SECRET_AUTOMATION_SERVICE: SHARED }, /AUTH_SERVICE_SHARED_SECRET/);
    expectRefusal({ ...clerkEnv(), M2M_CALLER_SECRET_AI_SERVICE: SHARED }, /ai-service.*AUTH_SERVICE_SHARED_SECRET/);
  });

  it("refuses a caller secret equal to AUTH_INTROSPECTION_SECRET (every service holds that one)", () => {
    expectRefusal({ ...clerkEnv(), M2M_CALLER_SECRET_AI_SERVICE: INTROSPECTION }, /AUTH_INTROSPECTION_SECRET/);
    expectRefusal({ ...clerkEnv(), M2M_CALLER_SECRET_AUTOMATION_SERVICE: INTROSPECTION }, /automation-service.*AUTH_INTROSPECTION_SECRET/);
  });

  it("has nothing to collide with when there is no introspection secret", () => {
    const env: Env = { ...clerkEnv(), M2M_CALLER_SECRET_AI_SERVICE: "" };
    delete env.AUTH_INTROSPECTION_SECRET;
    // An empty introspection secret is not a value a caller secret can equal (an empty caller secret is "disabled").
    expect(run(env).error).toBeUndefined();
  });

  it.each([" secret", "secret ", "secret\t", "   ", " secret", "secret　", "\nsecret"])("refuses a caller secret with surrounding whitespace, or only whitespace: %j", (secret) => {
    expectRefusal({ ...clerkEnv(), M2M_CALLER_SECRET_AI_SERVICE: secret }, /the m2m caller secret for ai-service has leading or trailing whitespace/);
  });

  it("accepts whitespace INSIDE a caller secret, and the characters JavaScript's trim would wrongly strip (U+FEFF)", () => {
    expect(run({ ...clerkEnv(), M2M_CALLER_SECRET_AI_SERVICE: "two words" }).error).toBeUndefined();
    expect(run({ ...clerkEnv(), M2M_CALLER_SECRET_AI_SERVICE: "﻿secret" }).error).toBeUndefined();
  });

  it("refuses an enabled caller with nothing to mint with", () => {
    const env = clerkEnv();
    delete env.M2M_MACHINE_KEY_AUTOMATION_SERVICE;
    expectRefusal(env, /m2m caller automation-service has a caller secret but no machine key and no DEV_M2M_SIGNING_KEY_FILE/);
    const bare: Env = { CLERK_JWT_KEY: PUBLIC_PEM, AUTH_SERVICE_SHARED_SECRET: SHARED, M2M_CALLER_SECRET_AI_SERVICE: CALLER_B };
    expectRefusal(bare, /ai-service has a caller secret but no machine key/);
  });

  it("refuses two callers sharing one Clerk machine key", () => {
    expectRefusal({ ...clerkEnv(), M2M_MACHINE_KEY_AI_SERVICE: MACHINE_A }, /same M2M_MACHINE_KEY_\*: one Clerk Machine per caller/);
  });

  it("refuses two callers sharing a machine key even when neither has a caller secret", () => {
    const env = clerkEnv();
    delete env.M2M_CALLER_SECRET_AUTOMATION_SERVICE;
    delete env.M2M_CALLER_SECRET_AI_SERVICE;
    expectRefusal({ ...env, M2M_MACHINE_KEY_AI_SERVICE: MACHINE_A }, /same M2M_MACHINE_KEY_\*/);
  });

  it("refuses a dev signing key next to a machine key: one trust anchor per process", () => {
    expectRefusal({ ...devEnv(), M2M_MACHINE_KEY_AI_SERVICE: MACHINE_B }, /DEV_M2M_SIGNING_KEY_FILE and a M2M_MACHINE_KEY_\* variable are both set/);
  });

  it("refuses a dev signing key that is missing, empty, or not an RSA private key", () => {
    expectRefusal(devEnv(), /DEV_M2M_SIGNING_KEY_FILE/, {});
    expectRefusal(devEnv(), /DEV_M2M_SIGNING_KEY_FILE.*is empty/, { "/run/dev-m2m.pem": "\n" });
    expectRefusal(devEnv(), /DEV_M2M_SIGNING_KEY_FILE is not an RSA private key/, { "/run/dev-m2m.pem": "garbage" });
    expectRefusal(devEnv(), /DEV_M2M_SIGNING_KEY_FILE is not an RSA private key/, { "/run/dev-m2m.pem": PUBLIC_PEM });
    expectRefusal(devEnv(), /DEV_M2M_SIGNING_KEY_FILE is not an RSA private key/, {
      "/run/dev-m2m.pem": generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    });
  });

  it("takes the dev key as PKCS#8 or PKCS#1", () => {
    expect(run(devEnv(), { "/run/dev-m2m.pem": PRIVATE_PEM }).error).toBeUndefined();
    expect(run(devEnv(), { "/run/dev-m2m.pem": rsa.privateKey.export({ type: "pkcs1", format: "pem" }).toString() }).error).toBeUndefined();
  });

  it("refuses a caller that is not in the scope table (the check Go repeats in SetUpRouter)", () => {
    expect(() => { validateM2MConfig([{ name: "rogue-service", secret: "s", machineKey: "k" }], false, SHARED, INTROSPECTION); }).toThrow(/m2m caller "rogue-service" is not in the scope table/);
  });
});

describe("CLERK_API_BASE_URL", () => {
  it.each(["not a url", "ftp://stub.example", "http://", "http://user:hunter2@stub.example", "http://stub.example?x=1", "http://stub.example?", "http://stub.example#frag", "http://stub.example/#"])(
    "refuses %s, even in dev mode where it would not be used, and never prints it",
    (bad) => {
      expectRefusal({ ...clerkEnv(), CLERK_API_BASE_URL: bad }, /^CLERK_API_BASE_URL must be an http or https URL/);
      expectRefusal({ ...devEnv(), CLERK_API_BASE_URL: bad }, /CLERK_API_BASE_URL/);
      expect(run({ ...clerkEnv(), CLERK_API_BASE_URL: bad }).error?.message).not.toContain(bad);
    },
  );
});

describe("which refusal is reported first (Go's order)", () => {
  it("the Clerk key text is read before the shared secret, the shared secret before the M2M table, the M2M table before the key is parsed", () => {
    const env = { ...clerkEnv(), M2M_CALLER_SECRET_AI_SERVICE: " bad", AUTH_SERVICE_SHARED_SECRET: "" };
    expect(run({ ...env, CLERK_JWT_KEY: "garbage" }).error?.message).toMatch(/AUTH_SERVICE_SHARED_SECRET/);
    expect(run({ ...env, AUTH_SERVICE_SHARED_SECRET: SHARED, CLERK_JWT_KEY: "garbage" }).error?.message).toMatch(/whitespace/);
    expect(run({ ...clerkEnv(), CLERK_JWT_KEY: "garbage" }).error?.message).toMatch(/CLERK_JWT_KEY/);
  });
});

describe("PORT", () => {
  it.each([
    ["80", 80],
    ["8080", 8080],
    ["0", 0],
    ["65535", 65535],
    ["08080", 8080],
  ])("accepts %s", (raw, port) => {
    expect(parsePort(raw)).toBe(port);
  });

  it.each(["65536", "-1", "http", "80a", " 80", "80 ", "8.0", "0x50", "", "99999999999999999999"])("refuses %j: Go's listen would fail, Node would take a word for a pipe name", (raw) => {
    expect(() => parsePort(raw)).toThrow(ConfigError);
  });

  it("is checked by loadConfig", () => {
    expectRefusal({ ...clerkEnv(), PORT: "http" }, /PORT must be a TCP port number/);
  });
});
