import http from "node:http";
import type { DatabaseSync } from "node:sqlite";
import express, { type ErrorRequestHandler, type Request, type RequestHandler } from "express";

import { ConfigError, loadConfig, type Config } from "./config";
import { CLOCK_LOCAL, CREDENTIALS_LOCAL, INTROSPECTION_LOCAL, VAULT_LOCAL } from "./controllers/support";
import { sqliteCredentialStore, type CredentialStore } from "./db/credential";
import { openDatabase } from "./db/database";
import { RegisterRoutes } from "./generated/routes";
import { CallerGone } from "./http/body";
import { corsHeaders } from "./http/cors";
import { goJson, sendText, TextAnswer } from "./http/json";
import type { IntrospectionDeps } from "./introspection";
import { createVerifier } from "./jwt/verify";
import { decodedPathOf, muxCompat, noHead, terminalAnswer } from "./http/muxCompat";
import { stderrLog, visible, type Logger } from "./log";
import { nodeTooOld } from "./runtime";
import { CLOSED_VAULT, startVault, type VaultDeps } from "./vault";

/**
 * How much of an unread request body is read, after the answer, to keep the connection (Go's maxPostHandlerReadBytes);
 * the wait for it is bounded too (UNREAD_BODY_WAIT_MS).
 */
export const UNREAD_BODY_ALLOWANCE = 256 << 10;
export const UNREAD_BODY_WAIT_MS = 1000;

/** How long a connection is read from, after its answer, before it is closed (Go: 500 ms). */
export const CLOSE_WAIT_MS = 500;

/**
 * An answer that leaves the request body unread must not make the server read it all (Node would discard any
 * amount) nor wedge the connection (the next request on it, other users' through a proxy, must still be served).
 * No listener is put on the socket, which would detach it from the HTTP parser: the request is resumed so that the
 * parser discards the body, and the bytes the socket has read are watched. Within the allowance and the wait the body
 * ends and the connection serves on; past either: Go's closeWriteAndWait, a FIN so that the answer is read, a short
 * wait (closing on unread data resets the connection and the caller loses the answer), then close.
 */
export const closeWhenBodyUnread: RequestHandler = (req, res, next) => {
  res.once("finish", () => {
    if (req.complete) return;
    const socket = req.socket;
    const start = socket.bytesRead;
    const t0 = Date.now();
    req.resume();
    const poll = setInterval(() => {
      if (req.complete || socket.destroyed) {
        clearInterval(poll);
        return;
      }
      if (socket.bytesRead - start <= UNREAD_BODY_ALLOWANCE && Date.now() - t0 < UNREAD_BODY_WAIT_MS) return;
      clearInterval(poll);
      socket.end();
      setTimeout(() => {
        socket.destroy();
      }, CLOSE_WAIT_MS).unref();
    }, 5);
    poll.unref();
  });
  next();
};

/** What Node answers a request it cannot parse, written with explicit CRLFs. */
export function clientErrorAnswer(err: NodeJS.ErrnoException): string {
  const status = err.code === "HPE_HEADER_OVERFLOW" ? "431 Request Header Fields Too Large" : "400 Bad Request";
  return "HTTP/1.1 " + status + "\r\nConnection: close\r\n\r\n";
}

/**
 * The server the process runs: reads are bounded (Go's `http.ListenAndServe` bounds nothing but the header size;
 * a slow caller is the one deliberate difference), and a check every second makes the header timeout 10 s, not 10 to
 * 40. It closes a connection that is too slow without a word (Node would answer 408), and it never sends
 * `100 Continue` by itself: a handler that reads a body sends it when it starts reading, so a caller who is refused
 * does not upload.
 */
export function createHttpServer(app: express.Express): http.Server {
  const server = http.createServer({ connectionsCheckingInterval: 1000, headersTimeout: 10_000, requestTimeout: 30_000, keepAliveTimeout: 120_000 }, app);
  server.on("checkContinue", (req, res) => {
    app(req as never, res as never);
  });
  server.on("clientError", (err: NodeJS.ErrnoException, socket) => {
    // Node's default: a socket that cannot be written to is closed.
    if (!socket.writable || socket.destroyed) {
      socket.destroy();
      return;
    }
    // A slow caller is closed, not answered; for the rest, what Node answers without a listener.
    if (err.code === "ERR_HTTP_REQUEST_TIMEOUT") socket.destroy();
    else socket.end(clientErrorAnswer(err));
  });
  return server;
}

export interface AppDeps {
  readonly corsAllowedOrigin: string;
  readonly credentials: CredentialStore;
  /** POST /auth/v1/introspect's secret and verifier. Without them the route refuses every caller (no secret). */
  readonly introspection?: IntrospectionDeps;
  /** Milliseconds since the epoch; the wall clock if not given. */
  readonly now?: () => number;
  /** One line per request, like the Go logging middleware; off unless given. */
  readonly log?: Logger;
  /** The vault (step 7c): GET /auth/v1/token and the operator routes. Without it every caller is refused. */
  readonly vault?: VaultDeps;
}

/**
 * Builds the app. Order is load-bearing:
 *
 *  1. closeWhenBodyUnread: an answer that leaves the request body unread closes the connection, as Go's server does.
 *  2. goJson: Go's JSON content type, which tsoa's generated routes would otherwise write with a charset.
 *  3. muxCompat: 400 / 301 / decoded routing, before anything else can answer.
 *  4. the request line, path only.
 *  5. CORS: constants on every response a matched route produces; a preflight is answered here, on every path.
 *  6. noHead: HEAD is never routed.
 *  7. the routes (tsoa's generated registration).
 *  8. the terminal answer: 404 / 405 exactly as the Go router gives them.
 *  9. the error handler.
 *
 * No body parser is mounted and Express' query parser is off: a handler that wants a body or a query reads it itself,
 * with Go's semantics (the contract README, notes 18-22).
 */
export function createApp(deps: AppDeps): express.Express {
  const app = express();
  app.locals[CREDENTIALS_LOCAL] = deps.credentials;
  app.locals[CLOCK_LOCAL] = deps.now ?? Date.now;
  app.locals[INTROSPECTION_LOCAL] = deps.introspection ?? { secret: "", verifier: () => Promise.resolve(null) };
  app.locals[VAULT_LOCAL] = deps.vault ?? CLOSED_VAULT;
  app.disable("x-powered-by");
  app.set("etag", false);
  // mux is case sensitive and tolerates no trailing slash.
  app.set("case sensitive routing", true);
  app.set("strict routing", true);
  app.set("query parser", false);

  app.use(closeWhenBodyUnread);
  app.use(goJson);
  app.use(muxCompat);
  if (deps.log !== undefined) {
    const log = deps.log;
    app.use((req: Request, _res, next) => {
      // The decoded path only, never the query string: a token mistakenly sent in one must not reach a log sink.
      log(`${req.method} request: to ${visible(decodedPathOf(req).toString("utf8"))}`);
      next();
    });
  }
  app.use(corsHeaders(deps.corsAllowedOrigin));
  app.use(noHead);
  RegisterRoutes(app);
  app.use(terminalAnswer);

  const onError: ErrorRequestHandler = (err: unknown, _req, res, next) => {
    // The caller hung up while its body was being read: nobody is left to answer.
    if (err instanceof CallerGone) return;
    if (res.headersSent) {
      next(err);
      return;
    }
    if (err instanceof TextAnswer) {
      sendText(res, err.status, err.body);
      return;
    }
    console.error(err);
    sendText(res, 500, "Internal Server Error");
  };
  app.use(onError);
  return app;
}

/** Startup. Every refusal exits 1 before a port is bound, like log.Fatal in Go. */
export function main(env: NodeJS.ProcessEnv = process.env): void {
  const tooOld = nodeTooOld(process.versions.node);
  if (tooOld !== undefined) {
    console.error(tooOld);
    process.exit(1);
  }
  let config: Config;
  let db: DatabaseSync;
  try {
    config = loadConfig(env, stderrLog);
    db = openDatabase(config.sqlitePath, stderrLog);
  } catch (err) {
    console.error(err instanceof ConfigError ? err.message : err instanceof Error ? err.message : err);
    process.exit(1);
  }

  // The vault's poller starts before the listener, as Go's `go p.Run(ctx)` does.
  const vault = startVault(db, { sharedSecret: config.sharedSecret, gatewayProxyUrl: config.gatewayProxyUrl, log: stderrLog });
  const app = createApp({
    corsAllowedOrigin: config.corsAllowedOrigin,
    credentials: sqliteCredentialStore(db),
    introspection: { secret: config.introspectionSecret, verifier: createVerifier({ key: config.clerkJwtKey, issuer: config.clerkIssuer }) },
    log: stderrLog,
    vault: vault.deps,
  });
  const server = createHttpServer(app);
  server.listen(config.port, () => {
    stderrLog(`auth-service listening on :${String(config.port)}`);
  });
  server.on("error", (err) => {
    console.error(err);
    process.exit(1);
  });

  const shutdown = (signal: string): void => {
    stderrLog(`received ${signal}, shutting down`);
    // The poller first: its wait ends and an upstream call in flight is abandoned, so no request waits on one.
    const vaultStopped = vault.stop();
    server.close(() => {
      void vaultStopped.then(() => {
        db.close();
        process.exit(0);
      });
    });
    server.closeIdleConnections();
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.once(signal, () => {
      shutdown(signal);
    });
  }
}

if (require.main === module) main();
