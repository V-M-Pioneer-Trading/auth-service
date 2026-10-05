# CLAUDE.md (ts/)

Contributor and agent notes for the TypeScript port of auth-service (meta#103, auth-design.md decision 23). The Go
service in `../src` is what runs in production until the cutover (auth-service#17); this package is built beside it, and
its behaviour is pinned to Go's by the black-box suite in `../contract` (never edited to make code pass). Many comments
say "like Go": read them as "as the contract suite and the Go source pin it".

Step 7a (the scaffold) ported: health, status, CORS, the router's 404/405/301 table, every startup refusal, SQLite.
Step 7b ported Clerk JWT verification (`src/jwt/verify.ts`, `jose`) and `POST /auth/v1/introspect`
(`src/introspection.ts`, `controllers/introspect.controller.ts`). Step 7d ported `POST /auth/v1/m2m-token` (decision
22: `src/m2m/`, `controllers/m2m.controller.ts`). Not ported, and deliberately unregistered so the contract skip list
covers them: the vault, register, restore and the poller (7c). The vault's operator routes must call the same
`createVerifier` function in-process (decision 21: one verification code path).

## Commands (from `ts/`)

| Task | Command |
|---|---|
| Install | `npm ci --ignore-scripts` (never plain `npm ci`, never `npm install` in CI) |
| Test one file | `npm test -- src/__tests__/verifyToken.test.ts` (`npm test` runs Jest under `--experimental-vm-modules`: `jose` is ESM-only, and Jest loads it with Node's `require(esm)` only so; the built service needs no flag) |
| Typecheck / lint / build / test | `npm run typecheck` / `npm run lint` / `npm run build` / `npm test` |
| Regenerate the OpenAPI spec | `npm run openapi` (CI fails on drift in `openapi.json`) |
| Dependency gate | `npm run check:deps`; after any change to `package-lock.json`, `npm run snapshot:deps` and review the diff |
| Contract suite against the image | `docker build -t auth-service:contract-ts .` then `CONTRACT_IMAGE=auth-service:contract-ts node scripts/run-contract.cjs` |

Node 24.15 or later: `node:sqlite` is a release candidate from there (experimental before), and `src/runtime.ts` refuses to
start below it. The image is `gcr.io/distroless/nodejs24-debian13` (the debian12 tag is frozen at Node 24.14), running as
root like the Go image: `/data/auth.db` is root-owned.

## The dependency gate (the mitigation decision 23 accepts the npm risk on)

* `allowed-dependencies.txt`: direct dependencies, per section, exactly. A new line is the first review point.
* `dependency-snapshot.txt`: every package in the lockfile, `[runtime]` (what the image ships) and `[dev]`, with version and
  integrity. CI fails when the lockfile gains, loses or changes any package the file does not say. The second review
  point, and the one that shows what a dependency brings with it. Read `[runtime]`.
* `scripts/check-dependencies.cjs` also refuses: specs that are not plain semver (the eslint-config release tarball is the
  one exception, in devDependencies); a `resolved` that is not **exactly** `https://registry.npmjs.org/<name>/-/<basename>-<version>.tgz`
  for the entry's name (from its lock path) and version (npm ci installs what `resolved` says, so a `..`, another package
  or another version riding on an honest name and version is refused); one name@version with two integrities at two lock
  paths (reported, never merged); renamed or aliased lock entries; missing sha512; `overrides`, `.npmrc`, bundled
  dependencies, `workspaces` and `link: true` entries; and in `[runtime]` any install script or platform binary.
  `[runtime]` is everything but `dev: true`: `devOptional` packages are installed by `npm ci --omit=dev`.
* The Dockerfile's `deps` stage installs with `--omit=dev --omit=optional`, fails on compiled code in the production tree
  (`scripts/find-native.cjs`: by extension and by ELF, Mach-O, PE and WebAssembly magic bytes, so a rename hides nothing),
  then deletes `node_modules/@hapi` and `node_modules/@types`. Both base images are pinned by digest (Dependabot's docker
  ecosystem bumps them).
* A Dependabot PR is red until `npm run snapshot:deps` is committed to it. That is the point.
* Known cost: `@tsoa/runtime` depends on `@hapi/*` (about 30 packages) though only Express is used. It is in `[runtime]` of
  the lockfile and snapshot but never loaded and not in the image: `runtimeTree.test.ts` boots `dist/server.js` and fails if
  anything under `@hapi` or `@types` is required (so `npm test` builds first).
* `jose` (7b) is pinned exactly, has no dependencies and no install script: one line in `[runtime]`. `clerk-client` is not a
  dependency (auth-service is the verifier; clerk-client is how the others ask it).
* The eslint-config release tarball is the only lock entry that may resolve to a release asset, its `resolved` must equal
  package.json's URL and its version the tag's: npm ci fetches package.json's URL and skips the lockfile's integrity when
  the two differ, so a lockfile-only edit would otherwise void the pin.

## Where Go is reproduced, and how it is proven

| Piece | File | Proof |
|---|---|---|
| env, defaults, startup refusals, their order | `src/config.ts` | `config.test.ts`; contract `startup.test.ts` |
| `url.Parse` verdict of CLERK_API_BASE_URL | `src/goUrl.ts` | `goParity.test.ts` against recorded Go 1.22.4 verdicts |
| `strings.TrimSpace` set | `src/goText.ts` | same |
| golang-jwt PEM readers (DER lengths, getLine on the END line) | `src/keys.ts` | same, 80 spellings |
| golang-jwt verifyToken (with jose) | `src/jwt/verify.ts` | `verifyToken.test.ts`: 179 tokens against Go's recorded answers, deviations named |
| `mime.ParseMediaType`, `url.ParseQuery` (ParseForm) | `src/http/goForm.ts` | `goParity.test.ts`, 64 content types and 38 queries |
| the introspection handler, MaxBytesReader, 100-continue | `src/introspection.ts`, `src/http/body.ts` | `introspect.test.ts`; contract `introspect*.test.ts` |
| the server-side fixture conformance test | — | `introspectionFixture.test.ts` against the vendored fixture v6, sha256-pinned |
| `time.Parse(RFC3339)` / `Format` | `src/goTime.ts` | `goParity.test.ts` |
| gorilla/mux and net/http artefacts | `src/http/muxCompat.ts`, `cors.ts`, `json.ts` | `app.test.ts`; contract `routing.test.ts` |
| server hardening (unread bodies, timeouts, parse errors) | `src/server.ts` | `connections.test.ts` |
| SQLite, same DDL | `src/db/` | `db.test.ts` against a file the Go image's `db` package wrote |
| M2M: `cacheEntryFrom`, the decode of Clerk's answer (`encoding/json` field folding, first value, 64 KiB), `ProxyFromEnvironment` | `src/m2m/token.ts`, `goJson.ts`, `clerk.ts`, `proxy.ts` | `m2mGoParity.test.ts` against Go's recorded verdicts (80 tokens, 58 bodies, 1140 proxy decisions) |
| M2M: the per-caller cache (single flight, detached mint, refresh at half life, 10 s backoff, 10 s timeout, expiry) | `src/m2m/cache.ts` | `m2mCache.test.ts` on a fake clock; contract `m2m-clerk*.test.ts` |
| M2M: the route, both trust anchors, the Clerk request, redirects, the log | `src/m2m/service.ts`, `dev.ts`, `clerk.ts` | `m2m.test.ts` against a Clerk stub on a socket; contract `m2m-*.test.ts`, `startup.test.ts` |

Never `url.Parse` through WHATWG `URL`, never `trim()` for Go's TrimSpace, never `createPublicKey(pem)` directly: each
answers differently from Go on inputs the contract pins. Never `URLSearchParams` or `express.urlencoded` for the
introspection form (no `;` error, no sticky escape error), never `req.headers[...]` for the introspection secret (Node
joins repeats), and never `jwtVerify` without `verify.ts`'s Go checks around it (it reads padding, whitespace, a BOM and
1e400 that golang-jwt refuses, and judges a fractional `exp` up to a second longer). Never `JSON.parse` alone for
Clerk's answer or a minted token's payload (`m2m/goJson.ts`: Go folds field names, takes the last of two spellings, and
reads only the first value), never `fetch` for the mint (it follows redirects, and the Machine Secret Key must not), and
never a request signal on the mint (it is detached: only its own 10 s timeout cancels it).

## Deliberate differences from Go

* Config is read before the database is opened (Go opens it first): an invalid configuration no longer creates `/data/auth.db`.
* Slow callers are bounded (10 s for headers, 30 s for a request, 120 s idle); Go's `ListenAndServe` bounds none.
* The request log line is written for every request, including the router's own 404/405 (Go logs matched routes only).
  Control characters in a path are escaped. Path only, never the query.
* A start-up line `auth-service listening on :PORT`.
* Node below 24.15 is refused at start.
* `PORT` must be digits up to 65535. Go's `":" + port` also accepts a service name (`http`, `https`), a leading space
  and a leading `+`; those are refused here (Node would take a word for a pipe name). Checked against a corpus of 4329
  Go verdicts for the config: these four are the only differences.
* PEM keys follow golang-jwt exactly, including: bytes after the DER structure are refused for a public key and for a
  PKCS#1 private key but accepted for a PKCS#8 private key; the END line must start a line and the first END decides.
* Accepted by the owner (decision 23): `Cache-Control: no-store` may be added to `GET /auth/v1/token`; a JWT with an unknown
  `crit` header is rejected; `GET /auth/v1/token`'s secret compares in constant time.
* Token verification is stricter than Go's, never looser (each case pinned against Go's recorded answer): any `crit` but
  `["b64"]` with `b64: true` (decision 23); an RSA key under 2048 bits makes every token inactive (jose's floor for RS256,
  Go has none; no startup refusal is added in the port, a follow-up after cutover); a present `iat` that is not a number;
  claims that are not valid UTF-8 (Go substitutes U+FFFD); a fractional `nbf` inside the last second of the leeway; an
  `nbf` so large that Go's int64 conversion wraps it into the past. None is producible by Clerk.
* Machine tokens (7d): the mint request is HTTP/1.1 without Go's `User-Agent: Go-http-client/1.1` and
  `Accept-Encoding: gzip` (Go would also try HTTP/2 to api.clerk.com); a `socks5://` proxy (which Go dials) fails the
  mint instead; a transport failure is logged by its error code, not Go's error text. The proxy choice itself is Go's.

## Invariants

1. No SpaceTraders credential, key or secret is logged, echoed in a refusal, or placed in an error message.
2. A route with no controller does not exist: the contract's skip list is the only record of what is not ported.
3. The schema does not change in the port; a rollback to the Go image must open the file.
4. `contract/` is never edited by a port PR.

---

Update this file in the same PR as the change it describes.
