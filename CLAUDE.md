# CLAUDE.md

Contributor and agent notes for auth-service, the TypeScript service (meta#103, auth-design.md decision 23). It replaced
the Go service at the cutover (auth-service#17): the Go code is deleted from `main` and lives in history, the last Go
commit being `8a09f84d8898e4e1bd1428cce264250ab9ce78d1`. Comments that name `src/api/m2m.go`, `src/db/db.go` and the like
point at that commit (`git show 8a09f84:src/api/m2m.go`). The service's behaviour is pinned to Go's by the black-box suite
in `contract/` (never edited to make code pass). Many comments say "like Go": read them as "as the contract suite and the
Go source pin it". README.md has what an operator needs: deploy, rollback, the SQLite `/data` volume, environment
variables and secrets.

Step 7a (the scaffold) ported: health, status, CORS, the router's 404/405/301 table, every startup refusal, SQLite.
Step 7b ported Clerk JWT verification (`src/jwt/verify.ts`, `jose`) and `POST /auth/v1/introspect`
(`src/introspection.ts`, `controllers/introspect.controller.ts`). Step 7c ported the vault: `GET /auth/v1/token`, Restore
Token and Reset Agent (`src/vault.ts`, `controllers/vault.controller.ts`, `operator.controller.ts`), the poller
(`src/poller.ts`), the SpaceTraders client (`src/spacetraders/client.ts`) and the row's writes (`src/db/credential.ts`).
The operator routes call the introspection verifier in-process (decision 21: one verification code path). Step 7d
ported `POST /auth/v1/m2m-token` (decision 22: `src/m2m/`, `controllers/m2m.controller.ts`). Every route is ported: the
contract skip list is empty. The cutover PR (auth-service#17) moved the package to the repository root and deleted the Go code.

## Commands (from the repository root)

| Task | Command |
|---|---|
| Install | `npm ci --ignore-scripts` (never plain `npm ci`, never `npm install` in CI) |
| Test one file | `npm test -- src/__tests__/verifyToken.test.ts` (`npm test` runs Jest under `--experimental-vm-modules`: `jose` is ESM-only, and Jest loads it with Node's `require(esm)` only so; the built service needs no flag) |
| Typecheck / lint / build / test | `npm run typecheck` / `npm run lint` / `npm run build` / `npm test` |
| Regenerate the OpenAPI spec | `npm run openapi` (CI fails on drift in `openapi.json`) |
| Dependency gate | `npm run check:deps`; after any change to `package-lock.json`, `npm run snapshot:deps` and review the diff |
| Contract suite against the image | `docker build -t auth-service:contract .` then `CONTRACT_IMAGE=auth-service:contract node scripts/run-contract.cjs` |
| Production probe (after a deploy) | `node scripts/cutover-probe.mjs --dry-run` lists it; see its header and `scripts/cutover-*.ps1` |

Node 24.15 or later: `node:sqlite` is a release candidate from there (experimental before), and `src/runtime.ts` refuses to
start below it. The image is `gcr.io/distroless/nodejs24-debian13` (the debian12 tag is frozen at Node 24.14), running as
root like the Go image did: `/data/auth.db` is root-owned.

## CI and the required checks

`.github/workflows/container.yml` has four jobs. **`ts-checks`** (the dependency gate and `npm audit`), **`test`** (typecheck,
lint, build, the `openapi.json` freshness check, Jest) and **`contract`** (the black-box suite against the image the root
Dockerfile builds, judged by `scripts/run-contract.cjs`) are the checks branch protection requires on `main`
(`enforce_admins` on): never rename or drop one without changing the protection in the same step, because a required check
that no job reports blocks every merge. `test` and `contract` wait for `ts-checks`, so nothing is installed from a lockfile
the gate has not passed. **`docker`** builds the arm64 image and, on `main` only, tags `:latest` and redeploys through SSM
(tip-of-main check, one deploy at a time); it waits for `test` and `ts-checks`, not for `contract`. A `v*` tag pushes
`sha-<40 hex>` and never deploys: that is how a pull request's tip gets an image to deploy by hand and probe.

## Production probe

`scripts/cutover-probe.mjs` (with `__tests__/cutoverProbe.test.ts`, stub-backed) probes the public domain: the public auth
routes, the operator routes' refusals, and every introspection caller. Its output is status codes and member names only,
never a token, a bearer or a body, and it never calls `/auth/v1/token`, `/auth/v1/m2m-token` or `/auth/v1/introspect`.
**Never extend it to call `register` or `agent-token` with a session that may hold `agent:reset`: that resets the game
account.** It cannot tell the Go image from this one, so after any deploy that matters, `docker inspect auth-service` on the
host is the gate (`scripts/cutover-deploy-rc.ps1` and `scripts/cutover-hostcheck.ps1` run it through SSM).

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
| the vault's writes, same statements, Go's `formatTime` | `src/db/credential.ts` | `vaultStore.test.ts`, writes onto the Go-written file; a TS-written file served by the Go image (PR #15's evidence) |
| `encoding/json` as the vault uses it: `Decoder.Decode` (first value) for the operator bodies, `Unmarshal` for SpaceTraders' answers, key folding, `int` | `src/goJson.ts` | `vaultParity.test.ts` against 160 bodies Go decoded four ways (`go-vault-recorder.go.txt`) |
| `parseFlexibleTime` (RFC 3339, else a bare date), `Time.Equal` to the nanosecond | `src/spacetraders/client.ts`, `src/goTime.ts` | `vaultParity.test.ts`, 40 dates |
| the poller: cadence, forced polls and their 10 s cooldown, wipe detection, re-registration, APP_TOKEN_EXPIRED | `src/poller.ts`, `src/state/machine.ts` | `poller.test.ts` on a fake clock with a stubbed st-gateway; contract `poller.test.ts` |
| the token route, the session gate, Restore Token, Reset Agent | `src/vault.ts` | `vault.test.ts`; contract `vault.test.ts`, `register.test.ts` |
| M2M: `cacheEntryFrom`, the decode of Clerk's answer (`encoding/json` field folding, first value, 64 KiB), `ProxyFromEnvironment` | `src/m2m/token.ts`, `goJson.ts`, `clerk.ts`, `proxy.ts` | `m2mGoParity.test.ts` against Go's recorded verdicts (80 tokens, 58 bodies, 1140 proxy decisions) |
| M2M: the per-caller cache (single flight, detached mint, refresh at half life, 10 s backoff, 10 s timeout, expiry) | `src/m2m/cache.ts` | `m2mCache.test.ts` on a fake clock; contract `m2m-clerk*.test.ts` |
| M2M: the route, both trust anchors, the Clerk request, redirects, the log | `src/m2m/service.ts`, `dev.ts`, `clerk.ts` | `m2m.test.ts` against a Clerk stub on a socket; contract `m2m-*.test.ts`, `startup.test.ts` |

Never `url.Parse` through WHATWG `URL`, never `trim()` for Go's TrimSpace, never `createPublicKey(pem)` directly: each
answers differently from Go on inputs the contract pins. Never `URLSearchParams` or `express.urlencoded` for the
introspection form (no `;` error, no sticky escape error), never `req.headers[...]` for the introspection secret (Node
joins repeats), and never `jwtVerify` without `verify.ts`'s Go checks around it (it reads padding, whitespace, a BOM and
1e400 that golang-jwt refuses, and judges a fractional `exp` up to a second longer). Never `JSON.parse` for an operator
route's body or a SpaceTraders answer (`src/goJson.ts`: Go ignores what follows the first value of a body, folds key
case, keeps the last duplicate, and refuses `1.0` for an int), and never log an `UpstreamError`'s body or an error's
text other than through `describeError` (upstream's body can hold anything). Never `JSON.parse` alone for Clerk's
answer or a minted token's payload either (`m2m/goJson.ts`, the same rules for the mint's two readers; the two
modules are separate, see "Follow-ups"), never `fetch` for the mint (it follows redirects, and the Machine Secret Key
must not), and never a request signal on the mint (it is detached: only its own 10 s timeout cancels it). The vault's
SpaceTraders calls do use `fetch`, with `redirect: "manual"` and Go's redirect policy by hand; never `new URL(location,
base)` for a Location (WHATWG reads `///h`, `/\h`, `http:\\h` as another host where Go reads a path or refuses):
`spacetraders/location.ts` assembles the URL from Go's parts and checks it round-trips.

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
  `crit` header is rejected; `GET /auth/v1/token`'s secret compares in constant time. The constant-time compare is
  done (SHA-256 of each side, `timingSafeEqual`; still 403). `no-store` on the token answer is NOT added: 15 cases of
  the contract suite pin its absence (only one accepts either), and contract/ is not edited by a port.
* Token verification is stricter than Go's, never looser (each case pinned against Go's recorded answer): any `crit` but
  `["b64"]` with `b64: true` (decision 23); an RSA key under 2048 bits makes every token inactive (jose's floor for RS256,
  Go has none; no startup refusal is added in the port, a follow-up after cutover); a present `iat` that is not a number;
  claims that are not valid UTF-8 (Go substitutes U+FFFD); a fractional `nbf` inside the last second of the leeway; an
  `nbf` so large that Go's int64 conversion wraps it into the past. None is producible by Clerk.
* Machine tokens (7d): the mint request is HTTP/1.1 without Go's `User-Agent: Go-http-client/1.1` and
  `Accept-Encoding: gzip` (Go would also try HTTP/2 to api.clerk.com); a `socks5://` proxy (which Go dials) fails the
  mint instead; a transport failure is logged by its error code, not Go's error text. The proxy choice itself is Go's.

* The vault (7c):
  * Polls and operator writes never interleave: scheduled, forced and post-registration polls, Restore Token and Reset
    Agent all run on one queue (`Poller.exclusive`). Go ran them on separate goroutines, and two interleavings lost an
    operator's write (a Restore Token undone by a forced poll's expired flag; a Reset Agent overwritten by a
    re-registration of the old account). A forced poll inside the cooldown still returns at once; one outside it waits
    for what is in flight, so behind a stuck upstream call it can take up to two 30 s timeouts (Go: one). Reset Agent
    can take four (a poll ahead of it: the root and a re-registration; then its own registration and the poll after
    it), about two minutes, and every further item already queued adds its bound. An operator write whose caller hung
    up while it waited is dropped before it sends or writes anything; once a registration has been sent it is stored.
    Restore Token is stamped with the time it is written. The cooldown runs on a monotonic clock, as Go's.
  * An operator route reads at most 1 MiB of body; a first JSON value that does not end within it is `400 invalid request
    body: http: request body too large` (Go read the first value without a bound). Nesting deeper than 10000 is Go's
    `invalid character '[' exceeded max depth`; the parser is iterative, so no depth reaches the call stack.
  * The bearer credential is parsed as clerk-client's `bearerFrom` (owner, auth-service#15). Node reads the header as
    latin1, so a lone byte 0xA0 separates the scheme from the token here and not in Go, while a UTF-8 non-ASCII space
    (C2 A0, C2 85, ...) separates in Go and not here. ASCII whitespace is the same. Scopes split on SP, TAB, CR, LF only.
  * Log lines about upstream failures name the call and the status (`spacetraders upstream error (503) on GET /`) or the
    error code, never upstream's body or Go's error text. A 502's text is `POST /register: request failed (CODE)`.
  * Redirects are followed by hand, as Go 1.22's client follows them (`spacetraders/client.ts` `follow`): a 3xx WITH a
    Location is followed, one without is the answer as it stands (Go returns it); 301/302/303 turn a POST into a GET
    without a body (Content-Type kept, as Go copies it), 307/308 repeat it; the 10th redirect is refused (`stopped after
    10 redirects`, a 502), an unreadable Location first (`failed to parse Location header`). The Location is read by
    Go's url.Parse and ResolveReference rules (`spacetraders/location.ts`, agent-service's, verbatim): userinfo, a scheme
    without a host and anything but http(s) are refused. Stricter than Go: `Authorization` (the account token) goes only
    to the host the call started at, compared byte for byte as written and as fetched, never over https to http, and
    once a hop has left that host never again in the chain; a request body (the register call) is never sent to another
    host (a 307/308 that would is refused); no Referer is added.
  * JSON answers are Go's bytes (`http/json.ts` `goMarshal`): `<`, `>`, `&`, U+2028 and U+2029 escaped as Go escapes them.
  * `updated_at` and `occurred_at` are written in UTC (Go: the local zone, UTC in the image). Nothing reads them.
  * A non-ASCII account token is sent as its UTF-8 bytes, as Go sends it; a control character fails the call before it
    is sent, as in Go.

## Follow-ups

* Two Go `encoding/json` readers: `src/goJson.ts` (the vault: Decoder and Unmarshal into string/int/nested-struct
  shapes, an iterative parser with Go's error wording) and `m2m/goJson.ts` (the mint: an incremental scanner for a
  64 KiB-limited stream, string and float-pointer fields). Their scanning, UTF-8 and key folding are the same rules
  written twice; one module serving both shapes, held to both verdict files, is the cleanup. Not done in 7c because
  their interfaces differ (incremental "more" scanning, pointer fields) and each is pinned by its own Go corpus.

## Invariants

1. No SpaceTraders credential, key or secret is logged, echoed in a refusal, or placed in an error message.
2. A route with no controller does not exist (the contract suite's skip list, `contract-skip.txt`, is empty and stays so).
3. The schema does not change in the port; a rollback to the Go image must open the file.
4. `contract/` is never edited to make code pass; a change to it is a deliberate change of the contract. (The cutover PR touched only its fixture path and README.)

---

Update this file in the same PR as the change it describes.
