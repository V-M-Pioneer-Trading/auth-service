# CLAUDE.md (ts/)

Contributor and agent notes for the TypeScript port of auth-service (meta#103, auth-design.md decision 23). The Go
service in `../src` is what runs in production until the cutover (auth-service#17); this package is built beside it, and
its behaviour is pinned to Go's by the black-box suite in `../contract` (never edited to make code pass). Many comments
say "like Go": read them as "as the contract suite and the Go source pin it".

Step 7a (this scaffold) ports: health, status, CORS, the router's 404/405/301 table, every startup refusal, SQLite.
Not ported, and deliberately unregistered so the contract skip list covers them: introspection (7b), the vault, register,
restore and the poller (7c), machine tokens (7d). No JWT is verified anywhere in this package yet.

## Commands (from `ts/`)

| Task | Command |
|---|---|
| Install | `npm ci --ignore-scripts` (never plain `npm ci`, never `npm install` in CI) |
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
  one exception, in devDependencies), registries other than registry.npmjs.org, renamed or aliased lock entries, missing
  sha512, `overrides`, `.npmrc`, bundled dependencies, and in `[runtime]` any install script or platform binary. The
  Dockerfile's `deps` stage fails on a compiled file in the production tree.
* A Dependabot PR is red until `npm run snapshot:deps` is committed to it. That is the point.
* Known cost: `@tsoa/runtime` depends on `@hapi/*` (about 30 packages) though only Express is used. It is in `[runtime]`.
* `jose` joins in 7b; `clerk-client` is not a dependency (auth-service is the verifier; clerk-client is how the others ask it).

## Where Go is reproduced, and how it is proven

| Piece | File | Proof |
|---|---|---|
| env, defaults, startup refusals, their order | `src/config.ts` | `config.test.ts`; contract `startup.test.ts` |
| `url.Parse` verdict of CLERK_API_BASE_URL | `src/goUrl.ts` | `goParity.test.ts` against recorded Go 1.22.4 verdicts |
| `strings.TrimSpace` set | `src/goText.ts` | same |
| golang-jwt PEM readers | `src/keys.ts` | same, 52 spellings |
| `time.Parse(RFC3339)` / `Format` | `src/goTime.ts` | same |
| gorilla/mux and net/http artefacts | `src/http/muxCompat.ts`, `cors.ts`, `json.ts` | `app.test.ts`; contract `routing.test.ts` |
| server hardening (unread bodies, timeouts, parse errors) | `src/server.ts` | `connections.test.ts` |
| SQLite, same DDL | `src/db/` | `db.test.ts` against a file the Go image's `db` package wrote |

Never `url.Parse` through WHATWG `URL`, never `trim()` for Go's TrimSpace, never `createPublicKey(pem)` directly: each
answers differently from Go on inputs the contract pins.

## Deliberate differences from Go

* Config is read before the database is opened (Go opens it first): an invalid configuration no longer creates `/data/auth.db`.
* Slow callers are bounded (10 s for headers, 30 s for a request, 120 s idle); Go's `ListenAndServe` bounds none.
* The request log line is written for every request, including the router's own 404/405 (Go logs matched routes only).
  Control characters in a path are escaped. Path only, never the query.
* A start-up line `auth-service listening on :PORT`.
* Node below 24.15 is refused at start.
* Accepted by the owner (decision 23): `Cache-Control: no-store` may be added to `GET /auth/v1/token`; a JWT with an unknown
  `crit` header is rejected; `GET /auth/v1/token`'s secret compares in constant time.

## Invariants

1. No SpaceTraders credential, key or secret is logged, echoed in a refusal, or placed in an error message.
2. A route with no controller does not exist: the contract's skip list is the only record of what is not ported.
3. The schema does not change in the port; a rollback to the Go image must open the file.
4. `contract/` is never edited by a port PR.

---

Update this file in the same PR as the change it describes.
