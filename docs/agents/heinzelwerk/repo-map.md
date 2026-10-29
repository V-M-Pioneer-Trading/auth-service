# Repo map: V-M-Pioneer-Trading/auth-service
Verified against 2d25f28 2026-10-29.

## Purpose
- Holds the SpaceTraders game credential, is the fleet's sole Clerk JWT verifier (introspection), mints Clerk M2M tokens. `package.json:5`, `README.md:3-10`
- Replaced the Go service; `contract/` pins Go behaviour, never edit it to make code pass. `CLAUDE.md:6-7`
- Design: `../meta/docs/design/auth-design.md` (`README.md:5`).
- Node >=24.15; start refused below it. `package.json:8`, `src/runtime.ts:7`

## Layout
- Controllers (tsoa, `tsoa.json`): `src/controllers/{vault,operator,introspect,m2m,health,status}.controller.ts`, glob `tsoa.json:4`.
- Vault + session gate: `src/vault.ts`. Poller: `src/poller.ts`. Introspection: `src/introspection.ts`. JWT: `src/jwt/verify.ts`, `src/keys.ts`.
- M2M: `src/m2m/clerk.ts`, `src/m2m/cache.ts`, `src/m2m/service.ts`, `src/m2m/token.ts`, `src/m2m/dev.ts`, `src/m2m/proxy.ts`.
- SpaceTraders client: `src/spacetraders/client.ts`. SQLite: `src/db/`.
- Dependencies reach controllers via `app.locals` accessors. `src/controllers/support.ts:11`
- Docs outside `docs/agents/`: `README.md`, `CLAUDE.md`, `contract/README.md`, `contract/fixtures/SOURCE.txt`, `src/__tests__/fixtures/SOURCE.txt`; no `docs/` dir (verified 2026-10-29 @ 2d25f28: ls).

## Entry points and auth
- GET `/auth/v1/token`: header `X-Auth-Service-Secret` = `AUTH_SERVICE_SHARED_SECRET`, SHA-256 + `timingSafeEqual`; 403 on mismatch; 503 text if no token. `src/vault.ts:73-76`, `src/vault.ts:90`, `src/vault.ts:104`, `src/controllers/vault.controller.ts:18-19`
- `?afterUnauthorized=true` forces a poll (10 s cooldown). `src/vault.ts:79-81`, `src/poller.ts:37`
- POST `/api/auth/v1/agent-token` (Restore Token) and `/api/auth/v1/register` (Reset Agent): Bearer Clerk JWT with scope `agent:reset`, verified in-process; 401 no/invalid bearer, 403 no scope. `src/controllers/operator.controller.ts:52`, `:63`, `:75`, `:86`; `src/vault.ts:136-141`
- POST `/auth/v1/introspect`: `X-Introspection-Secret` = `AUTH_INTROSPECTION_SECRET`, form body `token=<jwt>`, 8192 bytes max; 401 bad secret; `{active:false}` for anything unverifiable. `src/controllers/introspect.controller.ts:26`, `src/introspection.ts:24`, `:96-99`
- POST `/auth/v1/m2m-token`: `X-M2M-Caller-Secret`; callers automation-service (`fleet:control`), ai-service (`events:write planner:advise`); 401 unknown, 503 mint failed. `src/controllers/m2m.controller.ts:22-25`, `src/config.ts:33-34`

## Unauthenticated routes
- GET `/health`, `/api/auth/health`. `src/controllers/health.controller.ts:15`
- GET `/auth/v1/status`, `/api/auth/v1/status`; never returns a token. `src/controllers/status.controller.ts:8`
- CORS preflight on every path. `src/server.ts:116`
- Public via Caddy, all behind `X-Origin-Verify` (403 otherwise): only `/api/auth/v1/status`, `/agent-token`, `/register`, `/api/auth/health`; never `/auth/v1/token`. `../V-M-Pioneer-Trading_infrastructure/caddy/Caddyfile.tftpl:30`, `:38`, `:70-89`
- Host port loopback only, `127.0.0.1:3005`. `../V-M-Pioneer-Trading_infrastructure/auth-service/main.tf:468`

## Game-agent resets and paid calls
- No credit spending. SpaceTraders calls go via `{ST_GATEWAY_URL}/proxy`: GET `/` (unauthenticated) and POST `/register` with the account token as Bearer. `src/spacetraders/client.ts:1-3`, `:196-210`; `src/config.ts:276`
- Registration paths: Reset Agent route (`src/controllers/operator.controller.ts:88`); automatic re-registration after an observed `resetDate` change, from scheduled polls and from forced polls. `src/poller.ts:4-11`, `:178`, `:190-194`
- Poll cadence: daily, hourly from 24 h before predicted reset. `src/poller.ts:8-9`
- Paid Clerk call: POST `{CLERK_API_BASE_URL or https://api.clerk.com}/v1/m2m_tokens` with the machine key. `src/m2m/clerk.ts:5`, `:105`
- Mint cache until half of token life, 10 s backoff and timeout. `src/m2m/cache.ts:20-22`

## Calls and called-by
- Called by st-gateway for `/auth/v1/token`. `../st-gateway/src/authServiceClient.ts:65`
- Every other service asks `/introspect` through clerk-client. `CLAUDE.md:77-78` (clerk-client is not a dependency here)
- Vendored `contract/fixtures/introspection.json` = meta `../meta/fixtures/introspection.json`, fixture v7, meta f226e5f, sha256 pinned `contract/fixtures/SOURCE.txt:3-6`; asserted `src/__tests__/introspectionFixture.test.ts:204-212` and `contract/tests/introspect-fixture.test.ts`; `-text` in `.gitattributes:8`.
- `openapi.json` written by `scripts/write-openapi.cjs` (`package.json:16`); synced to meta `../meta/openapi/auth-service.json` `.github/workflows/container.yml:302-307`.
- Go parity fixtures: `src/__tests__/fixtures/SOURCE.txt:1-68`.

## Persistence
- `node:sqlite` at `SQLITE_DB_PATH` (default ./data/auth.db; /data/auth.db root-owned volume in prod). `src/config.ts:78-80`, `Dockerfile:35-40`
- Tables `credential` (id=1 only) and `registration_history`; `CREATE TABLE IF NOT EXISTS` each start, no migrations, Go-identical DDL for rollback. `src/db/schema.ts:1-24`

## Build, test, run
- `npm ci --ignore-scripts` (never plain); `npm run typecheck|lint|build`; `npm test` (pretest builds, `package.json:19`); one file `npm test -- src/__tests__/verifyToken.test.ts`. `CLAUDE.md:20-30`
- Contract locally: `docker build -t auth-service:contract .` then `CONTRACT_IMAGE=auth-service:contract node scripts/run-contract.cjs`. `CLAUDE.md:20-30`
- Run: `npm run build && node dist/server.js` or `docker compose up auth-service` from meta. `README.md:30-35`; dev secrets from `../meta/dev-keys` `README.md:37`
- Refuses start without `CLERK_JWT_KEY(_FILE)` or `AUTH_SERVICE_SHARED_SECRET`. `src/config.ts:116`, `:249`
- Defaults PORT 80, ./data/auth.db, `http://localhost:3002`. `src/config.ts:78-80`
- Git-ignored: `dist/`, src/generated/, `.env`, `data/`, `*.db` except `go-written.db`. `./.gitignore:2-12`
- Lockfiles `package-lock.json`, `contract/package-lock.json`. `.github/workflows/container.yml:79`, `:118`

## CI and deploy
- `.github/workflows/container.yml` triggers: pull_request, push main, tags `v*`, dispatch. `:7-13`
- `ts-checks` (`.github/workflows/container.yml:46`): `check:deps`, `npm audit --audit-level=high`. `:59-63`
- `test` (`.github/workflows/container.yml:66`, needs `ts-checks`): ci, typecheck, lint, build, openapi drift, `npm test`. `:82-100`
- `contract` (`.github/workflows/container.yml:107`, needs `ts-checks`): image build, Node >=24.15 and uid 0 probe, `contract/` ci + typecheck, `scripts/run-contract.cjs`. `:120-145`
- `docker` (`.github/workflows/container.yml:147`, needs `test` + `ts-checks`, not `contract`): push or dispatch on main, never PR; arm64; tip-of-main check; GHCR `sha-<long>`, `latest` only if tip; if tip, role `github-actions-ssm-deploy` and `aws ssm send-command` document `auth-service-bootstrap-i-011b6b82a9072a385` `--parameters imageTag=sha-<sha>`; 90 polls 10 s apart. `:150-297`, `:266-269`
- Only `docker` has `id-token: write`. `.github/workflows/container.yml:159-162`
- `v*` tag pushes `sha-<long>` image, never deploys. `CLAUDE.md:44-45`
- `sync-openapi` (`.github/workflows/container.yml:302`, needs `test`, non-PR on main): `../meta/.github/workflows/openapi-sync.yml@main`. `:303-307`
- Required checks `test`, `contract`, `ts-checks`; never rename. `.github/workflows/container.yml:41-42`, `CLAUDE.md:36-42`

## Patterns
- New route = tsoa controller; middleware order is load-bearing, no body or query parser. `src/server.ts:109-137`
- Each Go-parity piece has a recorded-verdict test. `CLAUDE.md:83-106`
- Lint: `eslint . --max-warnings 0` `package.json:14`; `base()` from eslint-config tarball v1.1.0 `eslint.config.mjs:1`, `package.json:32`; generated routes get `@ts-nocheck` `scripts/codegen.cjs:1-4`; strict tsconfig plus `exactOptionalPropertyTypes` `tsconfig.json`.

## Traps
- `contract/` never edited to pass; lint ignores it. `CLAUDE.md:6-7`, `eslint.config.mjs:5`
- Contract pins `suite=330 pass=293 dynamic-skips=37`. `contract-skip.expected:6-9`
- Never extend `scripts/cutover-probe.mjs` to call `register`/`agent-token` with an `agent:reset` session: resets the game account. `CLAUDE.md:52-53`
- Dependabot PR is red until `snapshot:deps` is committed. `CLAUDE.md:73`
- No WHATWG URL, `trim()`, `createPublicKey(pem)`, `URLSearchParams`, `express.urlencoded`, `JSON.parse` on Go-parity paths. `CLAUDE.md:108-115`
- Token answer has no `Cache-Control`: 15 contract cases pin it. `src/controllers/vault.controller.ts:28-30`
- Unset `AUTH_INTROSPECTION_SECRET` is legal; `/introspect` then rejects all. `src/config.ts:250-253`
- M2M caller secrets must differ from vault, introspection and each other. `src/config.ts:125-131`, `:177-187`
- Image runs as root. `./Dockerfile:35-37`
- Runtime test fails if `@hapi/` or `@types/` is loaded. `./Dockerfile:19-20`
