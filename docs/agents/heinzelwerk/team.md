# Team rules

How heinzelwerk agents work in this repo. Mode rules (single repo vs workspace) live in the `heinzelwerk:team-modes` skill. This file holds only what is specific to this repo.

- **Autonomy**: full. Agents merge and apply on their own; breakages are learnings. Secrets are never published (name the variable, never the value); the gate never merges its own policy.
- **Backend paths**: whole repo except `contract/` (`src/`, `scripts/`, `Dockerfile`, `openapi.json`, `.github/`)
- **Worktree setup** (run once in every new task worktree): `npm ci --ignore-scripts`
- **Checks** (validator runs every one, in order; copied from CI, quiet flags only):
  - `npm run check:deps`
  - `npm audit --audit-level=high (red on main: V-M-Pioneer-Trading/meta#136)`
  - `npm run typecheck`
  - `npm run lint`
  - `npm run build`
  - `npm run openapi && test -z "$(git status --porcelain -- openapi.json)"`
  - `npm test`
  - contract job, `.github/workflows/container.yml` steps "Build the image under test" through "Run the contract suite against the image", each run as written (the Node ≥24.15/root probe is a multi-line step: copy it to a temp script) `(unverified locally: docker daemon not running)`
  - `docker buildx build --platform linux/arm64 . (unverified locally: docker daemon not running)`
- **Verified against**: 2d25f28 2026-10-29 (checks and every ref in this file; retro bumps it)
- **Coding standards**: `eslint.config.mjs:1` (shared `base` from `@v-m-pioneer-trading/eslint-config`, `package.json:32`), `eslint . --max-warnings 0` (`package.json:14`); `CLAUDE.md` "## Invariants" (:193); "Where Go is reproduced" rules (`CLAUDE.md:83`)
- **Risk areas** (validator reviews diffs touching these on Opus):
  - `src/vault.ts:73-81`, `src/controllers/vault.controller.ts:34`: `GET /auth/v1/token` returns the game credential; shared-secret compare, bare path only, never routed publicly (`../V-M-Pioneer-Trading_infrastructure/caddy/Caddyfile.tftpl:70-89`)
  - `src/introspection.ts:96-99`, `src/jwt/verify.ts`, `src/keys.ts`: verify every token in the fleet; an error here is an auth bypass fleet-wide; stricter than Go, never looser (`CLAUDE.md:123`)
  - `src/vault.ts:136-141`, `src/controllers/operator.controller.ts:52-88`: `POST /api/auth/v1/agent-token` and `/register` (Reset Agent) need scope `agent:reset`; Reset Agent resets the game account
  - `src/poller.ts:178-194`: automatic re-registration after a `resetDate` change re-mints the game agent, also reachable from forced polls (`GET /auth/v1/token?afterUnauthorized=true`)
  - `scripts/cutover-probe.mjs`: never make it call `register` or `agent-token` with an `agent:reset` session (`CLAUDE.md:52-53`)
  - `src/controllers/m2m.controller.ts:22`, `src/m2m/clerk.ts:105`: `POST /auth/v1/m2m-token` mints machine tokens via a paid Clerk call; caller table `src/config.ts:33-34`; caller secrets must differ from vault, introspection and each other (`src/config.ts:125-131`, `:177-187`)
  - `src/config.ts:116`, `:249-253`: startup refusals; unset `AUTH_INTROSPECTION_SECRET` is legal and makes `/introspect` reject everyone
  - `src/db/schema.ts:1-24`: SQLite `credential` and `registration_history`, no migrations, Go-identical DDL for rollback; image runs as root on a root-owned volume (`Dockerfile:35-37`)
  - `contract/**`: pinned parity suite; never edit to make code pass (`CLAUDE.md:6-7`, `:198`); `contract-skip.expected:6-9` pins counts
  - `contract/fixtures/introspection.json`: sha256-pinned vendored copy (`contract/fixtures/SOURCE.txt:3-6`)
  - `.github/workflows/container.yml:147-297`: a merge to `main` deploys to production (arm64 image, GHCR, SSM document `auth-service-bootstrap-i-011b6b82a9072a385`, `:266-269`); only job with `id-token: write` (`:159-162`)
  - `.github/workflows/container.yml` job names `ts-checks` (:46), `test` (:66), `contract` (:107): required checks, never rename (`:41-42`, `CLAUDE.md:36-42`)
  - `package.json`, `package-lock.json`, `allowed-dependencies.txt`, `dependency-snapshot.txt`, `scripts/check-dependencies.cjs`: dependency gate (decision 23); lockfile change needs `npm run snapshot:deps` (`CLAUDE.md:56-73`)
  - `Dockerfile:19-20`: runtime tree test fails if `@hapi/` or `@types/` is loaded
- **Contracts** (see team-modes **Contract changes**; validator checks every diff touching these):
  - API: `openapi.json` (committed, `npm run openapi`; synced to meta `../meta/openapi/auth-service.json` by `.github/workflows/container.yml:302-307`) = single source of truth backend ↔ frontend · provider backend
  - Provided: `POST /auth/v1/introspect` (`src/controllers/introspect.controller.ts:26`), `GET /auth/v1/token` (`src/controllers/vault.controller.ts:34`), `POST /auth/v1/m2m-token` (`src/controllers/m2m.controller.ts:22`), `POST /api/auth/v1/agent-token` and `/register` (`src/controllers/operator.controller.ts:52`, `:75`), health/status routes · consumers: every service via clerk-client (`/introspect`); st-gateway (`../st-gateway/src/authServiceClient.ts:65`, `/token`); automation-service, ai-service (`/m2m-token`, `src/config.ts:33-34`); command-interface (public routes via Caddy)
  - Consumed: SpaceTraders via st-gateway `{ST_GATEWAY_URL}/proxy` (`src/config.ts:276`, `src/spacetraders/client.ts:196-210`) · provider st-gateway; Clerk `POST /v1/m2m_tokens` (`src/m2m/clerk.ts:5`) · provider Clerk
  - Vendored: `contract/fixtures/introspection.json`, copy of meta `../meta/fixtures/introspection.json`, fixture v7, pinned in `contract/fixtures/SOURCE.txt:3-6`, asserted by `src/__tests__/introspectionFixture.test.ts:204-212` · provider meta
