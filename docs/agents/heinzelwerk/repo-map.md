# Repo map: auth-service

Facts verified against origin/main 2d25f28 on 2026-10-27, each with `path:line`. Line numbers drift: open the file before relying on one.

1. PURPOSE: holds the SpaceTraders game credential (SQLite), sole Clerk JWT verifier for the fleet (introspection), mints Clerk M2M tokens; TS port of the former Go service. package.json:5, CLAUDE.md:3-9
2. ROUTES (tsoa controllers on Express, RegisterRoutes src/server.ts:152)
- GET /auth/v1/token: X-Auth-Service-Secret (AUTH_SERVICE_SHARED_SECRET, st-gateway alone); ?afterUnauthorized=true (exactly) forces a poll, only after the secret passes. src/controllers/vault.controller.ts:34-41, src/vault.ts:89-96, README.md:72
- POST /auth/v1/introspect: X-Introspection-Secret; form body token=<jwt>, 8 KiB max; unset secret = 401 to all. src/controllers/introspect.controller.ts:19-29, README.md:73,238-243
- POST /auth/v1/m2m-token: X-M2M-Caller-Secret per caller (automation-service: fleet:control; ai-service: events:write planner:advise). src/controllers/m2m.controller.ts:22-26, src/config.ts:32-35
- POST /api/auth/v1/agent-token (Restore Token) and POST /api/auth/v1/register (Reset Agent): Clerk session with scope agent:reset, checked in-process before the body is read. src/controllers/operator.controller.ts:43,52,63,75,86; src/vault.ts:37,136
3. UNAUTHENTICATED: GET /health, GET /api/auth/health (src/controllers/health.controller.ts:15,21); GET /auth/v1/status, GET /api/auth/v1/status, never a token (src/controllers/status.controller.ts:15,21; README.md:75); OPTIONS on any path answers 204 with CORS headers (src/http/cors.ts:14-17, mounted src/server.ts:150).
4. MONEY/SPEND (no credits moved)
- Reset Agent: POST {ST_GATEWAY_URL}/proxy/register, account token as bearer; replaces stored credential wholesale = resets the game account; then one GET / poll. src/controllers/operator.controller.ts:68-72, src/vault.ts:218-226,233, src/spacetraders/client.ts:203-215
- Poller: GET / via gateway at start then daily/hourly cadence (src/poller.ts:8,88-90,119; started src/server.ts:193); on observed resetDate change auto re-registers (POST /register) with stored account token (src/poller.ts:174-178,190-194). All via st-gateway's shared rate budget (src/spacetraders/client.ts:2-3). Forced polls: 10 s cooldown (src/poller.ts:37,128); 30 s per-call timeout (src/spacetraders/client.ts:19).
- Clerk M2M mint: POST https://api.clerk.com/v1/m2m_tokens with Machine Secret Key (src/m2m/clerk.ts:5,26,100-105). Cached until iat+(exp-iat)/2, 10 s timeout, 10 s backoff (src/m2m/cache.ts:4,20,22; CLAUDE.md:105).
- Trap: never extend scripts/cutover-probe.mjs to call register/agent-token with a session that may hold agent:reset (CLAUDE.md:52-53).
5. CALLS / CALLED BY
- Calls: st-gateway ST_GATEWAY_URL+"/proxy" (default http://localhost:3002, src/config.ts:80,276), never SpaceTraders directly (README.md:227-228). Clerk via CLERK_API_BASE_URL else api.clerk.com (src/config.ts:222, src/m2m/clerk.ts:26).
- Called by (per README.md:72-78, src/config.ts:32-35; not confirmed from other repos): st-gateway (token), verifying services (introspect), automation-service/ai-service (m2m), UI (operator; CORS_ALLOWED_ORIGIN default http://localhost:3000, src/config.ts:81,277).
- Env: PORT (80), SQLITE_DB_PATH, ST_GATEWAY_URL, CORS_ALLOWED_ORIGIN, CLERK_JWT_KEY/_FILE, CLERK_ISSUER, AUTH_SERVICE_SHARED_SECRET, AUTH_INTROSPECTION_SECRET, M2M_CALLER_SECRET_*, M2M_MACHINE_KEY_*, DEV_M2M_SIGNING_KEY_FILE, CLERK_API_BASE_URL. src/config.ts:78-81,103-277, README.md:220-262. Required to start: Clerk key + AUTH_SERVICE_SHARED_SECRET (README.md:33-34).
6. BUILD/TEST/RUN (CLAUDE.md:22-30, package.json:10-21)
- npm ci --ignore-scripts (never plain npm ci); npm run typecheck | lint | build | npm test (pretest builds; Jest under --experimental-vm-modules); one file: npm test -- src/__tests__/verifyToken.test.ts
- npm run openapi; npm run check:deps; npm run snapshot:deps after any package-lock.json change
- run: npm ci --ignore-scripts && npm run build && node dist/server.js (README.md:35); or docker compose up auth-service from meta/ (README.md:30-31)
- contract: docker build -t auth-service:contract . then CONTRACT_IMAGE=auth-service:contract node scripts/run-contract.cjs (CLAUDE.md:29). Node >=24.15 (package.json:8, CLAUDE.md:32-33)
7. CI: .github/workflows/container.yml (triggers :7-13: pull_request, push main, tags v*, workflow_dispatch; permissions contents: read :15-16; concurrency deploy-<repo> on main, cancel-in-progress false :36-38)
- ts-checks (:46-63, timeout 10): checkout@v4; setup-node@v4 node 24 (no cache); NO npm ci; `npm run check:deps`; `npm audit --audit-level=high`
- test (:66-100, needs ts-checks, timeout 15): checkout@v4; setup-node@v4 {24, cache npm, cache-dependency-path package-lock.json}; `npm ci --ignore-scripts`; `npm run typecheck`; `npm run lint`; `npm run build`; `npm run openapi` then `test -z "$(git status --porcelain -- openapi.json)" || {git diff; ::error; exit 1}` (:94-98); `npm test`
- contract (:107-145, needs ts-checks, timeout 20): checkout@v4; setup-node@v4 {24, cache npm, contract/package-lock.json}; `docker build -t auth-service:contract .`; docker run node>=24.15 + root check (:125-132); in contract/: `npm ci --ignore-scripts`; `npm run typecheck`; CONTRACT_IMAGE=auth-service:contract `node scripts/run-contract.cjs`
- docker (:147-297, needs [test, ts-checks], not contract; push, or dispatch on main; ubuntu-24.04-arm, timeout 30): checkout; tip-of-main check; buildx; GHCR login; metadata (sha long, latest if tip); build-push linux/arm64; AWS role github-actions-ssm-deploy; SSM redeploy imageTag=sha-<sha> to i-011b6b82a9072a385, poll 90x10 s
- sync-openapi (:302-310, needs test, non-PR on main): uses V-M-Pioneer-Trading/meta/.github/workflows/openapi-sync.yml@main, spec-path openapi.json
- Required checks ts-checks, test, contract; never rename (:41-42, CLAUDE.md:38-42). Dependabot PR red until snapshot:deps committed (.github/dependabot.yml:3-4, CLAUDE.md:73).
8. PERSISTENCE: node:sqlite at SQLITE_DB_PATH (default ./data/auth.db src/config.ts:79; image /data/auth.db Dockerfile:40, VOLUME Dockerfile:46). Tables credential (single row id=1) + registration_history (src/db/schema.ts:6-24). No migrations: CREATE TABLE IF NOT EXISTS run each start (src/db/database.ts:17-18). Schema must not change, Go rollback opens file (CLAUDE.md:197).
9. PATTERNS: tsoa controllers via scripts/codegen.cjs (package.json:11); openapi.json committed and CI-checked (container.yml:94-98). Operator routes call sessionGate in-process (src/vault.ts:136). Polls and operator writes serialise via Poller.exclusive (src/poller.ts:144, src/vault.ts:179,218). Update CLAUDE.md in same PR (CLAUDE.md:202).
10. TRAPS
- Go parity: no WHATWG URL, trim(), createPublicKey, URLSearchParams/express.urlencoded, req.headers[...] for introspection secret, bare jwtVerify, JSON.parse on operator/SpaceTraders/Clerk bodies, fetch or request signal for the mint; no new URL() for a Location (CLAUDE.md:108-121).
- contract/ never edited to pass (CLAUDE.md:198); contract-skip.txt empty and stays so (CLAUDE.md:196).
- Lockfile change: allowed-dependencies.txt + dependency-snapshot.txt (CLAUDE.md:58-61); image installs --omit=dev --omit=optional (CLAUDE.md:69); runtimeTree.test.ts fails if @hapi/@types load (CLAUDE.md:75-76).
- AUTH_INTROSPECTION_SECRET == AUTH_SERVICE_SHARED_SECRET fatal; unset legal, fails closed; M2M caller secret equal to another secret fatal (README.md:238-252).
- Image runs as root; /data/auth.db root-owned (Dockerfile:35-37, CLAUDE.md:33-34). GET /auth/v1/token must NOT gain Cache-Control: no-store (15 contract cases; vault.controller.ts:28-30, CLAUDE.md:136-139).
- Reset Agent can take ~2 min behind a stuck upstream (CLAUDE.md:154-156, src/vault.ts:205-208).
11. DOCS (no docs/ dir): README.md (endpoints :68, introspection :80, M2M :128, deploy :181, SQLite :191, rollback :195, secrets :216, env :220); CLAUDE.md (commands, CI, dependency gate, Go parity, invariants :193-198); contract/README.md; contract/fixtures/SOURCE.txt, src/__tests__/fixtures/SOURCE.txt; openapi.json (synced to meta).

## Reference docs

- `README.md`: read when deploying, rolling back, or touching the `/data` volume, secrets or env vars.
- `contract/README.md` "Behaviour notes": read when changing routing, introspection, M2M or startup.
