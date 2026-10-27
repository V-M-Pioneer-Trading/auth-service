# Team rules

How heinzelwerk agents work in this repo. Mode rules (single repo vs workspace) live in the `heinzelwerk:team-modes` skill. This file holds only what is specific to this repo.

- **Role**: backend (Node 24.15+ / TS / Express / tsoa / node:sqlite). The vault (game and account tokens) and the center (sole token verifier, M2M minter)
- **Backend paths**: `src/`, `scripts/`, `Dockerfile`
- **Shared paths** (only the owner named in the task edits them): `contract/`, `openapi.json`, `allowed-dependencies.txt`, `dependency-snapshot.txt`
- **Worktree setup**: `npm ci --ignore-scripts`
- **Checks** (validator runs every one, in order):
  1. `npm run check:deps --silent`
  2. `npm audit --audit-level=high`
  3. `npm run typecheck --silent`
  4. `npm run lint --silent`
  5. `npm run build --silent`
  6. `npm run openapi --silent && git diff --exit-code openapi.json`
  7. `npm test --silent -- --silent`
  8. `(cd contract && npm ci --ignore-scripts && npm run typecheck)`
  9. `docker build -q -t auth-service:contract . && CONTRACT_IMAGE=auth-service:contract node scripts/run-contract.cjs` (needs a running Docker daemon)
- **Security**: no secret scan runs yet: gitleaks is not installed and no pre-commit hook exists (planned: `gitleaks git --pre-commit --staged` in `.git/hooks/pre-commit`), so check every diff for secrets by eye · dependency audit in checks
- **Coding standards**: `CLAUDE.md` in this repo; lint rules come from `@v-m-pioneer-trading/eslint-config` and change only by a release of that package
- **Risk areas** (validator reviews diffs touching these on Opus). The whole repo is one; hot spots:
  - `src/vault.ts`, SQLite schema: game and account tokens at rest; DDL stays openable by the Go image, for rollback
  - introspection and `verify.ts`: every service's authorization rests on its answer
  - M2M minting: a redirect followed by `fetch` leaks the Clerk Machine Secret Key
  - operator routes under `agent:reset`: register / restore resets the game account, irreversible
  - `scripts/cutover-probe.mjs`: calls only read routes; register and agent-token stay out of it
  - secrets `AUTH_SERVICE_SHARED_SECRET`, `AUTH_INTROSPECTION_SECRET` (the two differ), `CLERK_JWT_KEY`, `M2M_*`: never logged
  - `.github/workflows/`: push to main deploys production; required checks `ts-checks`, `test`, `contract` keep their names
- **Contracts**:
  - `openapi.json`: provider this repo; CI diffs it; meta's copy synced by bot
  - Introspection answer (`meta/docs/design/token-introspection.md`, `meta/fixtures/introspection.json` vendored in `contract/fixtures/`): provider this repo; consumers every verifier (agent, fleet, navigation, automation, st-gateway, via clerk-client)
  - Vault `GET /auth/v1/token` (consumer st-gateway); `POST /auth/v1/m2m-token` (consumers automation-service, ai-service)
  - `contract/`: code changes to pass it, the suite does not
  - `@v-m-pioneer-trading/eslint-config`: consumed by release-tarball URL, so a change is a version bump here
