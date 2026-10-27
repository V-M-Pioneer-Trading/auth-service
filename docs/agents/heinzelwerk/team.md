# Team rules

How heinzelwerk agents work in this repo. Mode rules (single repo vs workspace) live in the `heinzelwerk:team-modes` skill. This file holds only what is specific to this repo; the workspace is described in V-M-Pioneer-Trading/meta `docs/agents/heinzelwerk/workspace.md`.

- **Autonomy**: full. Agents merge and apply on their own; breakages are learnings. Secrets are never published (name the variable, never the value), and the gate never merges its own policy.
- **Role**: backend
- **Backend paths**: whole repo (`contract/` is never edited)
- **Worktree setup**: `npm ci --ignore-scripts`
- **Checks** (validator runs every one, in order; copied from CI, quiet flags only):
  - `npm run check:deps` (CI runs it before any install)
  - `npm audit --audit-level=high` (red on main: V-M-Pioneer-Trading/meta#119)
  - `npm run typecheck`
  - `npm run lint`
  - `npm run build`
  - `npm run openapi && test -z "$(git status --porcelain -- openapi.json)"`
  - `npm test`
  - contract job, in order: `docker build -t auth-service:contract .`; the Node >= 24.15 and root probe (container.yml:125-132, verbatim); `(cd contract && npm ci --ignore-scripts && npm run typecheck)`; `CONTRACT_IMAGE=auth-service:contract node scripts/run-contract.cjs` (unverified locally: docker daemon not running)
- **Checks verified on main**: 2d25f28 2026-10-27
- **Coding standards**: `CLAUDE.md` and the shared `@v-m-pioneer-trading/eslint-config`
- **Risk areas** (validator reviews diffs touching these on Opus):
  - `src/**`: the vault holds the game and account tokens; the center is the sole token verifier for every service
  - `POST /api/auth/v1/register` (Reset Agent) and `POST /api/auth/v1/agent-token` (Restore Token): Reset Agent wipes and re-registers the game agent
  - `src/m2m/**`: mints Clerk M2M tokens through the billed Clerk API
  - `src/poller.ts`: re-registers after a universe reset and spends the shared rate budget
  - Go-parity helpers (`src/goUrl.ts`, `src/goText.ts`, `src/goJson.ts`, `src/jwt/verify.ts`): replacing one with the obvious library call breaks the contract suite
  - `package-lock.json`: needs `allowed-dependencies.txt` and `npm run snapshot:deps` in the same PR
  - `.github/workflows/**`: a merge to `main` deploys or releases
- **Contracts** (see team-modes **Contract changes**; validator checks every diff touching these):
  - API: `openapi.json` (mirrored to meta `openapi/auth-service.json`) · provider auth-service
  - Introspection answers: meta `fixtures/introspection.json` and `docs/design/token-introspection.md` · provider meta
