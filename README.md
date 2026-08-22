# Auth Service

Owns the SpaceTraders game credential — the account token that mints agents, and the
resulting agent token every other service's traffic flies under. No other service persists
either. This is `meta/docs/design/auth-design.md` decision 4/5/6: authorization (Clerk
scopes) stays a library inside every service; this service exists only to hold the one
credential and refresh it, so st-gateway can inject it instead of every caller carrying it.

**Status: increment 3, Stage 3 in progress.** Stages 1–2 (this application; st-gateway
injection and priority derivation) are done and tested. Stage 3's Terraform stack exists in
`V-M-Pioneer-Trading/infrastructure/auth-service/` but this service is **not yet deployed** —
no GitHub repo, no live host, no traffic. It is also not yet wired into Caddy/CloudFront (Stage
4). See `meta/docs/design/auth-design.md`'s "New repository: auth-service" and "Build order"
sections for the full rollout plan.

## Setup and local development

### Required software

* Golang (https://go.dev/doc/install) — 1.22+

### Running application locally

From `meta/`:
> docker compose up auth-service

Or directly, from `src/`:
> go run .

Requires `CLERK_JWT_KEY`/`CLERK_JWT_KEY_FILE` and `AUTH_SERVICE_SHARED_SECRET` — see
Environment variables below. `docker compose` supplies both from `meta/dev-keys/` and
`meta/.env`.

### Tests

> cd src && go test ./...

State-machine and poller tests run with no network access (in-memory SQLite, stubbed
SpaceTraders calls) — the only untestable path locally is a real account-token reset flow,
which needs a real account token that doesn't exist outside production
(auth-design.md decision 10's known gap).

### Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `GET /auth/v1/token` | `X-Auth-Service-Secret` header | st-gateway fetches the agent token to inject. Never gets a public route — see decision 9. |
| `GET /auth/v1/status`, `GET /api/auth/v1/status` | none | `{state, agentSymbol, resetDate, nextPredictedReset}` — never a token |
| `POST /api/auth/v1/agent-token` | Clerk `agent:reset` scope | **Restore Token** — body `{agentToken}`, regenerates the existing agent's token |
| `POST /api/auth/v1/register` | Clerk `agent:reset` scope | **Reset Agent** — body `{accountToken, symbol, faction, email?}`, mints a new agent |
| `GET /health`, `GET /api/auth/health` | none | liveness |

`state` is one of `UNCONFIGURED` / `HEALTHY` / `WIPE_IMMINENT` / `APP_TOKEN_EXPIRED` — see
`src/state/machine.go` and auth-design.md decisions 7/8 for the transition rules.

### Environment variables

- `PORT` — listen port (default `80`, matching local compose; production sets this
  explicitly since every service on the shared host shares one network namespace and
  agent-service already hardcodes `:80`).
- `SQLITE_DB_PATH` — where the credential file lives (default `./data/auth.db`; compose
  mounts a named volume here).
- `ST_GATEWAY_URL` — same convention as every sibling service; the poller's `GET /` calls and
  `POST /register` both route through it, never SpaceTraders directly.
- `CLERK_JWT_KEY` / `CLERK_JWT_KEY_FILE` — Clerk's RS256 public key, inline wins over file.
  No default — a service that can start with no trust anchor is one that can ship with
  authentication silently off.
- `CLERK_ISSUER` — optional `iss` claim check.
- `AUTH_SERVICE_SHARED_SECRET` — gates `GET /auth/v1/token`. No default, same reasoning as
  `CLERK_JWT_KEY`.
- `CORS_ALLOWED_ORIGIN` — frontend origin allowed to call the public routes (default
  `http://localhost:3000`).
