# Auth Service

Owns the SpaceTraders game credential — the account token that mints agents, and the
resulting agent token every other service's traffic flies under. No other service persists
either. This is `meta/docs/design/auth-design.md` decision 5/6: this service holds the one
credential and refreshes it, so st-gateway can inject it instead of every caller carrying it.

It is also the fleet's **single token verifier** (decision 21, which supersedes decision 4's
"authorization is a library in every service") — see `POST /auth/v1/introspect` below.

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
`meta/.env`. `AUTH_INTROSPECTION_SECRET` is optional: without it the service still starts
and `POST /auth/v1/introspect` rejects every caller.

### Tests

> cd src && go test ./...

State-machine and poller tests run with no network access (in-memory SQLite, stubbed
SpaceTraders calls) — the only untestable path locally is a real account-token reset flow,
which needs a real account token that doesn't exist outside production
(auth-design.md decision 10's known gap).

Introspection is tested against `src/api/testdata/introspection.json`, a verbatim copy of
`meta/fixtures/introspection.json` (provenance and re-copy instructions in
`src/api/testdata/SOURCE.txt`). This is the only repository where real signatures are still
checked — every other service's suite stands up a stub center instead.

### Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `GET /auth/v1/token` | `X-Auth-Service-Secret` header | st-gateway fetches the agent token to inject. Never gets a public route — see decision 9. |
| `POST /auth/v1/introspect` | `X-Introspection-Secret` header | **Token introspection** — form body `token=<jwt>`, answers `{active}` or `{active, sub, scope, exp, kind}`. See below. |
| `GET /auth/v1/status`, `GET /api/auth/v1/status` | none | `{state, agentSymbol, resetDate, nextPredictedReset}` — never a token |
| `POST /api/auth/v1/agent-token` | Clerk `agent:reset` scope | **Restore Token** — body `{agentToken}`, regenerates the existing agent's token |
| `POST /api/auth/v1/register` | Clerk `agent:reset` scope | **Reset Agent** — body `{accountToken, symbol, faction, email?}`, mints a new agent |
| `GET /health`, `GET /api/auth/health` | none | liveness |

### Token introspection

`POST /auth/v1/introspect` makes this service the fleet's only token verifier
(auth-design.md **decision 21**, which supersedes decision 4; rollout is
[meta#80](https://github.com/V-M-Pioneer-Trading/meta/issues/80)). Every other
service sends the token it received here and compares the returned scopes
against what its own route declares. The contract is fixed by
`meta/fixtures/introspection.json`, vendored into `src/api/testdata/`.

    curl -s localhost:$PORT/auth/v1/introspect \
      -H "X-Introspection-Secret: $AUTH_INTROSPECTION_SECRET" \
      --data-urlencode "token=$JWT"

- **Request** — form-encoded `token=<jwt>` in the **body**. A token in a query
  string is *ignored*, not honoured, and `GET` is not routed at all: a token in
  a URL lands in access logs.
- **Response** — always `200` once the caller's secret is good.
  `{"active":false}` for anything that does not verify (invalid, expired
  beyond leeway, foreign-signed, malformed, missing, oversized, or carrying no
  `exp` or no non-empty `sub`), with nothing
  else in the body; otherwise
  `{"active":true,"sub":…,"scope":"a b c","exp":…,"kind":"operator"|"machine"}`
  and **never any other claim** — `azp`, `sid`, `email` and the rest stay in
  this process. No reason for a rejection is returned: it is a probing oracle
  and the remedy is the same for all of them.
- `scope` is **verbatim** — irregular whitespace and all. Every client splits
  on whitespace runs. This service keeps no route-to-scope table.
- `scope` is **always present** on an active answer, as `""` when the token
  carries no scopes (no claim, an empty string or an empty array). RFC 7662
  would allow leaving it out; this contract does not.
- `kind` is `operator` when `sub` starts `user_`, else `machine`. This is the
  one place in the fleet that knows Clerk's `sub` conventions; clients use the
  answer and must never re-derive it.
- **Wrong, missing or unconfigured caller secret** — `401`
  `a valid introspection secret is required`. That `401` is about *the calling
  service*, never about the end user's token, and a client must relay it as a
  `503`, never as a `401`.
- **Verification** — what every service did before, moved here, plus two
  stricter checks: `exp` is required and `sub` must be a non-empty string, so
  an active answer always carries both. `golang-jwt`, RS256 pinned, `exp`/`nbf` with a **60-second** leeway (decision
  21 says "a small leeway" without naming a value; 60 s is this repository's
  choice — see `clockSkewLeeway` in `src/api/introspect.go` for the reasoning),
  `CLERK_ISSUER` checked when configured, networkless, no bypass flag. `azp` is
  **deliberately not checked** (owner's decision, 2026-09-20).
- `POST /api/auth/v1/agent-token` and `/register` call the **same verification
  function in-process**. One code path; this service never calls itself over
  HTTP. Their external behaviour is unchanged apart from the new leeway.

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
  `CLERK_JWT_KEY`. Held by **st-gateway alone**.
- `AUTH_INTROSPECTION_SECRET` — gates `POST /auth/v1/introspect`. A **separate secret** from
  `AUTH_SERVICE_SHARED_SECRET`, on a separate code path, and the two must never hold the same
  value: every service in the fleet gets the introspection secret, so reusing the vault's would
  hand four more stacks the key to the route that returns the game token.
  - **Unset is legal and fails closed**: the service starts normally and the route rejects
    *every* caller with `401`, including one sending no header at all. It is deliberately not a
    startup requirement — production has no such variable until meta#80 step 3 applies it by
    hand, and a service that refused to boot would take the game credential down with it (the
    2026-08-22 outage shape).
  - Setting it to the same value as `AUTH_SERVICE_SHARED_SECRET` **is** fatal at startup. That
    cannot happen by accident in production today, so failing loudly costs nothing.
- `CORS_ALLOWED_ORIGIN` — frontend origin allowed to call the public routes (default
  `http://localhost:3000`).
