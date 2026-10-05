# Auth Service

Owns the SpaceTraders game credential — the account token that mints agents, and the
resulting agent token every other service's traffic flies under. No other service persists
either. This is `meta/docs/design/auth-design.md` decision 5/6: this service holds the one
credential and refreshes it, so st-gateway can inject it instead of every caller carrying it.

It is also the fleet's **single token verifier** (decision 21, which supersedes decision 4's
"authorization is a library in every service") — see `POST /auth/v1/introspect` below — and
the **machine-token minter** (decision 22) — see `POST /auth/v1/m2m-token`.

**TypeScript since the cutover** (meta#103, auth-design.md decision 23; auth-service#17). The
service was written in Go until then; the Go code is gone from `main` and lives in its history
(the last Go commit is `8a09f84d8898e4e1bd1428cce264250ab9ce78d1`: `git show 8a09f84:src/...`;
comments in `src/` that name `src/api/*.go` point there). The black-box suite in `contract/`
held both implementations to one behaviour and stays as the regression gate. Contributor and
agent notes: `CLAUDE.md`. Production: one container on the shared host, port 3005 (Deploy and
Rollback below).

## Setup and local development

### Required software

* Node 24.15 or later (`node:sqlite` is a release candidate from 24.15; the service refuses to
  start on anything older) and npm.
* Docker, for the contract suite and the image.

### Running application locally

From `meta/`:
> docker compose up auth-service

Or directly (needs the environment of the table below; `CLERK_JWT_KEY` or `CLERK_JWT_KEY_FILE`
and `AUTH_SERVICE_SHARED_SECRET` are the two it refuses to start without):
> npm ci --ignore-scripts && npm run build && node dist/server.js

`docker compose` supplies the secrets from `meta/dev-keys/` and `meta/.env`.
`AUTH_INTROSPECTION_SECRET` is optional: without it the service still starts and
`POST /auth/v1/introspect` rejects every caller.

### Tests

| What | Command |
|---|---|
| Install | `npm ci --ignore-scripts` (never plain `npm ci`: no dependency's install script runs, here, in CI or in the image) |
| Typecheck, lint, build | `npm run typecheck`, `npm run lint`, `npm run build` |
| Unit tests (Jest) | `npm test` (builds first) |
| Dependency gate | `npm run check:deps` (allowlist and transitive snapshot; see `CLAUDE.md`) |
| OpenAPI spec | `npm run openapi` regenerates `openapi.json`; CI fails when it drifts |
| Contract suite against the image | `docker build -t auth-service:contract .` then `CONTRACT_IMAGE=auth-service:contract node scripts/run-contract.cjs` |

State-machine and poller tests run with no network access (in-memory SQLite, stubbed
SpaceTraders calls) — the only untestable path locally is a real account-token reset flow,
which needs a real account token that doesn't exist outside production
(auth-design.md decision 10's known gap).

Introspection is tested against `contract/fixtures/introspection.json`, a verbatim copy of
`meta/fixtures/introspection.json` (provenance, sha256 pin and re-copy instructions in
`contract/fixtures/SOURCE.txt`), by `src/__tests__/introspectionFixture.test.ts` and by the
contract suite. This is the only repository where real signatures are still checked — every
other service's suite stands up a stub center instead.

CI (`.github/workflows/container.yml`) reports `ts-checks` (the dependency gate and
`npm audit`), `test` (typecheck, lint, build, the `openapi.json` freshness check, Jest) and
`contract`; the `docker` job builds the arm64 image and, on `main`, deploys it. These three
names are the required checks on `main`.

### Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `GET /auth/v1/token` | `X-Auth-Service-Secret` header | st-gateway fetches the agent token to inject. Never gets a public route — see decision 9. |
| `POST /auth/v1/introspect` | `X-Introspection-Secret` header | **Token introspection** — form body `token=<jwt>`, answers `{active}` or `{active, sub, scope, exp, kind}`. See below. |
| `POST /auth/v1/m2m-token` | `X-M2M-Caller-Secret` header (per caller) | **Machine token minting** — empty body, answers `{token, expires_at}`. See below. |
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
`meta/fixtures/introspection.json`, vendored into `contract/fixtures/`.

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
  it on runs of space, tab, CR and LF, and on nothing else (fixture v6). This service keeps no route-to-scope table.
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
  an active answer always carries both. RS256 pinned (`jose`, with the Go parser's checks around it in `src/jwt/verify.ts`), `exp`/`nbf` with a **60-second** leeway (decision
  21 says "a small leeway" without naming a value; 60 s is this repository's
  choice — see `CLOCK_SKEW_LEEWAY_SECONDS` in `src/jwt/verify.ts` for the reasoning),
  `CLERK_ISSUER` checked when configured, networkless, no bypass flag. `azp` is
  **deliberately not checked** (owner's decision, 2026-09-20).
- `POST /api/auth/v1/agent-token` and `/register` call the **same verification
  function in-process**. One code path; this service never calls itself over
  HTTP. Their external behaviour is unchanged apart from the new leeway.

### Minting a machine token

`POST /auth/v1/m2m-token` makes this service the only holder of a Clerk Machine Secret Key
(auth-design.md **decision 22**; rollout is
[meta#59](https://github.com/V-M-Pioneer-Trading/meta/issues/59); contract in
`meta/docs/design/token-introspection.md`, "Minting a machine token"). A headless service
presents its own caller secret and gets back a bearer token for its outbound calls.

    curl -s -X POST localhost:$PORT/auth/v1/m2m-token \
      -H "X-M2M-Caller-Secret: $M2M_CALLER_SECRET_AUTOMATION_SERVICE"

| Situation | Status | Body |
|---|---|---|
| Known secret, token minted or served from cache | `200` | `{"token":"<jwt>","expires_at":<unix seconds>}` |
| Missing, empty or unknown secret; caller disabled | `401` | `{"error":"unknown caller"}` |
| Minting failed and no cached token is still unexpired | `503` | `{"error":"the token could not be minted"}` |
| `OPTIONS` | `204` | — (the service-wide CORS preflight catch-all; CORS does not allow the caller-secret header) |
| Any other method | `405` | — |

- **The secret is the identity.** There is no body field naming a caller or asking for a
  scope. Scopes are a fixed table in `src/config.ts`: `automation-service` gets
  `fleet:control`; `ai-service` gets `events:write planner:advise`. Changing it is a pull
  request here.
- **Tokens live 24 hours** and are cached in memory per caller, served again until the
  refresh point `iat + (exp - iat) / 2`, read from the token itself (callers use the same
  point). Nothing is persisted, so a restart costs each caller one mint.
- **A request never waits on a refresh while a valid token exists.** Past the refresh point
  with the cached token unexpired, the request gets that token at once and a mint starts (or
  is joined) behind it. Only a request with nothing valid in hand waits for the mint.
- **A mint is detached and single-flight.** It runs on a background context under its own
  10 s timeout, never the request's, so a caller giving up after its 1 s timeout cancels
  nothing (and is not logged as a failure): its retry joins the mint in flight, and a token
  that lands after everyone left is still cached.
- **Failures back off and fall back.** Failed mints are spaced at least 10 s apart per
  caller; inside that window no request reaches Clerk, and the backoff is logged once per
  window. If a mint fails, or is backing off, while the cached token is still unexpired, the
  cached token is served; with nothing valid in hand the answer is `503`.
- **A minted token must have a usable lifetime** or it counts as a failed mint and is not
  cached: `iat` and `exp` present, both within `0 … 2^53`, at least 60 s apart, at most 7 days
  apart, and the refresh point still in the future. A failed mint is logged once, by the mint
  itself, since a background refresh has no request to report it.
- **Production** calls Clerk's `POST /v1/m2m_tokens` with that caller's own Machine Secret
  Key, so `sub` names the caller's Machine (`mch_…`). Redirects are never followed (the
  request carries the key), and a failure is logged with Clerk's status only, never its body.
- **Local dev** (`DEV_M2M_SIGNING_KEY_FILE` set) signs the same shape of JWT with the
  committed dev private key: `sub` is `mch_local_<caller>`, `kid` is `dev-only-do-not-use`,
  `iss` is `CLERK_ISSUER` when set. This service's own introspection answers it
  `kind: "machine"`.
- A `401` names no caller and no secret, in the body or the log.

`state` is one of `UNCONFIGURED` / `HEALTHY` / `WIPE_IMMINENT` / `APP_TOKEN_EXPIRED` — see
`src/state/machine.ts` and auth-design.md decisions 7/8 for the transition rules.

### Deploy

CI deploys `main`: `.github/workflows/container.yml` runs `ts-checks`, `test` and `contract` on every pull request and push, and on a push to `main` its `docker` job builds the root `Dockerfile` for linux/arm64 (the shared host is a Graviton t4g), pushes `ghcr.io/v-m-pioneer-trading/auth-service:sha-<40 hex>` and `:latest`, and redeploys on the shared host: it sends the SSM document `auth-service-bootstrap-<instance id>` (instance `i-011b6b82a9072a385`, eu-central-1) and waits for it to finish. The job deploys only if its commit is still the tip of `main`, only one run deploys at a time, and a failed bootstrap fails the run. A `v*` tag builds and pushes `sha-<40 hex>` only and never deploys.

What the bootstrap does (Terraform in `V-M-Pioneer-Trading/infrastructure`, `auth-service/`): reads the secrets from SSM Parameter Store, pulls the image, replaces the `auth-service` container (on the `authnet` network, bound to `127.0.0.1:3005`, `PORT=3005`, `SQLITE_DB_PATH=/data/auth.db`) and polls `GET /health` on `127.0.0.1:3005` for about 90 seconds, failing the command if it never answers. The other services reach it on `localhost:3005`; CloudFront routes `/api/auth/*`.

The image is `gcr.io/distroless/nodejs24-debian13`: no shell, no package manager, the entrypoint is `node`, and it runs as **root** because the existing `/data/auth.db` is root-owned (changing that is a volume ownership migration, not part of the cutover). To look at it on the host use `docker inspect auth-service`, `docker logs auth-service` and `docker stats`; there is no shell to `docker exec` into.

A memory cap (`--memory`, plus a Node old-space limit) belongs on the `docker run` in the bootstrap document in infrastructure, not here.

### The SQLite state (`/data` volume)

The credential row (account token, agent token, symbol, reset dates, the `APP_TOKEN_EXPIRED` flag) and the registration history live in one SQLite file, `SQLITE_DB_PATH` (production: `/data/auth.db`; the host directory `/data/auth-service`, on its own EBS volume, is mounted at `/data`; locally, compose mounts a named volume). The schema is applied on every start and is exactly the one the Go implementation used, so **either image opens the file the other wrote**, in both directions; that is what makes a rollback need no data change (`src/__tests__/db.test.ts` and `vaultStore.test.ts` run against a file the Go image wrote; the contract suite restarts the container on the same volume). Never delete the file to "fix" a deploy: it holds the only copy of the agent token, and a lost one is restored through Restore Token or the agent is reset through Reset Agent, with a human holding the account token (decisions 7 and 8).

### Rollback

The bootstrap document takes an optional `imageTag` parameter (default `latest`, which is what CI and the association send). `latest` or `sha-<40 hex git sha>` are the only values it accepts; only commits pushed to `main` or a `v*` tag have a `sha-` image. To put an earlier image on the host:

```bash
INSTANCE_ID=i-011b6b82a9072a385
SHA=<40-hex commit sha to roll back to>
command_id=$(aws ssm send-command --region eu-central-1 \
  --document-name "auth-service-bootstrap-$INSTANCE_ID" \
  --targets "Key=InstanceIds,Values=$INSTANCE_ID" \
  --parameters imageTag=sha-$SHA --timeout-seconds 600 \
  --query Command.CommandId --output text)
# wait for Success, not Failed or TimedOut
aws ssm get-command-invocation --region eu-central-1 \
  --command-id "$command_id" --instance-id "$INSTANCE_ID" --query Status --output text
```

Check first that the CI deploy on `main` is idle, or the two runs race. **A rollback is not sticky:** the next merge to `main`, any run of the bootstrap without `imageTag`, and any `terraform apply` that changes the document redeploy `:latest`. Follow a rollback with a revert PR on `main` before anything else merges there. An older image may not accept today's environment (the introspection and M2M variables), so read the command's status; the `/health` poll fails it if the container crash-loops.

The last Go image, for a rollback across the cutover, is `sha-8a09f84d8898e4e1bd1428cce264250ab9ce78d1` (the tip of `main` before the cutover PR; its `container` run built and deployed the Go Dockerfile). `scripts/cutover-probe.mjs` is the production probe used for the cutover (see its header; the cutover was issue #17, PR #26), with `scripts/cutover-deploy-rc.ps1` and `scripts/cutover-hostcheck.ps1` for the host side; the probe is safe to re-run after any deploy.

### Secrets

The SSM parameters the bootstrap reads, and the variables they become: `AUTH_SERVICE_SHARED_SECRET` (`auth-service-shared-secret`, shared with st-gateway alone), `AUTH_INTROSPECTION_SECRET` (`auth-service-introspection-secret`, shared with every verifying service), `CLERK_JWT_KEY` (`auth-service-clerk-jwt-key`), `M2M_MACHINE_KEY_AUTOMATION_SERVICE` and `M2M_MACHINE_KEY_AI_SERVICE` (Clerk Machine Secret Keys), `M2M_CALLER_SECRET_AUTOMATION_SERVICE` and `M2M_CALLER_SECRET_AI_SERVICE`. None is ever logged, echoed in a refusal or put in an error message (`CLAUDE.md`, invariant 1); the repository is public.

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
- `M2M_CALLER_SECRET_AUTOMATION_SERVICE`, `M2M_CALLER_SECRET_AI_SERVICE` — the secret each
  caller presents to `POST /auth/v1/m2m-token` as `X-M2M-Caller-Secret`. **Unset or empty disables that
  caller** (its requests get `401`); it is not a startup error. Fatal at startup: equal to
  `AUTH_SERVICE_SHARED_SECRET`, to `AUTH_INTROSPECTION_SECRET` (every service holds that one,
  so every service could mint), or to the other caller's secret (either could mint as the
  other); set with leading or trailing whitespace, or whitespace only (HTTP header values are trimmed,
  so it could never match); or set with nothing to mint with (neither that caller's machine
  key nor the dev key).
- `M2M_MACHINE_KEY_AUTOMATION_SERVICE`, `M2M_MACHINE_KEY_AI_SERVICE` — that caller's Clerk
  Machine Secret Key (production). One Clerk Machine per caller, so a token's `sub` names the
  caller and one can be revoked without the other. Two callers configured with the same key is
  fatal at startup.
- `DEV_M2M_SIGNING_KEY_FILE` — path to an RSA private key PEM; when set, tokens are signed
  locally instead of minted by Clerk (compose mounts
  `meta/dev-keys/dev-only-do-not-use.key.pem`). Setting it **and** any `M2M_MACHINE_KEY_*` is
  fatal at startup: one trust anchor per process. If it does not match the verification key
  the service logs a warning, since every token it mints would then introspect as inactive.
- `CORS_ALLOWED_ORIGIN` — frontend origin allowed to call the public routes (default
  `http://localhost:3000`).
