# Repo map: auth-service

Two roles in one process. The vault: holds the SpaceTraders account and agent tokens (SQLite), detects universe resets and re-registers. The center: the only verifier of Clerk tokens (`POST /auth/v1/introspect`) and the M2M token minter. Ported from Go (decision 23); `contract/` and Go-recorded fixtures pin the behaviour.

| Path | Holds |
|---|---|
| `src/server.ts`, `src/runtime.ts` | startup, Node ≥ 24.15 check |
| `src/config.ts` | env, secrets |
| `src/controllers/*.controller.ts` | tsoa controllers |
| `src/vault.ts`, `src/db/`, `src/state/` | token storage, SQLite DDL (Go-compatible) |
| `src/introspection.ts`, `src/jwt/`, `src/keys.ts` | token verification (through `verify.ts` only) |
| `src/m2m/` | M2M minting via Clerk |
| `src/poller.ts`, `src/status.ts` | reset detection via st-gateway `GET /` |
| `src/spacetraders/` | SpaceTraders client (through st-gateway) |
| `src/goJson.ts`, `goText.ts`, `goTime.ts`, `goUrl.ts` | Go-compatible parsing; used in place of `JSON.parse`, `trim()`, WHATWG `URL` |
| `src/__tests__/fixtures/go-*` | Go-recorded parity fixtures |
| `contract/`, `openapi.json` | black-box suite; committed spec |

- Calls: st-gateway `/proxy`, Clerk API (M2M mint).
- Called by: st-gateway (`GET /auth/v1/token`, `X-Auth-Service-Secret`), every verifier (introspect, `X-Introspection-Secret`), automation-service and ai-service (`m2m-token`, `X-M2M-Caller-Secret`).
- Port 80 by default (`PORT`); meta compose publishes it as 8082.
- CI `container.yml`: `ts-checks` first; `test` and `contract` need it; `docker` needs `test` and `ts-checks` only (main: SSM redeploy, `sha-<sha>` tag), so `contract` gates merges through branch protection, not the deploy; `sync-openapi` on main.

## Reference docs

- `README.md` "Endpoints", "Environment variables", "Secrets": read when changing routes, their callers, config or secrets.
- `README.md` "Deploy", "Rollback", "The SQLite state": read when deploying, rolling back, or touching `/data`.
- `contract/README.md` "Behaviour notes": read when changing routes, introspection, operator routes, the poller or M2M.
- `meta/docs/design/token-introspection.md`: the authoritative introspection and M2M contract.
