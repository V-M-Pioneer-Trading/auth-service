# auth-service contract suite

A black-box HTTP suite that pins what auth-service does. It starts a
container image, wires it to stub upstreams, and talks to it over HTTP. It knows
nothing about the language the service is written in, so the Go image and the
TypeScript port were held to the same definition of "same": the suite was green
against the Go image, and the TypeScript image passes it **unchanged**. Since the
cutover (auth-service#17) the Go code is gone and the suite is the parity record
and a regression gate for the TypeScript service.

If a test here looks wrong, the answer is never to edit it to suit the code. The
test captures what the Go service did and what clients depend on; changing it is a
deliberate, reviewed change to the contract.

## Running it

```sh
docker build -t auth-service:contract ..        # from contract/; builds ../Dockerfile
npm ci
npm run typecheck
CONTRACT_IMAGE=auth-service:contract node --test
```

Node 24 runs the `.ts` files directly (native type stripping): no build step, no
runtime dependencies. The only dev dependencies are `typescript` and
`@types/node`, for `npm run typecheck`. Test code is erasable syntax only (no
enums, no parameter properties, `import type` for types).

CI is the `contract` job of `.github/workflows/container.yml`, judged by `scripts/run-contract.cjs` (the `docker` deploy job does not wait for it; branch protection does).

`CONTRACT_BIN=<path to a native executable>` is accepted instead of
`CONTRACT_IMAGE` for iterating on a machine with no Docker daemon. It runs the
same suite against a process instead of a container, and cannot test the
default port 80. CI and porters use the image.

Everything is generated per run: an RSA keypair (the Clerk verification key
and, in dev mode, the M2M signing key), every secret and machine key, every
token. Nothing in the repository is a real credential and the suite never
prints one.

## How it works

- `lib/service.ts` runs the image with `docker run --add-host=host.docker.internal:host-gateway`,
  a named volume for `/data` (the SQLite file), a host port mapped to the
  container's `PORT`, and secrets passed as `-e NAME` with the value in the
  docker CLI's environment (never on a command line). It waits for `GET /health`
  and tears everything down on exit, including when a test throws. Containers
  are stopped with `docker rm -f` (SIGKILL): the contract says nothing about
  graceful shutdown, and a hard kill is what proves the data survives.
- `lib/stubs.ts` serves, from the test process on `0.0.0.0` and a random port,
  a SpaceTraders stub (`GET /proxy/` root, `POST /proxy/register`, reached
  through `ST_GATEWAY_URL`) and a Clerk Backend API stub (`POST /v1/m2m_tokens`,
  reached through `CLERK_API_BASE_URL`).
- `lib/lab.ts` gives each test file its own world: keys, secrets, the two stubs
  and `start()`. Each test file starts as many containers as it needs; files run
  in parallel under `node --test`.
- Both M2M modes are covered by separate container runs: **dev**
  (`DEV_M2M_SIGNING_KEY_FILE`, tokens signed locally) and **production**
  (`M2M_MACHINE_KEY_*`, tokens minted by the Clerk stub).
- Responses are compared whole: status, the pinned headers, and the body. JSON
  is parsed and compared with `deepStrictEqual` (so `null` is not "missing" and
  `1` is not `"1"`); byte formatting is free. Text bodies are compared byte for
  byte. Pinned headers (`lib/expect.ts`): `Content-Type`, `Cache-Control`, the
  `Access-Control-*` family, `X-Content-Type-Options`, `Location`, `Allow`,
  `Vary`, `ETag`, `WWW-Authenticate`, `Set-Cookie`. A pinned header that is not
  expected must be **absent**; that is how "no `Cache-Control` here" and "no
  CORS on a 405" are checked. Anything else a framework adds (`X-Powered-By`,
  `Date`, `Content-Length`, `Connection`) is ignored.

## Layout

| File | What it pins |
| --- | --- |
| `tests/introspect-fixture.test.ts` | the SHA-256 pin of `contract/fixtures/introspection.json`, then **every** one of its 75 cases driven through the container, with the classification totals asserted |
| `tests/introspect.test.ts` | caller-secret gate, where the token travels, the 8 KiB cap, what verifies and what is `{"active":false}`, `CLERK_ISSUER` |
| `tests/vault.test.ts` | `GET /auth/v1/token`, both status routes, health routes, the Clerk session gate, Restore Token |
| `tests/register.test.ts` | Reset Agent: what is sent to SpaceTraders, what is stored, how upstream failures map |
| `tests/poller.test.ts` | forced polls, the 10 s cooldown, wipe detection, `APP_TOKEN_EXPIRED`, state across a restart on the same volume |
| `tests/m2m-dev.test.ts` | `POST /auth/v1/m2m-token`, dev mode: the caller table, the secret gate, the token's shape |
| `tests/m2m-clerk.test.ts` | same route against the Clerk stub: what is asked of Clerk, single flight, every reason a minted token is refused |
| `tests/m2m-clerk-backoff.test.ts` | the 10 s backoff and the 10 s mint timeout |
| `tests/m2m-clerk-refresh.test.ts` | refresh at half the token's lifetime, using a short-lived stub token |
| `tests/m2m-clerk-expiry.test.ts` | an expired cached token is never served, even while Clerk is down |
| `tests/routing.test.ts` | the whole 404/405/301 table, HEAD, OPTIONS, CORS, path cleaning |
| `tests/startup.test.ts` | configuration the service refuses to start with, key formats, log hygiene |

## Test titles tagged `[net-http-text]`

A title ending in `[net-http-text]` pins a fixed text that Go's `net/http` writes
itself (`404 page not found`, with its `text/plain; charset=utf-8` and
`nosniff`), and it is kept **exact** on purpose: it is part of the router
contract, and a port can reproduce it trivially. The 405 answers are empty, so
there is no text to pin.

Wording that Go's *other* libraries generate (the `encoding/json` decode
messages after `invalid request body: `, the error text of a failed upstream
call in a 502) is **not** pinned, permanently, with no strict mode: those tests
assert the status, the content type and the stable prefix only.

## Not covered

- **Timing.** Constant-time secret comparison cannot be asserted black-box
  without flaking. Behaviour that follows from it (every length, prefix and case
  variant is rejected, the secret is checked before the body is read) is covered.
- **The scheduled poll cadence** (daily, hourly inside the 24 h before a
  predicted reset). It is not observable in a test that lasts seconds. What is
  covered: the poll at startup, forced polls, and the state machine.
- **The 30 s upstream client timeout**, and the 64 KiB cap on Clerk's reply.
- **HTTP server limits.** Go's `http.Server` here has no read, write or idle
  timeouts; none are pinned.
- **Log wording.** Only that no credential, query-string token or request body
  reaches the log.
- **The `registration_history` table.** It is write-only: no route reads it.

## Behaviour notes

Quirks of the Go service that the suite pins. These are input for the porters:
each one is a place a "cleaner" implementation fails the contract.

### Routing

1. **405 and 404 are not principled.** A catch-all `OPTIONS` route is mounted
   first, so for every path *outside* `/api/auth` any method but `OPTIONS` is
   `405` with an empty body, **whether or not the path exists** (`GET /`,
   `GET /nope`, `GET /health/`). Inside `/api/auth` the sub-router answers
   `404` with `404 page not found\n` for unknown paths **and** for wrong methods
   (`POST /api/auth/health`, `GET /api/auth/v1/agent-token`), except
   `/api/auth/v1/register`, whose wrong methods are `405`. The full table is in
   `tests/routing.test.ts`; replicate the table, not a rule.
2. **HEAD is never served**, not even on GET routes: `405` on bare routes,
   `404` under `/api/auth`. There is no automatic HEAD-from-GET.
3. **`OPTIONS` is `204` for any path**, including unknown ones, with the three
   CORS headers and no other header and no body.
4. **No CORS on router-generated answers**: the `404`, `405` and `301` carry no
   `Access-Control-*` headers; only responses a handler wrote do.
5. **Path cleaning redirects.** `//health`, `/health//`, `/a/../health`,
   `/./health` get `301` with `Location: <cleaned path>`, an empty body, no
   CORS, **for every method including POST and OPTIONS**, before any route
   runs. Routing is on the **decoded** path (`/%68ealth`, `/api/auth%2Fhealth`
   are `/health` and `/api/auth/health`).
6. **No trailing-slash tolerance, no case folding.** `/health/` and `/Health`
   are not routes.
7. **The vault token is not under `/api/auth`**: `/api/auth/v1/token` is `404`
   at every method (decision 9: no public route for the credential).

### Headers

8. **`Content-Type` is exact.** JSON is `application/json` (no charset). Plain
   text errors (Go's `http.Error`) are `text/plain; charset=utf-8` with
   `X-Content-Type-Options: nosniff` and end in `\n`. Express's default
   `application/json; charset=utf-8` and its `ETag` fail the suite.
9. **`Cache-Control: no-store` is on some answers and not others.** It is on:
   every introspection answer (active and inactive, and the 401), every
   M2M answer (token, 401, 503), and every `{"error":{"message":…}}` envelope
   (`GET /auth/v1/token`'s 403, the session gate's 401 and 403). It is **not**
   on: status, health, register and restore answers, the plain-text errors, or
   anything the router wrote; the suite asserts the absence. The successful
   `GET /auth/v1/token` (which carries the credential) has none today, and the
   suite accepts either no `Cache-Control` or `no-store` there, so a port may add it.
10. **CORS** is one fixed `Access-Control-Allow-Origin` from
    `CORS_ALLOWED_ORIGIN` (an empty value is unset, default
    `http://localhost:3000`), never reflected from the request. Methods are
    `GET, POST, OPTIONS`, headers `Content-Type, Authorization,
    X-Auth-Service-Secret`. `X-Introspection-Secret` and `X-M2M-Caller-Secret`
    are deliberately not allowed (no browser caller). No credentials, max-age or
    `Vary`.
11. **Header values are trimmed.** Go's HTTP server drops leading and trailing
    whitespace from header values, so `X-Auth-Service-Secret:   s  ` matches
    `s`. This is why startup refuses an M2M caller secret with surrounding
    whitespace (it could never match). Only the first `Authorization` header is
    read when a request sends two.

### Secrets

12. **Three different rejections.** `GET /auth/v1/token`: **403** envelope
    `invalid or missing shared secret`. `POST /auth/v1/introspect`: **401**
    envelope `a valid introspection secret is required`. `POST
    /auth/v1/m2m-token`: **401** `{"error":"unknown caller"}` (a bare string, not
    the envelope). The Clerk session gate: 401 `a bearer token is required` /
    401 `invalid or expired session` / 403 `this action requires a scope this
    session does not carry`.
13. **Only two of the three comparisons are constant-time.** Introspect and
    M2M use `subtle.ConstantTimeCompare` (M2M against every enabled caller,
    without early exit). The vault's shared secret is compared with plain `!=`.
    Not testable black-box; a port should use a constant-time compare
    everywhere and say so.
14. **Empty never matches.** An empty or unset introspection secret rejects every
    caller, including one sending an empty header. A caller whose M2M secret is
    unset is disabled and gets the same 401 as a stranger.
15. **Each secret opens one door.** The vault, introspection and caller secrets
    are not interchangeable, and a secret in the query string, or in another
    route's header, is not read.

### Introspection

16. **Answer shape.** `{active:true, sub, scope, exp, kind}` with exactly those
    keys (no other claim leaks), or exactly `{"active":false}`. `scope` is
    always present on an active answer, `""` when the claim is absent, `null`, a
    number or an object. A string scope is returned verbatim (irregular
    whitespace included); an array is joined with single spaces with
    non-strings dropped. `exp` is an integer (a fractional `exp` is truncated).
    `kind` is `operator` iff `sub` starts `user_`, case-sensitively, else
    `machine`.
17. **Verification.** RS256 only (`none`, HS256 keyed with the public PEM, RS384,
    RS512, PS256 are all inactive). `exp` is required and must be numeric (a
    string `exp` is inactive). A 60 s leeway applies to `exp` and `nbf` (a token
    that expired 30 s ago is **active**; 90 s ago is not). `sub` must be a
    non-empty string. `iat`, `aud`, `azp`, `typ`, `kid` are not checked.
    `CLERK_ISSUER`, when non-empty, must equal `iss` exactly; unset means `iss`
    is not checked.
18. **A duplicated secret header: the first wins.** Two `X-Introspection-Secret`
    headers are read as the first one. Node joins unknown duplicate headers with
    `, `, which would never match: a port must take the first value.
    **Foreign key material in the header is ignored.** A token signed by an
    untrusted key is inactive whatever its `jwk`, `jku` or `x5u` header says; the
    only key is `CLERK_JWT_KEY`. **`crit` is deliberately not pinned:** Go accepts a
    token with an unknown `crit` header, `jose` rejects it, and the port will
    reject. That is an intentional, unpinned difference.
18a. **Everything unverifiable is `200 {"active":false}`**: no explanation, never
    4xx/5xx. That includes an empty or missing token, a token in the query
    string (ignored), a JSON body, a body without a form content type, and a
    body over the cap.
19. **Form parsing.** Only `application/x-www-form-urlencoded` (a charset
    parameter is fine) is read. The first `token` value counts. **The URL query
    is parsed too, only to be ignored: a malformed escape (`?%zz`) or a
    semicolon (`?a=1;b=2`) in the query, or a semicolon anywhere in the body,
    makes the whole request `{"active":false}` even with a valid body token.** **A malformed
    percent-escape anywhere in the body makes the whole request inactive, even
    when a valid token came first.** The cap is 8192 bytes of body: 8192 is
    accepted, 8193 is `{"active":false}` (not 413), however valid the token. The
    secret is checked before the body is read.
20. **Method.** `GET` (or anything but `POST`) is `405`: a token never travels in
    a URL.

### Operator routes (`/api/auth/v1/agent-token`, `/register`)

21. **Authentication precedes the body** (a bad body with no credential is 401).
    The scheme is matched case-insensitively and the header is split on **any
    run of whitespace**: `Bearer   t` and `Bearer<TAB>t` work; `Bearer a b`,
    `Bearer`, `Basic …` and a bare token are "a bearer token is required".
    The scope is an exact whole-word match of `agent:reset` against the scope
    (string or array) split on runs of space, tab, CR and LF only (fixture v6):
    VT, FF, a no-break space or any other Unicode space is part of a scope.
    `agent:resetx` and `AGENT:RESET` are 403.
22. **The body is decoded like Go's `encoding/json`**: key case is ignored
    (`{"AGENTTOKEN":…}` works), unknown keys are ignored, a repeated key's last
    value wins, **data after the first JSON value is ignored**, and a body of
    `null` is an empty object (so `agentToken is required`, not a decode
    error). No content type is required. There is no body size cap on these two
    routes (not pinned by the suite). A decode failure is `400 invalid request body: <Go's message>\n`
    (`EOF`, `unexpected EOF`, `json: cannot unmarshal number into Go struct
    field …`): the suite pins the status, the content type and the prefix
    `invalid request body: `, **not** the message after it or its newline.
23. **Restore Token**: `409` (text) `no credential configured to restore a token
    onto` when nothing is registered; `{"status":"restored"}` otherwise. It
    replaces only the agent token, stores it verbatim, clears
    `APP_TOKEN_EXPIRED`, and makes no upstream call.
24. **Reset Agent**: sends `POST {ST_GATEWAY_URL}/proxy/register` with
    `Authorization: Bearer <accountToken>` and `{symbol, faction, email}` (`email`
    omitted when empty). The answer's `agentSymbol` is **SpaceTraders'**, not the
    requested one. Any upstream status ≥ 400 is passed through with the body
    `POST /register: <upstream body>\n` (the operator sees upstream's raw text);
    a 2xx with an unusable body, or a transport failure, is `502`. A response
    with no token is stored and answered `200`, after which
    `GET /auth/v1/token` is `503`. It replaces the credential wholesale
    (clearing `APP_TOKEN_EXPIRED` and the stored dates), then makes **one
    best-effort `GET {ST_GATEWAY_URL}/proxy/`** to repopulate the dates; if that
    fails the registration still succeeds with no dates.

### Vault token, status, poller

25. **`GET /auth/v1/token`**: `503` text `no agent token configured` when there is
    no credential **or the stored token is empty**. The token is served in every
    state, `APP_TOKEN_EXPIRED` included.
26. **`?afterUnauthorized=true`** forces a poll **before** the answer is written
    and only for the exact value `true`, and only for a caller who passed the
    secret. The poll can change what is answered (a wipe replaces the token).
27. **The 10 s cooldown is global, and is consumed by anything that tries to
    poll**: a forced poll with no credential, or whose upstream fetch fails,
    still opens the window. A burst runs one poll. The first forced poll after
    start is always allowed.
28. **State machine.** A forced poll that finds the same `resetDate` flags the
    token expired. One that finds a different `resetDate` (both dates
    non-zero) is a wipe: it re-registers with the **stored** account token,
    symbol, faction and email, serves the new token, **does not** flag expiry,
    and adopts the new dates. If that re-registration fails, the old token is
    served, **the dates are not updated**, and the flag stays down. A root that
    cannot be fetched or parsed changes nothing. **A root that lacks
    `resetDate`/`serverResets.next` overwrites the stored dates with nothing.**
    The stored symbol survives a re-registration even if SpaceTraders returns a
    different one.
29. **Status.** `{"state":…}` plus `agentSymbol`, `resetDate`,
    `nextPredictedReset` only when non-empty. Dates are RFC 3339 as Go formats
    it: **the UTC offset the date arrived with is kept, fractional seconds are
    dropped**, a bare `YYYY-MM-DD` is midnight UTC (`…T00:00:00Z`), and an
    unparseable date is omitted. `WIPE_IMMINENT` is `now >= next - 24h` and
    stays on after `next` has passed. `APP_TOKEN_EXPIRED` outranks it.
    `UNCONFIGURED` is "no credential row".
30. **Startup.** If a credential exists the service polls the root immediately
    (a scheduled-style poll: it can detect a wipe and re-register, but never
    flags expiry and never clears the flag). With no credential it makes no
    upstream call. It comes up even when SpaceTraders is down. State lives in
    SQLite at `/data/auth.db` (`SQLITE_DB_PATH`), one connection.

### Machine tokens

31. **The secret is the identity.** Nothing in the body, query or other headers
    chooses a caller or a scope. Table: `automation-service` → `fleet:control`;
    `ai-service` → `events:write planner:advise`.
32. **Dev mode** (`DEV_M2M_SIGNING_KEY_FILE`): RS256, header
    `{alg, kid:"dev-only-do-not-use", typ:"JWT"}`, claims exactly
    `{sub:"mch_local_<caller>", scope, iat, exp = iat + 86400}` plus `iss` iff
    `CLERK_ISSUER` is set. The key may be PKCS#8 or PKCS#1 (jose's `importPKCS8`
    refuses the latter; `CLERK_JWT_KEY` may likewise be a PKCS#1 public key, or
    one line with literal `\n`). A dev key that is not the verification key is
    only a log warning: its tokens then introspect as inactive.
33. **Production mode**: `POST {CLERK_API_BASE_URL}/v1/m2m_tokens` (default
    `https://api.clerk.com`), `Authorization: Bearer <that caller's machine
    key>`, body `{token_format:"jwt", claims:{scope}, seconds_until_expiration:86400}`.
    Redirects are **not followed**. Any 2xx is success. The answer is
    `{token, expires_at}` where `token` is Clerk's string verbatim and
    `expires_at` is **read from its `exp`**, not computed.
34. **A minted token is refused (503) unless**: it is a three-part JWT whose
    payload is base64url JSON with numeric `iat` and `exp` in `[0, 2^53]`; its
    lifetime is 60 s to 7 days inclusive; it is not yet expired; and it is not
    already past its refresh point.
35. **Cache, single flight, refresh.** One cache per caller, nothing persisted.
    Served from memory until `iat + floor((exp - iat) / 2)`. After that the
    next request starts a refresh and **is answered immediately with the old
    token** while it runs; concurrent requests share the one refresh. A request
    waits only when there is no unexpired token. N concurrent first requests
    cost exactly one Clerk call. A caller that hangs up does not cancel the mint.
36. **Failure and backoff.** Any failed mint is `503
    {"error":"the token could not be minted"}`, never Clerk's text. After a
    failure no new mint starts for 10 s **per caller**; inside the window a
    valid cached token is still served, otherwise 503. A mint is abandoned after
    10 s. A failed refresh never costs a caller its still-valid token.

### Startup validation

37. **Refuses (non-zero exit; where the message names a setting it is the
    variable, and it never prints a value, so the suite asserts on variable names
    only and the Go wording is not pinned):** no
    `CLERK_JWT_KEY`/`CLERK_JWT_KEY_FILE` (inline wins; an empty file is an
    error; a private key is not a public key); no `AUTH_SERVICE_SHARED_SECRET`;
    `AUTH_INTROSPECTION_SECRET` equal to the shared secret; an M2M caller secret
    equal to the shared secret, the introspection secret (when set), or the
    other caller's; two callers with the same machine key; a dev key **and** a
    machine key; an enabled caller with neither; a caller secret with leading or
    trailing whitespace (or only whitespace); a dev key file that is missing,
    empty, or not an RSA private key; a `CLERK_API_BASE_URL` that is not an
    http(s) URL with a host and without credentials, query or fragment (the error
    never repeats the value). When `CLERK_API_BASE_URL` is set the service logs
    `scheme://host` only. Production never sets it.
38. **Boots in a fail-closed state:** no `AUTH_INTROSPECTION_SECRET` (the route is
    mounted and rejects everyone), no M2M caller secrets (the route rejects
    everyone), a machine key with no caller secret (that caller is disabled).
    Empty environment variables are the same as unset.
39. **`PORT`** defaults to 80.

### Logging

40. One line per request, `<METHOD> request: to <path>`: the **path only**, so a
    token mistakenly sent in a query string is never logged. No secret, key,
    token or body is written anywhere.
