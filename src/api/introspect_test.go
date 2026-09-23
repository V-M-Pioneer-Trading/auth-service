package api

// Behavioural tests for POST /auth/v1/introspect. The fixture-driven
// conformance pass lives in introspection_fixture_test.go; this file covers
// what the fixture cannot see, because it describes what a CLIENT answers:
// algorithm confusion, issuer pinning, the leeway boundary in both directions,
// the caller secret, and the promise that nothing but the five contract fields
// ever leaves this process.

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

const testIntrospectionSecret = "test-introspection-secret"

// introspect posts a form body the way a calling service does. secret is sent
// verbatim; sendSecret false omits the header entirely.
func introspect(t *testing.T, router http.Handler, token, secret string, sendSecret bool) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	return introspectRaw(t, router, "/auth/v1/introspect", form.Encode(), secret, sendSecret)
}

func introspectRaw(t *testing.T, router http.Handler, path, body, secret string, sendSecret bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if sendSecret {
		req.Header.Set(IntrospectionSecretHeader, secret)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decodeIntrospection insists the body is exactly the contract: a 200, and an
// object whose keys are a subset of the five. Decoding into a map rather than
// the response struct is deliberate — a struct would silently discard a leaked
// claim, which is the thing under test.
func decodeIntrospection(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%v): %s", err, rec.Body.String())
	}
	allowed := map[string]bool{"active": true, "sub": true, "scope": true, "exp": true, "kind": true}
	for key := range out {
		if !allowed[key] {
			t.Errorf("response leaked a field outside the contract: %q (body: %s)", key, rec.Body.String())
		}
	}
	return out
}

func assertInactive(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	body := decodeIntrospection(t, rec)
	if body["active"] != false {
		t.Errorf("expected {\"active\":false}, got %s", rec.Body.String())
	}
	// Nothing else may be leaked alongside it: not a sub, not a reason.
	if len(body) != 1 {
		t.Errorf("an inactive answer must carry nothing but `active`, got %s", rec.Body.String())
	}
}

// TestIntrospectionRejectsEveryTokenThatDoesNotVerify is the table the route
// exists to get right. Each case is a token that must answer
// {"active":false} — never an error status, never a hint about which check
// failed.
func TestIntrospectionRejectsEveryTokenThatDoesNotVerify(t *testing.T) {
	router, _, _ := newTestRouter(t)

	cases := []struct {
		name  string
		token string
	}{
		{
			// Alg confusion #1: HS256 signed with the PEM public key as the
			// HMAC secret. Anyone can build this; only WithValidMethods stops it.
			name:  "alg confusion: HS256 signed with the RSA public key",
			token: signHS256WithPublicKey(testTokenOptions{scopes: []string{SCOPEAgentReset}}),
		},
		{
			// Alg confusion #2: no signature at all.
			name:  "alg confusion: alg=none",
			token: signAlgNone(testTokenOptions{scopes: []string{SCOPEAgentReset}}),
		},
		{
			name:  "signed by a key this service has never seen",
			token: signTestToken(foreignPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}}),
		},
		{
			// Beyond the 60 s leeway. 10 minutes is unambiguously dead.
			name:  "expired beyond the leeway",
			token: signTestToken(testPrivateKey, testTokenOptions{expiresInSeconds: -600}),
		},
		{
			// nbf far enough in the future that the leeway cannot rescue it.
			name:  "nbf beyond the leeway",
			token: signTestToken(testPrivateKey, testTokenOptions{notBeforeSeconds: 600}),
		},
		{name: "garbage", token: "not-a-jwt-at-all"},
		{name: "three dots of nothing", token: ".."},
		{name: "empty token", token: ""},
		{
			// A valid token whose payload has been tampered with keeps a
			// well-formed shape and a broken signature.
			name:  "tampered payload",
			token: tamperedToken(),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertInactive(t, introspect(t, router, c.token, testIntrospectionSecret, true))
		})
	}
}

// tamperedToken flips a character in the payload segment of an otherwise
// perfect token.
func tamperedToken() string {
	signed := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})
	parts := strings.SplitN(signed, ".", 3)
	payload := []byte(parts[1])
	if payload[0] == 'A' {
		payload[0] = 'B'
	} else {
		payload[0] = 'A'
	}
	return parts[0] + "." + string(payload) + "." + parts[2]
}

// TestIntrospectionPinsRS256AndRejectsTheOtherRSAAlgorithms is the test the alg
// pin never had. The two alg-confusion cases in the table above are stopped by
// the KEY TYPE — an *rsa.PublicKey can never be an HMAC secret and `none` has
// no signature to check — so they pass with or without
// jwt.WithValidMethods. RS384, RS512 and PS256 are different: they are signed
// by the trusted private key and verify against the trusted public key, so the
// alg pin in verifyToken is the only thing between them and an active answer.
//
// Why it matters that they are refused rather than merely "also fine": the
// fleet's three implementations agree on exactly one algorithm, and an
// algorithm the center silently accepts is one a future Clerk misconfiguration
// (or a downgrade toward PSS) can slip through without anybody noticing.
func TestIntrospectionPinsRS256AndRejectsTheOtherRSAAlgorithms(t *testing.T) {
	router, _, _ := newTestRouter(t)

	methods := []struct {
		name   string
		method jwt.SigningMethod
	}{
		{"RS384", jwt.SigningMethodRS384},
		{"RS512", jwt.SigningMethodRS512},
		{"PS256", jwt.SigningMethodPS256},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			token := signTestTokenWith(m.method, testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})

			// Sanity: this token really is signed by the key the service
			// trusts, so an inactive answer below can only be the alg pin and
			// not an accident of key material.
			if _, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) { return testPublicKey, nil },
				jwt.WithValidMethods([]string{m.name})); err != nil {
				t.Fatalf("the %s token does not verify against the trusted key at all (%v) — the case would prove nothing", m.name, err)
			}

			assertInactive(t, introspect(t, router, token, testIntrospectionSecret, true))

			// The same token on a vault route: one verification path, so it
			// must be refused there too, with the vault's own sentence.
			rec := doRequest(t, router, http.MethodPost, "/api/auth/v1/register", "Bearer "+token, `{}`)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("the vault route accepted a %s token: got %d (body: %s)", m.name, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid or expired session") {
				t.Errorf("the vault route's 401 sentence changed: %s", rec.Body.String())
			}
		})
	}
}

// TestAuthResponsesAreUncacheable — an authentication decision in a shared
// cache outlives the session it describes and can be served to a caller it was
// never about. Both writers are covered: writeIntrospection's 200 and
// writeAuthError's 401, on the introspection route and on a vault route, so
// dropping the header from either one fails here.
func TestAuthResponsesAreUncacheable(t *testing.T) {
	router, _, _ := newTestRouter(t)
	valid := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})

	assertNoStore := func(t *testing.T, rec *httptest.ResponseRecorder, what string) {
		t.Helper()
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control is %q, want %q (status %d)", what, got, "no-store", rec.Code)
		}
	}

	t.Run("introspection 401 about the caller secret", func(t *testing.T) {
		rec := introspect(t, router, valid, "the-wrong-secret", true)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected a 401, got %d", rec.Code)
		}
		assertNoStore(t, rec, "introspection 401")
	})

	t.Run("introspection 200 active", func(t *testing.T) {
		rec := introspect(t, router, valid, testIntrospectionSecret, true)
		if body := decodeIntrospection(t, rec); body["active"] != true {
			t.Fatalf("expected active, got %v", body)
		}
		assertNoStore(t, rec, "introspection 200 (active)")
	})

	t.Run("introspection 200 inactive", func(t *testing.T) {
		rec := introspect(t, router, "not-a-jwt-at-all", testIntrospectionSecret, true)
		assertInactive(t, rec)
		assertNoStore(t, rec, "introspection 200 (inactive)")
	})

	t.Run("vault route 401", func(t *testing.T) {
		rec := doRequest(t, router, http.MethodPost, "/api/auth/v1/register", foreignBearer(), `{}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected a 401, got %d", rec.Code)
		}
		assertNoStore(t, rec, "vault route 401")
	})

	t.Run("vault route 403 about a missing scope", func(t *testing.T) {
		rec := doRequest(t, router, http.MethodPost, "/api/auth/v1/register", bearerWithoutScope(), `{}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected a 403, got %d", rec.Code)
		}
		assertNoStore(t, rec, "vault route 403")
	})
}

// TestRequestLoggingNeverRecordsAQueryStringToken — the route already ignores a
// token in the query string, but ignoring it is only half the job: the access
// log is exactly the place a credential must not end up, and it is written by
// middleware that sees the raw request before the handler does. This captures
// the real log output for a request whose URL carries a live token and insists
// none of it survives.
func TestRequestLoggingNeverRecordsAQueryStringToken(t *testing.T) {
	router, _, _ := newTestRouter(t)
	valid := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})

	var captured bytes.Buffer
	logger := log.Default()
	originalOut, originalFlags := logger.Writer(), logger.Flags()
	logger.SetOutput(&captured)
	logger.SetFlags(0)
	t.Cleanup(func() {
		logger.SetOutput(originalOut)
		logger.SetFlags(originalFlags)
	})

	path := "/auth/v1/introspect?token=" + url.QueryEscape(valid)
	assertInactive(t, introspectRaw(t, router, path, "", testIntrospectionSecret, true))

	logged := captured.String()
	if !strings.Contains(logged, "/auth/v1/introspect") {
		t.Fatalf("the request was not logged at all, so this test would pass for the wrong reason: %q", logged)
	}
	if strings.Contains(logged, valid) {
		t.Errorf("the whole token was written to the log: %q", logged)
	}
	// The signature segment alone is enough to be a credential leak, and the
	// escaped form is what a raw RequestURI actually contains.
	for _, segment := range strings.Split(valid, ".") {
		if strings.Contains(logged, segment) || strings.Contains(logged, url.QueryEscape(segment)) {
			t.Errorf("a token segment reached the log: %q", logged)
		}
	}
	if strings.Contains(logged, "token=") || strings.Contains(logged, "?") {
		t.Errorf("the query string reached the log: %q", logged)
	}
}

// TestIntrospectionMissingTokenFieldIsInactive covers a caller that posts a
// well-formed form with no `token` at all. Still a 200 and still inactive —
// the route never answers 4xx about the token.
func TestIntrospectionMissingTokenFieldIsInactive(t *testing.T) {
	router, _, _ := newTestRouter(t)
	assertInactive(t, introspectRaw(t, router, "/auth/v1/introspect", "somethingelse=1", testIntrospectionSecret, true))
}

// TestIntrospectionAcceptsAValidTokenWithinTheLeeway pins both sides of the
// leeway boundary. A token 10 seconds past exp, and one whose nbf is 10
// seconds out, both verify; the matching "beyond" cases are in the rejection
// table above. Without these two the leeway could be zero and every other
// test would still pass.
func TestIntrospectionAcceptsAValidTokenWithinTheLeeway(t *testing.T) {
	router, _, _ := newTestRouter(t)

	t.Run("expired within the leeway", func(t *testing.T) {
		token := signTestToken(testPrivateKey, testTokenOptions{expiresInSeconds: -10})
		body := decodeIntrospection(t, introspect(t, router, token, testIntrospectionSecret, true))
		if body["active"] != true {
			t.Errorf("a token 10s past exp must be inside the 60s leeway, got %v", body)
		}
	})

	t.Run("nbf in the future within the leeway", func(t *testing.T) {
		token := signTestToken(testPrivateKey, testTokenOptions{notBeforeSeconds: 10})
		body := decodeIntrospection(t, introspect(t, router, token, testIntrospectionSecret, true))
		if body["active"] != true {
			t.Errorf("a token whose nbf is 10s out must be inside the 60s leeway, got %v", body)
		}
	})
}

// TestIntrospectionChecksTheIssuerWhenConfigured — CLERK_ISSUER is optional,
// but when it is set a token minted by another Clerk instance is inactive.
func TestIntrospectionChecksTheIssuerWhenConfigured(t *testing.T) {
	conn, p := newTestDeps(t)
	router, err := SetUpRouter(Config{
		Conn:                conn,
		Auth:                AuthConfig{ClerkJWTKeyPEM: testClerkPublicKeyPEM, ClerkIssuer: "https://clerk.example.test"},
		SharedSecret:        testSharedSecret,
		IntrospectionSecret: testIntrospectionSecret,
		Poller:              p,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong issuer", func(t *testing.T) {
		token := signTestToken(testPrivateKey, testTokenOptions{issuer: "https://evil.example.test"})
		assertInactive(t, introspect(t, router, token, testIntrospectionSecret, true))
	})
	t.Run("no issuer claim at all", func(t *testing.T) {
		token := signTestToken(testPrivateKey, testTokenOptions{})
		assertInactive(t, introspect(t, router, token, testIntrospectionSecret, true))
	})
	t.Run("right issuer", func(t *testing.T) {
		token := signTestToken(testPrivateKey, testTokenOptions{issuer: "https://clerk.example.test"})
		body := decodeIntrospection(t, introspect(t, router, token, testIntrospectionSecret, true))
		if body["active"] != true {
			t.Errorf("a correctly-issued token must be active, got %v", body)
		}
	})
}

// TestIntrospectionCallerSecret is the whole caller-authentication surface.
// A bad caller secret is a 401 with the fixture's exact sentence — not a 200
// with active:false, which would tell a misconfigured stack that every
// operator's session had died.
func TestIntrospectionCallerSecret(t *testing.T) {
	router, _, _ := newTestRouter(t)
	valid := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})

	cases := []struct {
		name       string
		secret     string
		sendSecret bool
	}{
		{"header absent entirely", "", false},
		{"empty header value", "", true},
		{"wrong secret", "not-the-secret", true},
		{"right secret with trailing whitespace", testIntrospectionSecret + " ", true},
		{"a prefix of the right secret", testIntrospectionSecret[:5], true},
		{
			// The load-bearing one: the vault's secret is held by st-gateway
			// and must not open this route. They are different secrets on
			// different code paths, and this proves it from outside.
			name: "the vault's shared secret presented as the introspection secret", secret: testSharedSecret, sendSecret: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := introspect(t, router, valid, c.secret, c.sendSecret)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("got status %d, want 401 (body: %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "a valid introspection secret is required") {
				t.Errorf("expected the fixture's exact sentence, got %s", rec.Body.String())
			}
			// A rejected caller must learn nothing about the token it sent.
			if strings.Contains(rec.Body.String(), "active") {
				t.Errorf("a rejected caller was told something about the token: %s", rec.Body.String())
			}
		})
	}
}

// TestIntrospectionFailsClosedWithNoConfiguredSecret is the production posture
// between this change and meta#80 step 3: the service starts, the route
// exists, and it accepts nobody — including a caller sending no header, which
// an `==` against an empty configured secret would have let straight through.
func TestIntrospectionFailsClosedWithNoConfiguredSecret(t *testing.T) {
	router, _, _ := newTestRouterWithIntrospectionSecret(t, "")
	valid := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})

	for _, c := range []struct {
		name       string
		secret     string
		sendSecret bool
	}{
		{"no header", "", false},
		{"empty header", "", true},
		{"any header", "anything-at-all", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := introspect(t, router, valid, c.secret, c.sendSecret)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("with no AUTH_INTROSPECTION_SECRET configured the route must reject every caller, got %d (body: %s)",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestIntrospectionRejectsGET — a token must never travel in a URL, so the
// route exists on POST only.
func TestIntrospectionRejectsGET(t *testing.T) {
	router, _, _ := newTestRouter(t)
	valid := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/introspect?token="+url.QueryEscape(valid), nil)
	req.Header.Set(IntrospectionSecretHeader, testIntrospectionSecret)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("GET must not be answered, got 200: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "active") {
		t.Errorf("a GET was given an introspection answer: %s", rec.Body.String())
	}
}

// TestIntrospectionIgnoresATokenInTheQueryString is the same rule from the
// other side: a POST whose body has no token but whose URL does is a request
// with no token. Honouring the query string would make it trivial for a
// caller to put a live credential into every access log on the host.
func TestIntrospectionIgnoresATokenInTheQueryString(t *testing.T) {
	router, _, _ := newTestRouter(t)
	valid := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})

	rec := introspectRaw(t, router, "/auth/v1/introspect?token="+url.QueryEscape(valid), "", testIntrospectionSecret, true)
	assertInactive(t, rec)

	// And a query-string token must not override, or rescue, the body's.
	rec = introspectRaw(t, router, "/auth/v1/introspect?token="+url.QueryEscape(valid), "token=garbage", testIntrospectionSecret, true)
	assertInactive(t, rec)
}

// TestIntrospectionRejectsAnOversizedBody — the route is reachable by four
// host-network services, so an unbounded form read is a memory amplifier. An
// oversized body cannot hold a token we would accept, so it is inactive rather
// than an error.
func TestIntrospectionRejectsAnOversizedBody(t *testing.T) {
	router, _, _ := newTestRouter(t)

	valid := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})

	// THE case that bites. A body of padding alone proves nothing: it holds no
	// token, so it is inactive with the cap AND inactive without it, and the
	// assertion cannot fail however the cap is broken. This body carries a
	// perfectly good token followed by padding that pushes the whole form past
	// the cap — active if the cap is gone, inactive only because it is there.
	form := url.Values{}
	form.Set("token", valid)
	withToken := form.Encode()
	padded := withToken + "&padding=" + strings.Repeat("A", maxIntrospectionBody*2)
	if len(withToken) >= maxIntrospectionBody {
		t.Fatalf("the token alone (%d bytes) already exceeds the cap (%d) — the case would pass for the wrong reason",
			len(withToken), maxIntrospectionBody)
	}

	rec := introspectRaw(t, router, "/auth/v1/introspect", padded, testIntrospectionSecret, true)
	if rec.Code == http.StatusOK {
		assertInactive(t, rec)
	} else if rec.Code < 400 {
		t.Fatalf("an oversized body must not be answered affirmatively, got %d", rec.Code)
	}

	// Padding with no token at all is inactive too, and stays a 200 rather than
	// an error status — an oversized body is not a client error here.
	huge := "token=" + strings.Repeat("A", maxIntrospectionBody*2)
	rec = introspectRaw(t, router, "/auth/v1/introspect", huge, testIntrospectionSecret, true)
	if rec.Code == http.StatusOK {
		assertInactive(t, rec)
	} else if rec.Code < 400 {
		t.Fatalf("an oversized body must not be answered affirmatively, got %d", rec.Code)
	}

	// The control: the very same token, unpadded, is still active. Together
	// with the case above this says the cap is a cap and not an outage — and it
	// is what stops someone "fixing" the padded case by breaking verification.
	rec = introspectRaw(t, router, "/auth/v1/introspect", withToken, testIntrospectionSecret, true)
	if body := decodeIntrospection(t, rec); body["active"] != true {
		t.Errorf("an ordinary token must still verify under the body cap, got %v", body)
	}
}

// TestIntrospectionNeverLeaksExtraClaims — Clerk session tokens carry `azp`,
// `sid`, `iat`, `jti` and whatever else the instance is configured to emit.
// Five fields leave this process and no more.
func TestIntrospectionNeverLeaksExtraClaims(t *testing.T) {
	router, _, _ := newTestRouter(t)

	token := signTestToken(testPrivateKey, testTokenOptions{
		scopes: []string{SCOPEAgentReset},
		extraClaims: map[string]interface{}{
			"azp":   "https://dashboard.example.test",
			"sid":   "sess_2SecretSession",
			"email": "operator@example.test",
			"jti":   "jti-should-not-escape",
			"act":   map[string]string{"sub": "user_2Impersonator"},
		},
	})

	rec := introspect(t, router, token, testIntrospectionSecret, true)
	body := decodeIntrospection(t, rec) // fails the case on any unexpected key
	if body["active"] != true {
		t.Fatalf("expected an active answer, got %v", body)
	}
	for _, leaked := range []string{"azp", "sid", "operator@example.test", "jti-should-not-escape", "user_2Impersonator"} {
		if strings.Contains(rec.Body.String(), leaked) {
			t.Errorf("response leaked %q: %s", leaked, rec.Body.String())
		}
	}
}

// TestIntrospectionDerivesKindFromTheSubjectPrefix — the center is the one
// place in the fleet that knows Clerk's `sub` conventions.
func TestIntrospectionDerivesKindFromTheSubjectPrefix(t *testing.T) {
	router, _, _ := newTestRouter(t)

	for _, c := range []struct{ sub, wantKind string }{
		{"user_31qP8k2cQeXampleOperator", "operator"},
		{"mch_31qP8k2cQeXampleMachine", "machine"},
		{"svc_something_else", "machine"},
		// Not a prefix match: `user` without the underscore is not an operator.
		{"userlike_2Thing", "machine"},
	} {
		t.Run(c.sub+"->"+c.wantKind, func(t *testing.T) {
			token := signTestToken(testPrivateKey, testTokenOptions{sub: c.sub})
			body := decodeIntrospection(t, introspect(t, router, token, testIntrospectionSecret, true))
			if body["kind"] != c.wantKind {
				t.Errorf("sub %q: got kind %v, want %q", c.sub, body["kind"], c.wantKind)
			}
		})
	}

	// A token with no `sub` at all cannot be minted through the helper above
	// (it substitutes a default), so the empty subject is pinned on the
	// function directly. It must never fall on the operator side.
	if k := (VerifiedToken{Subject: ""}).Kind(); k != "machine" {
		t.Errorf("an empty subject must be machine, got %q", k)
	}
}

// TestIntrospectionReturnsScopeVerbatim — the center does not normalise. An
// array claim is joined (the only transformation there is); a string claim
// comes back byte for byte, irregular whitespace included, because every
// client splits on whitespace runs and the fixture carries exactly such a
// string.
func TestIntrospectionReturnsScopeVerbatim(t *testing.T) {
	router, _, _ := newTestRouter(t)

	t.Run("string claim is untouched", func(t *testing.T) {
		raw := "fleet:control  agent:reset\tuniverse:refresh "
		token := signTestToken(testPrivateKey, testTokenOptions{scopeRaw: raw})
		body := decodeIntrospection(t, introspect(t, router, token, testIntrospectionSecret, true))
		if body["scope"] != raw {
			t.Errorf("scope was normalised: got %q, want %q", body["scope"], raw)
		}
	})

	t.Run("array claim becomes a space-delimited string", func(t *testing.T) {
		token := signTestToken(testPrivateKey, testTokenOptions{scopeArray: []string{"fleet:control", "agent:reset"}})
		body := decodeIntrospection(t, introspect(t, router, token, testIntrospectionSecret, true))
		if body["scope"] != "fleet:control agent:reset" {
			t.Errorf("got scope %q", body["scope"])
		}
	})

}

// TestIntrospectionAlwaysSendsScope pins the contract that an ACTIVE answer
// always carries the `scope` key, as "" when the token holds no scopes. RFC
// 7662 would allow leaving it out; our contract does not, because
// ts-introspection-client v1.1.0 treats a missing scope as a malformed answer
// and turns every session route into a 503 for a signed-in user with no
// scopes. The fixture only ever stubs `"scope":""`, and the fixture test
// marshals its expectation through the same struct, which is why nothing
// caught the omitempty that used to drop it. A verified session carrying
// nothing is the fixture's `session-route-with-scopeless-token`: active,
// empty scope, and it is the client that decides whether that is enough.
func TestIntrospectionAlwaysSendsScope(t *testing.T) {
	router, _, _ := newTestRouter(t)

	for _, tc := range []struct {
		name string
		opts testTokenOptions
	}{
		{"no scope claim at all", testTokenOptions{omitScope: true}},
		{"empty-string scope claim", testTokenOptions{}},
		{"empty-array scope claim", testTokenOptions{scopeArray: []string{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := signTestToken(testPrivateKey, tc.opts)
			rec := introspect(t, router, token, testIntrospectionSecret, true)
			body := decodeIntrospection(t, rec)
			if body["active"] != true {
				t.Fatalf("a scopeless session must still be active, got %s", rec.Body.String())
			}
			s, present := body["scope"]
			if !present {
				t.Fatalf("an active answer must carry the scope key even when empty, got %s", rec.Body.String())
			}
			if s != "" {
				t.Errorf("expected scope \"\", got %q", s)
			}
			if !strings.Contains(rec.Body.String(), `"scope":""`) {
				t.Errorf("expected a literal \"scope\":\"\" on the wire, got %s", rec.Body.String())
			}
		})
	}
}

// TestReadIntrospectionSecret covers the startup contract: unset is legal and
// yields the fail-closed empty string; equal to the vault secret is fatal.
func TestReadIntrospectionSecret(t *testing.T) {
	t.Run("unset starts the service with the route closed", func(t *testing.T) {
		os.Unsetenv("AUTH_INTROSPECTION_SECRET")
		secret, err := ReadIntrospectionSecret("vault-secret")
		if err != nil {
			t.Fatalf("an unset AUTH_INTROSPECTION_SECRET must not stop the service from starting: %v", err)
		}
		if secret != "" {
			t.Fatalf("expected the empty (fail-closed) secret, got %q", secret)
		}
	})

	t.Run("identical to the vault secret refuses to start", func(t *testing.T) {
		t.Setenv("AUTH_INTROSPECTION_SECRET", "same-value")
		if _, err := ReadIntrospectionSecret("same-value"); err == nil {
			t.Fatal("expected an error when the introspection and vault secrets are the same value")
		}
	})

	t.Run("a distinct secret is accepted", func(t *testing.T) {
		t.Setenv("AUTH_INTROSPECTION_SECRET", "introspection-value")
		secret, err := ReadIntrospectionSecret("vault-value")
		if err != nil || secret != "introspection-value" {
			t.Fatalf("got %q, %v", secret, err)
		}
	})
}

// TestSetUpRouterRefusesIdenticalSecrets is the second line of the same
// defence: no caller can assemble the collision by hand.
func TestSetUpRouterRefusesIdenticalSecrets(t *testing.T) {
	conn, p := newTestDeps(t)
	_, err := SetUpRouter(Config{
		Conn:                conn,
		Auth:                testAuthConfig(),
		SharedSecret:        "one-secret",
		IntrospectionSecret: "one-secret",
		Poller:              p,
	})
	if err == nil {
		t.Fatal("expected SetUpRouter to refuse an introspection secret equal to the vault's shared secret")
	}
}
