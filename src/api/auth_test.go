package api

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"vnm/auth-service/db"
	"vnm/auth-service/poller"
	"vnm/auth-service/spacetraders"
)

// newTestDeps is the in-memory database and stubbed poller every router in
// this package's tests is built on.
func newTestDeps(t *testing.T) (*sql.DB, *poller.Poller) {
	t.Helper()
	conn, err := db.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	return conn, &poller.Poller{
		Conn:      conn,
		Clock:     time.Now,
		FetchRoot: func() (spacetraders.RootInfo, error) { return spacetraders.RootInfo{}, nil },
		Register: func(accountToken, symbol, faction, email string) (spacetraders.RegisterResult, error) {
			return spacetraders.RegisterResult{AgentToken: "minted-token", AgentSymbol: symbol, Credits: 175000}, nil
		},
	}
}

func newTestRouter(t *testing.T) (http.Handler, *sql.DB, *poller.Poller) {
	return newTestRouterWithIntrospectionSecret(t, testIntrospectionSecret)
}

func newTestRouterWithIntrospectionSecret(t *testing.T, introspectionSecret string) (http.Handler, *sql.DB, *poller.Poller) {
	t.Helper()
	conn, p := newTestDeps(t)

	router, err := SetUpRouter(Config{
		Conn:                conn,
		Auth:                testAuthConfig(),
		SharedSecret:        testSharedSecret,
		IntrospectionSecret: introspectionSecret,
		Poller:              p,
	})
	if err != nil {
		t.Fatalf("SetUpRouter: %v", err)
	}
	return router, conn, p
}

func doRequest(t *testing.T, router http.Handler, method, path, authorization, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *strings.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	} else {
		reqBody = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reqBody)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestScopeGatedMutationsRejectWithoutAValidSession(t *testing.T) {
	router, _, _ := newTestRouter(t)

	cases := []struct {
		name          string
		path          string
		authorization string
		wantStatus    int
	}{
		{"no Authorization header at all", "/api/auth/v1/register", "", http.StatusUnauthorized},
		{"expired session", "/api/auth/v1/register", expiredBearer(), http.StatusUnauthorized},
		{"signed by an untrusted key", "/api/auth/v1/register", foreignBearer(), http.StatusUnauthorized},
		{"valid session but no agent:reset scope", "/api/auth/v1/register", bearerWithoutScope(), http.StatusForbidden},
		{"agent-token: no session", "/api/auth/v1/agent-token", "", http.StatusUnauthorized},
		{"agent-token: no scope", "/api/auth/v1/agent-token", bearerWithoutScope(), http.StatusForbidden},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := doRequest(t, router, http.MethodPost, c.path, c.authorization, `{}`)
			if rec.Code != c.wantStatus {
				t.Errorf("got status %d, want %d (body: %s)", rec.Code, c.wantStatus, rec.Body.String())
			}
		})
	}
}

// GET /auth/v1/status is deliberately public — decision 6/8's whole point is
// that anonymous visitors see the lifecycle banners too, and it never
// returns a token in any state.
func TestPublicRoutesNeedNoSessionAtAll(t *testing.T) {
	router, _, _ := newTestRouter(t)

	for _, path := range []string{"/auth/v1/status", "/api/auth/v1/status", "/health", "/api/auth/health"} {
		t.Run(path, func(t *testing.T) {
			rec := doRequest(t, router, http.MethodGet, path, "", "")
			if rec.Code != http.StatusOK {
				t.Errorf("%s: got status %d, want 200 (body: %s)", path, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestStatusReportsUnconfiguredBeforeAnyRegistration(t *testing.T) {
	router, _, _ := newTestRouter(t)
	rec := doRequest(t, router, http.MethodGet, "/auth/v1/status", "", "")
	if !strings.Contains(rec.Body.String(), "UNCONFIGURED") {
		t.Errorf("expected UNCONFIGURED in status body, got %s", rec.Body.String())
	}
}

func TestGetTokenRequiresTheSharedSecret(t *testing.T) {
	router, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/token", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with no shared secret, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/auth/v1/token", nil)
	req.Header.Set("X-Auth-Service-Secret", "wrong-secret")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with a wrong shared secret, got %d", rec.Code)
	}
}

func TestGetTokenReturns503WhenUnconfigured(t *testing.T) {
	router, _, _ := newTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/token", nil)
	req.Header.Set("X-Auth-Service-Secret", testSharedSecret)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when UNCONFIGURED, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// End-to-end through the real handlers: register mints a credential, then
// the shared-secret-gated token route can hand it back to a "st-gateway"
// caller, and status flips out of UNCONFIGURED.
func TestRegisterThenGetTokenEndToEnd(t *testing.T) {
	router, _, _ := newTestRouter(t)

	registerRec := doRequest(t, router, http.MethodPost, "/api/auth/v1/register", bearer(),
		`{"accountToken":"acc-token","symbol":"RADOMSKY","faction":"COSMIC"}`)
	if registerRec.Code != http.StatusOK {
		t.Fatalf("register: got status %d, want 200 (body: %s)", registerRec.Code, registerRec.Body.String())
	}

	statusRec := doRequest(t, router, http.MethodGet, "/auth/v1/status", "", "")
	if strings.Contains(statusRec.Body.String(), "UNCONFIGURED") {
		t.Fatalf("expected status to leave UNCONFIGURED after registration, got %s", statusRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/token", nil)
	req.Header.Set("X-Auth-Service-Secret", testSharedSecret)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: got status %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "minted-token") {
		t.Fatalf("expected the newly minted token in the response, got %s", rec.Body.String())
	}
}

func TestRestoreTokenRequiresAnExistingCredential(t *testing.T) {
	router, _, _ := newTestRouter(t)

	rec := doRequest(t, router, http.MethodPost, "/api/auth/v1/agent-token", bearer(), `{"agentToken":"new-token"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 restoring a token onto an unconfigured service, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestVaultRoutesShareTheIntrospectionVerifier proves decision 21's
// "one verification code path" from outside: every token the introspection
// route calls inactive must also be refused by the vault's two routes, with
// their own unchanged 401 sentence. If someone reintroduces a second
// jwt.Parse in requireScope, one of these two halves drifts and this fails.
func TestVaultRoutesShareTheIntrospectionVerifier(t *testing.T) {
	router, _, _ := newTestRouter(t)

	tokens := map[string]string{
		"alg confusion: HS256 signed with the public key": signHS256WithPublicKey(testTokenOptions{scopes: []string{SCOPEAgentReset}}),
		"alg confusion: alg=none":                         signAlgNone(testTokenOptions{scopes: []string{SCOPEAgentReset}}),
		"expired beyond the leeway":                       signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}, expiresInSeconds: -600}),
		"nbf beyond the leeway":                           signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}, notBeforeSeconds: 600}),
		"foreign signature":                               signTestToken(foreignPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}}),
	}

	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			assertInactive(t, introspect(t, router, token, testIntrospectionSecret, true))

			rec := doRequest(t, router, http.MethodPost, "/api/auth/v1/register", "Bearer "+token, `{}`)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("the vault route accepted a token introspection calls inactive: got %d (body: %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid or expired session") {
				t.Errorf("the vault route's 401 sentence changed: %s", rec.Body.String())
			}
		})
	}

	// And the mirror: a token introspection calls active, carrying the scope,
	// still gets through the vault route unchanged.
	t.Run("an active scoped token still passes the vault route", func(t *testing.T) {
		token := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})
		body := decodeIntrospection(t, introspect(t, router, token, testIntrospectionSecret, true))
		if body["active"] != true {
			t.Fatalf("expected active, got %v", body)
		}
		// 409 rather than 200: there is no credential to restore onto yet,
		// which is past the auth guard and is the pre-existing behaviour.
		rec := doRequest(t, router, http.MethodPost, "/api/auth/v1/agent-token", "Bearer "+token, `{"agentToken":"t"}`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("expected the request to reach the handler (409), got %d (body: %s)", rec.Code, rec.Body.String())
		}
	})
}

func TestRequireClerkJWTKeyFailsClosed(t *testing.T) {
	os.Unsetenv("CLERK_JWT_KEY")
	os.Unsetenv("CLERK_JWT_KEY_FILE")

	if _, err := RequireClerkJWTKey(); err == nil {
		t.Fatal("expected an error with neither CLERK_JWT_KEY nor CLERK_JWT_KEY_FILE set")
	}
}

func TestRequireSharedSecretFailsClosed(t *testing.T) {
	os.Unsetenv("AUTH_SERVICE_SHARED_SECRET")

	if _, err := RequireSharedSecret(); err == nil {
		t.Fatal("expected an error with AUTH_SERVICE_SHARED_SECRET unset")
	}
}
