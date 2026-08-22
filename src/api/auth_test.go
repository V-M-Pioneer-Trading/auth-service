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

func newTestRouter(t *testing.T) (http.Handler, *sql.DB, *poller.Poller) {
	t.Helper()
	conn, err := db.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	p := &poller.Poller{
		Conn:      conn,
		Clock:     time.Now,
		FetchRoot: func(string) (spacetraders.RootInfo, error) { return spacetraders.RootInfo{}, nil },
		Register: func(accountToken, symbol, faction, email, priority string) (spacetraders.RegisterResult, error) {
			return spacetraders.RegisterResult{AgentToken: "minted-token", AgentSymbol: symbol, Credits: 175000}, nil
		},
	}

	router, err := SetUpRouter(Config{Conn: conn, Auth: testAuthConfig(), SharedSecret: testSharedSecret, Poller: p})
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
