package api

// Tests for POST /auth/v1/m2m-token (decision 22). Clerk is an httptest
// server that signs real RS256 tokens with the test key and records every
// request; the clock is injected, so the half-lifetime refresh and the
// stale-but-valid fallback are exercised at exact instants rather than slept
// through.

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testAutomationCallerSecret = "test-m2m-automation-secret"
	testAICallerSecret         = "test-m2m-ai-secret"
	testAutomationMachineKey   = "ak_test_automation_machine"
	testAIMachineKey           = "ak_test_ai_machine"
)

// fakeClock is the cache's `now`. The fake Clerk stamps `iat` from the same
// clock, so "half the lifetime has passed" means the same thing on both sides.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_900_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type clerkRequest struct {
	authorization string
	body          map[string]interface{}
}

// fakeClerk stands in for POST https://api.clerk.com/v1/m2m_tokens. It mints
// the way Clerk does: `sub` names the Machine the bearer key belongs to, the
// request's `claims` land flat in the token, and `exp` is `iat` plus
// seconds_until_expiration (or Clerk's default hour when it is absent, so a
// minter that forgets the field is caught by expires_at, not only by the
// recorded body).
type fakeClerk struct {
	t     *testing.T
	clock *fakeClock

	mu       sync.Mutex
	requests []clerkRequest
	fail     bool
	// payload, when set, replaces the token's claims wholesale: for tokens
	// with no usable lifetime.
	payload jwt.MapClaims
	// gate, when set, holds every request until it is closed; arrived is
	// signalled as each request comes in.
	gate    chan struct{}
	arrived chan struct{}

	server *httptest.Server
}

func newFakeClerk(t *testing.T, clock *fakeClock) *fakeClerk {
	f := &fakeClerk{t: t, clock: clock}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeClerk) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Errorf("fake Clerk: request body is not JSON: %v", err)
	}
	f.mu.Lock()
	f.requests = append(f.requests, clerkRequest{authorization: r.Header.Get("Authorization"), body: body})
	gate, arrived, fail, payload, n := f.gate, f.arrived, f.fail, f.payload, len(f.requests)
	f.mu.Unlock()

	if arrived != nil {
		arrived <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":[{"message":"clerk is down"}]}`))
		return
	}

	claims := jwt.MapClaims{}
	if payload != nil {
		claims = payload
	} else {
		lifetime := int64(3600)
		if s, ok := body["seconds_until_expiration"].(float64); ok {
			lifetime = int64(s)
		}
		iat := f.clock.Now().Unix()
		claims["sub"] = "mch_" + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims["iat"] = iat
		claims["exp"] = iat + lifetime
		if extra, ok := body["claims"].(map[string]interface{}); ok {
			for k, v := range extra {
				claims[k] = v
			}
		}
		// A per-request nonce, so two mints at the same instant are still two
		// different tokens and a test can tell a cache hit from a re-mint.
		claims["jti"] = n
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(testPrivateKey)
	if err != nil {
		f.t.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"object": "machine_to_machine_token", "token": token})
}

func (f *fakeClerk) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeClerk) setFail(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
}

// clerkM2MConfig is both callers enabled, minting through the fake Clerk.
func clerkM2MConfig(clerk *fakeClerk, clock *fakeClock) M2MConfig {
	return M2MConfig{
		Callers: []M2MCallerConfig{
			{Name: "automation-service", Secret: testAutomationCallerSecret, MachineKey: testAutomationMachineKey},
			{Name: "ai-service", Secret: testAICallerSecret, MachineKey: testAIMachineKey},
		},
		clerkURL:   clerk.server.URL,
		httpClient: clerk.server.Client(),
		now:        clock.Now,
	}
}

func newM2MTestRouter(t *testing.T, auth AuthConfig, m2m M2MConfig) http.Handler {
	t.Helper()
	conn, p := newTestDeps(t)
	router, err := SetUpRouter(Config{
		Conn:                conn,
		Auth:                auth,
		SharedSecret:        testSharedSecret,
		IntrospectionSecret: testIntrospectionSecret,
		M2M:                 m2m,
		Poller:              p,
	})
	if err != nil {
		t.Fatalf("SetUpRouter: %v", err)
	}
	return router
}

func requestM2M(t *testing.T, router http.Handler, method, secret string, sendSecret bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/auth/v1/m2m-token", nil)
	if sendSecret {
		req.Header.Set(M2MCallerSecretHeader, secret)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decodeMinted insists on exactly the 200 contract: JSON, two keys, a JWT and
// an integer expires_at.
func decodeMinted(t *testing.T, rec *httptest.ResponseRecorder) (string, int64) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("response is not JSON (%v): %s", err, rec.Body.String())
	}
	if len(raw) != 2 || raw["token"] == nil || raw["expires_at"] == nil {
		t.Fatalf("want exactly {token, expires_at}, got %s", rec.Body.String())
	}
	var token string
	var expiresAt int64
	if err := json.Unmarshal(raw["token"], &token); err != nil || strings.Count(token, ".") != 2 {
		t.Fatalf("token is not a JWT string: %s", raw["token"])
	}
	if err := json.Unmarshal(raw["expires_at"], &expiresAt); err != nil {
		t.Fatalf("expires_at is not an integer: %s", raw["expires_at"])
	}
	return token, expiresAt
}

func assertM2MError(t *testing.T, rec *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("got status %d, want %d (body: %s)", rec.Code, status, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	want := `{"error":"` + message + `"}`
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func claimsOf(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// TestM2MTokenContract is the contract table in token-introspection.md,
// row by row, plus the ways a secret can be wrong.
func TestM2MTokenContract(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		secret     string
		sendSecret bool
		clerkDown  bool
		wantStatus int
		wantError  string
		wantSub    string
		wantScope  string
	}{
		{name: "automation-service mints", method: "POST", secret: testAutomationCallerSecret, sendSecret: true,
			wantStatus: 200, wantSub: "mch_" + testAutomationMachineKey, wantScope: "fleet:control"},
		{name: "ai-service mints", method: "POST", secret: testAICallerSecret, sendSecret: true,
			wantStatus: 200, wantSub: "mch_" + testAIMachineKey, wantScope: "events:write planner:advise"},
		{name: "missing secret", method: "POST", sendSecret: false, wantStatus: 401, wantError: m2mUnknownCaller},
		{name: "empty secret", method: "POST", secret: "", sendSecret: true, wantStatus: 401, wantError: m2mUnknownCaller},
		{name: "unknown secret", method: "POST", secret: "not-a-caller", sendSecret: true, wantStatus: 401, wantError: m2mUnknownCaller},
		{name: "a prefix of a real secret", method: "POST", secret: testAutomationCallerSecret[:8], sendSecret: true, wantStatus: 401, wantError: m2mUnknownCaller},
		{name: "a real secret with a suffix", method: "POST", secret: testAutomationCallerSecret + "x", sendSecret: true, wantStatus: 401, wantError: m2mUnknownCaller},
		{name: "the introspection secret mints nothing", method: "POST", secret: testIntrospectionSecret, sendSecret: true, wantStatus: 401, wantError: m2mUnknownCaller},
		{name: "the vault secret mints nothing", method: "POST", secret: testSharedSecret, sendSecret: true, wantStatus: 401, wantError: m2mUnknownCaller},
		{name: "Clerk down and nothing cached", method: "POST", secret: testAutomationCallerSecret, sendSecret: true, clerkDown: true,
			wantStatus: 503, wantError: m2mMintFailed},
		{name: "GET", method: "GET", secret: testAutomationCallerSecret, sendSecret: true, wantStatus: 405},
		{name: "PUT", method: "PUT", secret: testAutomationCallerSecret, sendSecret: true, wantStatus: 405},
		{name: "PATCH", method: "PATCH", secret: testAutomationCallerSecret, sendSecret: true, wantStatus: 405},
		{name: "DELETE", method: "DELETE", secret: testAutomationCallerSecret, sendSecret: true, wantStatus: 405},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock()
			clerk := newFakeClerk(t, clock)
			clerk.setFail(tc.clerkDown)
			router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

			rec := requestM2M(t, router, tc.method, tc.secret, tc.sendSecret)
			switch {
			case tc.wantStatus == 200:
				token, expiresAt := decodeMinted(t, rec)
				claims := claimsOf(t, token)
				if claims["sub"] != tc.wantSub {
					t.Errorf("sub = %v, want %s: the token was minted with the wrong Machine key", claims["sub"], tc.wantSub)
				}
				if claims["scope"] != tc.wantScope {
					t.Errorf("scope = %v, want %q", claims["scope"], tc.wantScope)
				}
				if want := int64(claims["exp"].(float64)); expiresAt != want {
					t.Errorf("expires_at = %d, want the token's exp %d", expiresAt, want)
				}
			case tc.wantError != "":
				assertM2MError(t, rec, tc.wantStatus, tc.wantError)
			default:
				if rec.Code != tc.wantStatus {
					t.Fatalf("got status %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
				}
			}
			if tc.wantStatus != 200 && tc.wantStatus != 503 && clerk.calls() != 0 {
				t.Errorf("a rejected request reached Clerk %d time(s); only a known caller may cost money", clerk.calls())
			}
		})
	}
}

// TestM2MClerkRequestShape pins the body Clerk receives: 24 h, JWT format,
// the caller's fixed scope and nothing a caller could have influenced, sent
// with that caller's own Machine key.
func TestM2MClerkRequestShape(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	decodeMinted(t, requestM2M(t, router, "POST", testAICallerSecret, true))

	want := []struct {
		auth  string
		scope string
	}{
		{"Bearer " + testAutomationMachineKey, "fleet:control"},
		{"Bearer " + testAIMachineKey, "events:write planner:advise"},
	}
	requests := clerk.snapshot()
	if len(requests) != len(want) {
		t.Fatalf("Clerk got %d requests, want %d", len(requests), len(want))
	}
	for i, w := range want {
		got := requests[i]
		if got.authorization != w.auth {
			t.Errorf("request %d: Authorization = %q, want %q", i, got.authorization, w.auth)
		}
		if got.body["token_format"] != "jwt" {
			t.Errorf("request %d: token_format = %v, want jwt", i, got.body["token_format"])
		}
		if got.body["seconds_until_expiration"] != float64(86400) {
			t.Errorf("request %d: seconds_until_expiration = %v, want 86400", i, got.body["seconds_until_expiration"])
		}
		claims, _ := got.body["claims"].(map[string]interface{})
		if len(claims) != 1 || claims["scope"] != w.scope {
			t.Errorf("request %d: claims = %v, want exactly {scope: %q}", i, got.body["claims"], w.scope)
		}
	}
}

// TestM2MCacheServesUntilHalfLifetimeThenRefreshes: one mint for every
// request in the first 12 h, and expires_at is the token's exp, not a
// recomputation from the clock.
func TestM2MCacheServesUntilHalfLifetimeThenRefreshes(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))
	mintedAt := clock.Now().Unix()

	first, expiresAt := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	if expiresAt != mintedAt+86400 {
		t.Errorf("expires_at = %d, want iat+86400 = %d", expiresAt, mintedAt+86400)
	}

	clock.Advance(12*time.Hour - time.Second)
	again, againExpires := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	if again != first || againExpires != expiresAt {
		t.Fatal("a request before half the lifetime got a different token: the cache was not used")
	}
	if clerk.calls() != 1 {
		t.Fatalf("Clerk was called %d times before half the lifetime, want 1", clerk.calls())
	}

	clock.Advance(time.Second)
	refreshed, refreshedExpires := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	if refreshed == first {
		t.Fatal("at half the lifetime the cached token was served again instead of a fresh mint")
	}
	if clerk.calls() != 2 {
		t.Fatalf("Clerk was called %d times, want 2", clerk.calls())
	}
	if refreshedExpires != clock.Now().Unix()+86400 {
		t.Errorf("refreshed expires_at = %d, want %d", refreshedExpires, clock.Now().Unix()+86400)
	}

	// The two callers' caches are separate: ai-service's first request
	// mints, and gets its own token rather than automation-service's.
	aiToken, _ := decodeMinted(t, requestM2M(t, router, "POST", testAICallerSecret, true))
	if aiToken == refreshed || clerk.calls() != 3 {
		t.Fatalf("ai-service was served from automation-service's cache (calls: %d)", clerk.calls())
	}
}

// TestM2MRefreshPointFollowsTheTokensOwnLifetime: the refresh point is half
// of exp-iat as the token says, not half of the 24 h we asked for. A Clerk
// that shortens the lifetime must not leave us serving an expired token.
func TestM2MRefreshPointFollowsTheTokensOwnLifetime(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	iat := clock.Now().Unix()
	clerk.payload = jwt.MapClaims{"sub": "mch_x", "scope": "fleet:control", "iat": iat, "exp": iat + 600}
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	_, expiresAt := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	if expiresAt != iat+600 {
		t.Errorf("expires_at = %d, want %d", expiresAt, iat+600)
	}
	clock.Advance(299 * time.Second)
	decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	if clerk.calls() != 1 {
		t.Fatalf("re-minted before half of a 600 s lifetime (calls: %d)", clerk.calls())
	}
	clock.Advance(time.Second)
	decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	if clerk.calls() != 2 {
		t.Fatalf("did not re-mint at half of a 600 s lifetime (calls: %d)", clerk.calls())
	}
}

// TestM2MTokenWithoutALifetimeIsAFailedMint: a token with no iat/exp cannot
// be scheduled, so it is refused and not cached.
func TestM2MTokenWithoutALifetimeIsAFailedMint(t *testing.T) {
	for name, payload := range map[string]jwt.MapClaims{
		"no exp":         {"sub": "mch_x", "iat": 1_900_000_000},
		"no iat":         {"sub": "mch_x", "exp": 1_900_086_400},
		"exp before iat": {"sub": "mch_x", "iat": 1_900_000_000, "exp": 1_899_000_000},
	} {
		t.Run(name, func(t *testing.T) {
			clock := newFakeClock()
			clerk := newFakeClerk(t, clock)
			clerk.payload = payload
			router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

			assertM2MError(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)
			requestM2M(t, router, "POST", testAutomationCallerSecret, true)
			if clerk.calls() != 2 {
				t.Errorf("the unusable token was cached (calls: %d, want 2)", clerk.calls())
			}
		})
	}
}

// TestM2MConcurrentRequestsMintOnce: every mint is billed, so twenty callers
// arriving while a mint is in flight must share it.
func TestM2MConcurrentRequestsMintOnce(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	clerk.gate = make(chan struct{})
	clerk.arrived = make(chan struct{}, 100)
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	const n = 20
	tokens := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := requestM2M(t, router, "POST", testAutomationCallerSecret, true)
			if rec.Code == http.StatusOK {
				var out m2mTokenResponse
				json.Unmarshal(rec.Body.Bytes(), &out)
				tokens[i] = out.Token
			}
		}(i)
	}
	<-clerk.arrived
	// Give every other goroutine time to arrive while the first mint is held
	// open. A correct cache is right whatever this timing is (a latecomer gets
	// a cache hit); an incorrect one reaches Clerk again inside this window.
	time.Sleep(100 * time.Millisecond)
	close(clerk.gate)
	wg.Wait()

	if clerk.calls() != 1 {
		t.Fatalf("Clerk was called %d times for %d concurrent requests, want 1", clerk.calls(), n)
	}
	for i, tok := range tokens {
		if tok == "" || tok != tokens[0] {
			t.Fatalf("request %d did not get the one shared token", i)
		}
	}
}

// TestM2MStaleButValidFallback: past the refresh point a failed mint serves
// the cached token right up to its expiry, and a 503 only after it.
func TestM2MStaleButValidFallback(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	first, expiresAt := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	clerk.setFail(true)

	clock.Advance(24*time.Hour - time.Second)
	stale, staleExpires := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	if stale != first || staleExpires != expiresAt {
		t.Fatal("a failed refresh did not fall back to the still-valid cached token")
	}
	if clerk.calls() != 2 {
		t.Fatalf("past the refresh point a request must try Clerk first (calls: %d, want 2)", clerk.calls())
	}

	clock.Advance(time.Second)
	assertM2MError(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)

	// And it recovers: Clerk back, next request mints.
	clerk.setFail(false)
	fresh, _ := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
	if fresh == first {
		t.Fatal("after recovery the expired token was served")
	}
}

// TestM2MSecretsNeverReachTheLog: a 401 names no caller and no secret, and a
// 503 names the caller (an operator needs to know which Machine failed) but
// neither its secret nor its Machine key.
func TestM2MSecretsNeverReachTheLog(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	buf.Reset()
	rec := requestM2M(t, router, "POST", testAutomationCallerSecret+"-wrong", true)
	for _, leaked := range []string{testAutomationCallerSecret, "automation-service", "ai-service"} {
		if strings.Contains(buf.String(), leaked) || strings.Contains(rec.Body.String(), leaked) {
			t.Errorf("a 401 leaked %q (log: %q, body: %q)", leaked, buf.String(), rec.Body.String())
		}
	}

	clerk.setFail(true)
	buf.Reset()
	rec = requestM2M(t, router, "POST", testAutomationCallerSecret, true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	for _, leaked := range []string{testAutomationCallerSecret, testAutomationMachineKey} {
		if strings.Contains(buf.String(), leaked) || strings.Contains(rec.Body.String(), leaked) {
			t.Errorf("a 503 leaked a secret (log: %q, body: %q)", buf.String(), rec.Body.String())
		}
	}
	// Caller name and Clerk's status: what an operator needs to act on.
	if !strings.Contains(buf.String(), "automation-service") || !strings.Contains(buf.String(), "500") {
		t.Errorf("a failed mint should name the caller and Clerk's status in the log, got %q", buf.String())
	}
}

// TestM2MUnsetCallerIsDisabled: a caller with a machine key but no caller
// secret answers 401 like a stranger, and does not stop the other caller.
func TestM2MUnsetCallerIsDisabled(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	cfg := clerkM2MConfig(clerk, clock)
	cfg.Callers[1].Secret = ""
	router := newM2MTestRouter(t, testAuthConfig(), cfg)

	assertM2MError(t, requestM2M(t, router, "POST", testAICallerSecret, true), 401, m2mUnknownCaller)
	assertM2MError(t, requestM2M(t, router, "POST", "", true), 401, m2mUnknownCaller)
	decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))

	// And with no configuration at all the route still exists and rejects.
	bare := newM2MTestRouter(t, testAuthConfig(), M2MConfig{})
	assertM2MError(t, requestM2M(t, bare, "POST", testAutomationCallerSecret, true), 401, m2mUnknownCaller)
}

func testDevKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TestM2MDevTokenIntrospectsAsTheMachine is decision 22's "callers have one
// code path everywhere" proved locally: a dev-minted token sent to this same
// service's introspection comes back active, as a machine, with the caller's
// scope — including when CLERK_ISSUER is set, which is why the dev token
// carries `iss`.
func TestM2MDevTokenIntrospectsAsTheMachine(t *testing.T) {
	for _, issuer := range []string{"", "https://clerk.example.test"} {
		t.Run("issuer="+issuer, func(t *testing.T) {
			auth := testAuthConfig()
			auth.ClerkIssuer = issuer
			router := newM2MTestRouter(t, auth, M2MConfig{
				Callers: []M2MCallerConfig{
					{Name: "automation-service", Secret: testAutomationCallerSecret},
					{Name: "ai-service", Secret: testAICallerSecret},
				},
				DevSigningKeyPEM: testDevKeyPEM(t, testPrivateKey),
				Issuer:           issuer,
			})

			for _, c := range []struct{ secret, caller, scope string }{
				{testAutomationCallerSecret, "automation-service", "fleet:control"},
				{testAICallerSecret, "ai-service", "events:write planner:advise"},
			} {
				token, expiresAt := decodeMinted(t, requestM2M(t, router, "POST", c.secret, true))

				body := decodeIntrospection(t, introspect(t, router, token, testIntrospectionSecret, true))
				if body["active"] != true {
					t.Fatalf("%s: the dev token did not introspect as active: %v", c.caller, body)
				}
				if body["kind"] != "machine" {
					t.Errorf("%s: kind = %v, want machine", c.caller, body["kind"])
				}
				if body["sub"] != "mch_local_"+c.caller {
					t.Errorf("%s: sub = %v, want mch_local_%s", c.caller, body["sub"], c.caller)
				}
				if body["scope"] != c.scope {
					t.Errorf("%s: scope = %v, want %q", c.caller, body["scope"], c.scope)
				}
				if int64(body["exp"].(float64)) != expiresAt {
					t.Errorf("%s: expires_at %d disagrees with the token's exp %v", c.caller, expiresAt, body["exp"])
				}

				parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Header["alg"] != "RS256" || parsed.Header["typ"] != "JWT" || parsed.Header["kid"] != "dev-only-do-not-use" {
					t.Errorf("%s: header = %v", c.caller, parsed.Header)
				}
				claims := parsed.Claims.(jwt.MapClaims)
				if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != 86400 {
					t.Errorf("%s: lifetime = %v s, want 86400", c.caller, exp-iat)
				}
			}
		})
	}
}

// TestM2MStartupRejectsUnsafeConfig: every fail-closed rule, through both
// entry points — SetUpRouter's own check and the environment reader main
// uses — and no error message may carry a secret's value.
func TestM2MStartupRejectsUnsafeConfig(t *testing.T) {
	devKey := testDevKeyPEM(t, testPrivateKey)
	cases := []struct {
		name    string
		callers []M2MCallerConfig
		dev     bool
	}{
		{name: "secret but no machine key and no dev key",
			callers: []M2MCallerConfig{{Name: "automation-service", Secret: "caller-a"}}},
		{name: "machine key and dev key both set",
			callers: []M2MCallerConfig{{Name: "automation-service", Secret: "caller-a", MachineKey: "ak_a"}}, dev: true},
		{name: "machine key and dev key both set, caller disabled",
			callers: []M2MCallerConfig{{Name: "ai-service", MachineKey: "ak_b"}}, dev: true},
		{name: "caller secret equals the vault secret",
			callers: []M2MCallerConfig{{Name: "automation-service", Secret: testSharedSecret, MachineKey: "ak_a"}}},
		{name: "caller secret equals the introspection secret",
			callers: []M2MCallerConfig{{Name: "ai-service", Secret: testIntrospectionSecret, MachineKey: "ak_b"}}},
		{name: "two callers share a secret", callers: []M2MCallerConfig{
			{Name: "automation-service", Secret: "same-secret", MachineKey: "ak_a"},
			{Name: "ai-service", Secret: "same-secret", MachineKey: "ak_b"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := M2MConfig{Callers: tc.callers}
			if tc.dev {
				cfg.DevSigningKeyPEM = devKey
			}
			conn, p := newTestDeps(t)
			_, err := SetUpRouter(Config{
				Conn: conn, Auth: testAuthConfig(), SharedSecret: testSharedSecret,
				IntrospectionSecret: testIntrospectionSecret, M2M: cfg, Poller: p,
			})
			assertStartupError(t, "SetUpRouter", err, tc.callers)

			// The same configuration through the environment.
			t.Setenv("M2M_CALLER_SECRET_AUTOMATION_SERVICE", "")
			t.Setenv("M2M_CALLER_SECRET_AI_SERVICE", "")
			t.Setenv("M2M_MACHINE_KEY_AUTOMATION_SERVICE", "")
			t.Setenv("M2M_MACHINE_KEY_AI_SERVICE", "")
			t.Setenv("DEV_M2M_SIGNING_KEY_FILE", "")
			for _, c := range tc.callers {
				suffix := map[string]string{"automation-service": "AUTOMATION_SERVICE", "ai-service": "AI_SERVICE"}[c.Name]
				t.Setenv("M2M_CALLER_SECRET_"+suffix, c.Secret)
				t.Setenv("M2M_MACHINE_KEY_"+suffix, c.MachineKey)
			}
			if tc.dev {
				path := filepath.Join(t.TempDir(), "dev.key.pem")
				if err := os.WriteFile(path, []byte(devKey), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("DEV_M2M_SIGNING_KEY_FILE", path)
			}
			_, err = ReadM2MConfig(testSharedSecret, testIntrospectionSecret)
			assertStartupError(t, "ReadM2MConfig", err, tc.callers)
		})
	}

	t.Run("a caller not in the scope table", func(t *testing.T) {
		conn, p := newTestDeps(t)
		_, err := SetUpRouter(Config{
			Conn: conn, Auth: testAuthConfig(), SharedSecret: testSharedSecret, Poller: p,
			M2M: M2MConfig{Callers: []M2MCallerConfig{{Name: "st-gateway", Secret: "s", MachineKey: "k"}}},
		})
		if err == nil {
			t.Fatal("a caller with no scope row was accepted")
		}
	})
}

func assertStartupError(t *testing.T, where string, err error, callers []M2MCallerConfig) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s accepted an unsafe m2m configuration", where)
	}
	for _, c := range callers {
		for _, secret := range []string{c.Secret, c.MachineKey} {
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the startup error carries a secret value: %v", where, err)
			}
		}
	}
}

// TestReadM2MConfigAcceptsSafeConfigs: the legal shapes start — nothing set
// at all (production before meta#59), a machine key with no caller secret (a
// disabled caller), the dev key alone, and Clerk keys alone — and the
// environment reaches the right caller.
func TestReadM2MConfigAcceptsSafeConfigs(t *testing.T) {
	clear := func(t *testing.T) {
		for _, k := range []string{
			"M2M_CALLER_SECRET_AUTOMATION_SERVICE", "M2M_CALLER_SECRET_AI_SERVICE",
			"M2M_MACHINE_KEY_AUTOMATION_SERVICE", "M2M_MACHINE_KEY_AI_SERVICE",
			"DEV_M2M_SIGNING_KEY_FILE", "CLERK_ISSUER",
		} {
			t.Setenv(k, "")
		}
	}

	t.Run("nothing set", func(t *testing.T) {
		clear(t)
		cfg, err := ReadM2MConfig(testSharedSecret, testIntrospectionSecret)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cfg.Callers {
			if c.Secret != "" {
				t.Errorf("%s enabled with nothing set", c.Name)
			}
		}
	})

	t.Run("machine key without a caller secret", func(t *testing.T) {
		clear(t)
		t.Setenv("M2M_MACHINE_KEY_AI_SERVICE", "ak_b")
		if _, err := ReadM2MConfig(testSharedSecret, testIntrospectionSecret); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Clerk keys", func(t *testing.T) {
		clear(t)
		t.Setenv("M2M_CALLER_SECRET_AUTOMATION_SERVICE", "caller-a")
		t.Setenv("M2M_MACHINE_KEY_AUTOMATION_SERVICE", "ak_a")
		t.Setenv("M2M_CALLER_SECRET_AI_SERVICE", "caller-b")
		t.Setenv("M2M_MACHINE_KEY_AI_SERVICE", "ak_b")
		cfg, err := ReadM2MConfig(testSharedSecret, testIntrospectionSecret)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string][2]string{"automation-service": {"caller-a", "ak_a"}, "ai-service": {"caller-b", "ak_b"}}
		for _, c := range cfg.Callers {
			if w := want[c.Name]; c.Secret != w[0] || c.MachineKey != w[1] {
				t.Errorf("%s read %q/%q, want %q/%q", c.Name, c.Secret, c.MachineKey, w[0], w[1])
			}
		}
	})

	t.Run("dev key", func(t *testing.T) {
		clear(t)
		path := filepath.Join(t.TempDir(), "dev.key.pem")
		if err := os.WriteFile(path, []byte(testDevKeyPEM(t, testPrivateKey)), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("DEV_M2M_SIGNING_KEY_FILE", path)
		t.Setenv("M2M_CALLER_SECRET_AUTOMATION_SERVICE", "caller-a")
		t.Setenv("CLERK_ISSUER", "https://clerk.example.test")
		cfg, err := ReadM2MConfig(testSharedSecret, testIntrospectionSecret)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DevSigningKeyPEM == "" || cfg.Issuer != "https://clerk.example.test" {
			t.Errorf("dev key or issuer not read: %+v", cfg.Issuer)
		}
	})

	t.Run("dev key file missing", func(t *testing.T) {
		clear(t)
		t.Setenv("DEV_M2M_SIGNING_KEY_FILE", filepath.Join(t.TempDir(), "absent.pem"))
		if _, err := ReadM2MConfig(testSharedSecret, testIntrospectionSecret); err == nil {
			t.Fatal("a missing DEV_M2M_SIGNING_KEY_FILE was accepted")
		}
	})
}

func (f *fakeClerk) snapshot() []clerkRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]clerkRequest(nil), f.requests...)
}
