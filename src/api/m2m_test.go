package api

// Tests for POST /auth/v1/m2m-token (decision 22). Clerk is an httptest
// server that signs real RS256 tokens with the test key and records every
// request; the clock is injected, so the half-lifetime refresh and the
// stale-but-valid fallback are exercised at exact instants rather than slept
// through.

import (
	"bytes"
	"context"
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

// TestM2MTokenWithoutALifetimeIsAFailedMint: a token with no iat/exp cannot
// be scheduled, so it is refused and not cached.
func TestM2MTokenWithoutALifetimeIsAFailedMint(t *testing.T) {
	for name, payload := range map[string]jwt.MapClaims{
		"no exp":         {"sub": "mch_x", "iat": 1_900_000_000},
		"no iat":         {"sub": "mch_x", "exp": 1_900_086_400},
		"exp before iat": {"sub": "mch_x", "iat": 1_900_000_000, "exp": 1_899_000_000},
		// The fake clock stands at 1_900_000_000.
		"already expired":            {"sub": "mch_x", "iat": 1_899_992_800, "exp": 1_899_996_400},
		"lifetime under 60 s":        {"sub": "mch_x", "iat": 1_900_000_000, "exp": 1_900_000_059},
		"exp far out of range":       {"sub": "mch_x", "iat": 1_900_000_000, "exp": 1e300},
		"exp past 2^53":              {"sub": "mch_x", "iat": 1_900_000_000, "exp": float64(1 << 60)},
		"iat negative":               {"sub": "mch_x", "iat": -100, "exp": 1_900_086_400},
		"lifetime over 7 days":       {"sub": "mch_x", "iat": 1_900_000_000, "exp": 1_900_604_801},
		"refresh point already past": {"sub": "mch_x", "iat": 1_899_992_800, "exp": 1_900_003_600},
	} {
		t.Run(name, func(t *testing.T) {
			clock := newFakeClock()
			clerk := newFakeClerk(t, clock)
			clerk.payload = payload
			router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

			assertM2MError(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)
			// Past the failure backoff, so a second attempt is allowed.
			clock.Advance(m2mRetryBackoff)
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
	if strings.Contains(buf.String(), "clerk is down") {
		t.Errorf("Clerk's error body reached the log: %q", buf.String())
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
		{name: "two callers share a Machine key", callers: []M2MCallerConfig{
			{Name: "automation-service", Secret: "caller-a", MachineKey: "ak_same"},
			{Name: "ai-service", Secret: "caller-b", MachineKey: "ak_same"},
		}},
		{name: "two callers share a Machine key, one disabled", callers: []M2MCallerConfig{
			{Name: "automation-service", Secret: "caller-a", MachineKey: "ak_same"},
			{Name: "ai-service", MachineKey: "ak_same"},
		}},
		{name: "caller secret with leading whitespace",
			callers: []M2MCallerConfig{{Name: "automation-service", Secret: " caller-a", MachineKey: "ak_a"}}},
		{name: "caller secret with a trailing newline",
			callers: []M2MCallerConfig{{Name: "automation-service", Secret: "caller-a\n", MachineKey: "ak_a"}}},
		{name: "whitespace-only caller secret",
			callers: []M2MCallerConfig{{Name: "ai-service", Secret: " \t ", MachineKey: "ak_b"}}},
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

// TestM2MOptionsIsTheCORSPreflight documents the one non-POST method that is
// not a 405: the service-wide OPTIONS catch-all answers 204 before any
// handler runs. It carries no token, reaches no Clerk, and corsMiddleware
// does not allow the caller-secret header, so a browser can still never send
// one.
func TestM2MOptionsIsTheCORSPreflight(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	rec := requestM2M(t, router, http.MethodOptions, testAutomationCallerSecret, true)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("OPTIONS: got %d %q, want an empty 204", rec.Code, rec.Body.String())
	}
	if strings.Contains(strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers")), strings.ToLower(M2MCallerSecretHeader)) {
		t.Errorf("CORS allows %s; no browser may ever send a caller secret", M2MCallerSecretHeader)
	}
	if clerk.calls() != 0 {
		t.Errorf("a preflight reached Clerk")
	}
}

// TestM2MFailedMintsBackOff: after a failed mint, requests inside the next
// 10 s do not call Clerk. With nothing valid in hand they get 503; with a
// stale-but-unexpired token they get that token.
func TestM2MFailedMintsBackOff(t *testing.T) {
	t.Run("nothing cached", func(t *testing.T) {
		clock := newFakeClock()
		clerk := newFakeClerk(t, clock)
		clerk.setFail(true)
		router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

		assertM2MError(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)
		clock.Advance(m2mRetryBackoff - time.Second)
		for i := 0; i < 5; i++ {
			assertM2MError(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)
		}
		if clerk.calls() != 1 {
			t.Fatalf("Clerk was called %d times inside the backoff window, want 1", clerk.calls())
		}
		// The backoff is per caller: ai-service has not failed yet.
		assertM2MError(t, requestM2M(t, router, "POST", testAICallerSecret, true), 503, m2mMintFailed)
		if clerk.calls() != 2 {
			t.Fatalf("one caller's backoff held back another (calls: %d, want 2)", clerk.calls())
		}

		clock.Advance(time.Second)
		clerk.setFail(false)
		decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
		if clerk.calls() != 3 {
			t.Fatalf("after the backoff the next request should mint (calls: %d, want 3)", clerk.calls())
		}
	})

	t.Run("stale token in hand", func(t *testing.T) {
		clock := newFakeClock()
		clerk := newFakeClerk(t, clock)
		router := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))

		first, _ := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
		clerk.setFail(true)
		clock.Advance(13 * time.Hour)
		decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true)) // serves stale, refresh fails behind it
		settle(t, router)
		for i := 0; i < 5; i++ {
			tok, _ := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true))
			if tok != first {
				t.Fatal("inside the backoff the stale token was not served")
			}
		}
		if clerk.calls() != 2 {
			t.Fatalf("Clerk was called %d times, want 2 (one mint, one failed refresh)", clerk.calls())
		}
	})
}

func newM2MTestHandler(t *testing.T, cfg M2MConfig) *m2mHandler {
	t.Helper()
	h, err := newM2MHandler(cfg, testSharedSecret, testIntrospectionSecret, testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// requestM2MUntilCancelled sends a request whose context is cancelled as soon
// as the fake Clerk has received the mint: a caller whose 1 s timeout fired.
func requestM2MUntilCancelled(h http.Handler, clerk *fakeClerk) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodPost, "/auth/v1/m2m-token", nil).WithContext(ctx)
		req.Header.Set(M2MCallerSecretHeader, testAutomationCallerSecret)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()
	<-clerk.arrived
	cancel()
	<-done
}

// TestM2MMintIsDetachedFromTheRequest: the first mint after a restart is the
// slow one, and a caller's 1 s timeout fires during it. That must not cancel
// the mint: the caller's retry joins it, and if nobody is waiting when it
// lands, the token is cached anyway.
func TestM2MMintIsDetachedFromTheRequest(t *testing.T) {
	t.Run("a retry joins the mint its caller gave up on", func(t *testing.T) {
		clock := newFakeClock()
		clerk := newFakeClerk(t, clock)
		clerk.gate = make(chan struct{})
		clerk.arrived = make(chan struct{}, 10)
		h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))

		requestM2MUntilCancelled(h, clerk)

		retry := make(chan *httptest.ResponseRecorder)
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/auth/v1/m2m-token", nil)
			req.Header.Set(M2MCallerSecretHeader, testAutomationCallerSecret)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			retry <- rec
		}()
		time.Sleep(50 * time.Millisecond) // let the retry reach the in-flight mint
		close(clerk.gate)
		decodeMinted(t, <-retry)
		if clerk.calls() != 1 {
			t.Fatalf("the retry started a second mint (calls: %d, want 1)", clerk.calls())
		}
	})

	t.Run("a token that lands after its caller left is cached", func(t *testing.T) {
		clock := newFakeClock()
		clerk := newFakeClerk(t, clock)
		clerk.gate = make(chan struct{})
		clerk.arrived = make(chan struct{}, 10)
		h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))

		requestM2MUntilCancelled(h, clerk)
		close(clerk.gate)

		cache := h.callers[0].cache
		deadline := time.Now().Add(2 * time.Second)
		for {
			cache.mu.Lock()
			idle, cached := cache.inflight == nil, cache.cached != nil
			cache.mu.Unlock()
			if idle {
				if !cached {
					t.Fatal("the mint finished after its caller left and its token was thrown away")
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the mint never finished")
			}
			time.Sleep(5 * time.Millisecond)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/v1/m2m-token", nil)
		req.Header.Set(M2MCallerSecretHeader, testAutomationCallerSecret)
		h.ServeHTTP(rec, req)
		decodeMinted(t, rec)
		if clerk.calls() != 1 {
			t.Fatalf("the next request minted again (calls: %d, want 1)", clerk.calls())
		}
	})
}

// TestM2MMintHasItsOwnTimeout: a Clerk that never answers turns into a 503
// once the mint's own timeout passes, not a request that hangs forever
// (a detached mint has no request context to end it).
func TestM2MMintHasItsOwnTimeout(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	clerk.gate = make(chan struct{})
	clerk.arrived = make(chan struct{}, 10)
	t.Cleanup(func() { close(clerk.gate) })
	cfg := clerkM2MConfig(clerk, clock)
	cfg.mintTimeout = 50 * time.Millisecond
	router := newM2MTestRouter(t, testAuthConfig(), cfg)

	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- requestM2M(t, router, "POST", testAutomationCallerSecret, true) }()
	select {
	case rec := <-result:
		assertM2MError(t, rec, 503, m2mMintFailed)
	case <-time.After(3 * time.Second):
		t.Fatal("a mint against a Clerk that never answers did not time out")
	}
}

// settle waits until no caller has a mint in flight: the background refresh
// a request started without waiting for it has landed (or failed).
func settle(t *testing.T, h *m2mHandler) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for _, c := range h.callers {
		for {
			c.cache.mu.Lock()
			idle := c.cache.inflight == nil
			c.cache.mu.Unlock()
			if idle {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("a mint never finished")
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
}

// TestM2MCacheServesUntilHalfLifetimeThenRefreshes: one mint for every
// request in the first 12 h; at the refresh point the request still gets
// the old token, a refresh runs behind it, and the next request gets the
// new one. expires_at is the token's exp, not a recomputation from the clock.
func TestM2MCacheServesUntilHalfLifetimeThenRefreshes(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))
	mintedAt := clock.Now().Unix()

	first, expiresAt := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	if expiresAt != mintedAt+86400 {
		t.Errorf("expires_at = %d, want iat+86400 = %d", expiresAt, mintedAt+86400)
	}

	clock.Advance(12*time.Hour - time.Second)
	again, againExpires := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	settle(t, h)
	if again != first || againExpires != expiresAt {
		t.Fatal("a request before half the lifetime got a different token: the cache was not used")
	}
	if clerk.calls() != 1 {
		t.Fatalf("Clerk was called %d times before half the lifetime, want 1", clerk.calls())
	}

	clock.Advance(time.Second)
	atRefresh, _ := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	if atRefresh != first {
		t.Fatal("at the refresh point the request did not get the still-valid token at once")
	}
	settle(t, h)
	if clerk.calls() != 2 {
		t.Fatalf("the refresh point did not start a mint (calls: %d, want 2)", clerk.calls())
	}
	refreshed, refreshedExpires := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	if refreshed == first {
		t.Fatal("after the refresh landed the old token was still served")
	}
	if refreshedExpires != clock.Now().Unix()+86400 {
		t.Errorf("refreshed expires_at = %d, want %d", refreshedExpires, clock.Now().Unix()+86400)
	}
	if clerk.calls() != 2 {
		t.Fatalf("Clerk was called %d times, want 2", clerk.calls())
	}

	// The two callers' caches are separate: ai-service's first request
	// mints, and gets its own token rather than automation-service's.
	aiToken, _ := decodeMinted(t, requestM2M(t, h, "POST", testAICallerSecret, true))
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
	h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))

	_, expiresAt := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	if expiresAt != iat+600 {
		t.Errorf("expires_at = %d, want %d", expiresAt, iat+600)
	}
	clock.Advance(299 * time.Second)
	decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	settle(t, h)
	if clerk.calls() != 1 {
		t.Fatalf("re-minted before half of a 600 s lifetime (calls: %d)", clerk.calls())
	}
	clock.Advance(time.Second)
	decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	settle(t, h)
	if clerk.calls() != 2 {
		t.Fatalf("did not re-mint at half of a 600 s lifetime (calls: %d)", clerk.calls())
	}
}

// TestM2MStaleButValidFallback: past the refresh point a failed mint leaves
// the cached token in service right up to its expiry, and a 503 only after.
func TestM2MStaleButValidFallback(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))

	first, expiresAt := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	clerk.setFail(true)

	clock.Advance(24*time.Hour - time.Second)
	stale, staleExpires := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	settle(t, h)
	if stale != first || staleExpires != expiresAt {
		t.Fatal("past the refresh point the still-valid cached token was not served")
	}
	if clerk.calls() != 2 {
		t.Fatalf("past the refresh point a request must start a refresh (calls: %d, want 2)", clerk.calls())
	}
	again, _ := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	if again != first {
		t.Fatal("after the refresh failed the still-valid cached token was not served")
	}

	clock.Advance(time.Second)
	assertM2MError(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)

	// And it recovers: Clerk back and the failure backoff over, the next
	// request mints.
	clerk.setFail(false)
	clock.Advance(m2mRetryBackoff)
	fresh, _ := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	if fresh == first {
		t.Fatal("after recovery the expired token was served")
	}
}

// TestM2MRefreshNeverMakesARequestWait: 13 h after a mint, with a Clerk that
// takes as long as it likes, a request gets the old token immediately and
// exactly one mint runs however many requests arrive meanwhile.
func TestM2MRefreshNeverMakesARequestWait(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))
	first, _ := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))

	clerk.mu.Lock()
	clerk.gate = make(chan struct{})
	clerk.arrived = make(chan struct{}, 100)
	clerk.mu.Unlock()
	clock.Advance(13 * time.Hour)

	for i := 0; i < 5; i++ {
		result := make(chan *httptest.ResponseRecorder, 1)
		go func() { result <- requestM2M(t, h, "POST", testAutomationCallerSecret, true) }()
		select {
		case rec := <-result:
			if tok, _ := decodeMinted(t, rec); tok != first {
				t.Fatalf("request %d got a different token while the refresh was held", i)
			}
		case <-time.After(2 * time.Second):
			close(clerk.gate)
			t.Fatalf("request %d waited on a mint while a valid token existed", i)
		}
	}
	close(clerk.gate)
	settle(t, h)
	if clerk.calls() != 2 {
		t.Fatalf("Clerk was called %d times, want 2 (the first mint and exactly one refresh)", clerk.calls())
	}
	refreshed, _ := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	if refreshed == first {
		t.Fatal("the background refresh was not cached")
	}
}

// TestM2MShortLivedTokenDoesNotMintPerRequest: a 1 s token is refused, and
// the refusal backs off like any failed mint, so a Clerk that hands out
// nearly-dead tokens costs one mint per 10 s, not one per request.
func TestM2MShortLivedTokenDoesNotMintPerRequest(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	iat := clock.Now().Unix()
	clerk.payload = jwt.MapClaims{"sub": "mch_x", "iat": iat, "exp": iat + 1}
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	for i := 0; i < 10; i++ {
		assertM2MError(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)
		clock.Advance(500 * time.Millisecond)
	}
	if clerk.calls() != 1 {
		t.Fatalf("a 1 s token cost %d mints in 5 s, want 1", clerk.calls())
	}
}

// TestM2MSixtySecondTokenIsTheShortestAccepted pins the boundary from the
// other side, so the minimum cannot quietly drift upward.
func TestM2MSixtySecondTokenIsTheShortestAccepted(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	iat := clock.Now().Unix()
	clerk.payload = jwt.MapClaims{"sub": "mch_x", "iat": iat, "exp": iat + 60}
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	if _, exp := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true)); exp != iat+60 {
		t.Fatalf("expires_at = %d, want %d", exp, iat+60)
	}
}

// TestM2MClerkRedirectIsNotFollowed: the mint request carries a Machine
// Secret Key, so a 3xx is a failed mint, never a second request elsewhere.
func TestM2MClerkRedirectIsNotFollowed(t *testing.T) {
	var elsewhereHits int
	var mu sync.Mutex
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		elsewhereHits++
		mu.Unlock()
	}))
	t.Cleanup(elsewhere.Close)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	clock := newFakeClock()
	cfg := clerkM2MConfig(&fakeClerk{server: redirecting}, clock)
	router := newM2MTestRouter(t, testAuthConfig(), cfg)

	assertM2MError(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)
	mu.Lock()
	defer mu.Unlock()
	if elsewhereHits != 0 {
		t.Fatalf("the redirect was followed %d time(s)", elsewhereHits)
	}
}

// TestM2MBackoffIsLoggedOncePerWindow: a scheduler ticking during a Clerk
// outage writes one failure line and one backoff line per window, not one
// per tick.
func TestM2MBackoffIsLoggedOncePerWindow(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	clerk.setFail(true)
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))
	buf.Reset()

	for window := 1; window <= 2; window++ {
		for i := 0; i < 5; i++ {
			assertM2MError(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true), 503, m2mMintFailed)
			clock.Advance(time.Second)
		}
		if got := strings.Count(buf.String(), "status 500"); got != window {
			t.Errorf("window %d: %d failure lines so far, want %d", window, got, window)
		}
		if got := strings.Count(buf.String(), "not calling Clerk again yet"); got != window {
			t.Errorf("window %d: %d backoff lines so far, want %d (log: %q)", window, got, window, buf.String())
		}
		clock.Advance(m2mRetryBackoff)
	}
}

// TestM2MCallerLeavingIsNotAFailure: a caller whose own timeout fires while
// the mint is in flight is not a failed mint, and must not read like one in
// the log; the mint's later success is cached as usual.
func TestM2MCallerLeavingIsNotAFailure(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	clerk.gate = make(chan struct{})
	clerk.arrived = make(chan struct{}, 10)
	h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))

	buf.Reset()
	requestM2MUntilCancelled(h, clerk)
	close(clerk.gate)
	settle(t, h)
	if strings.Contains(buf.String(), "failed") {
		t.Errorf("a caller leaving was logged as a failed mint: %q", buf.String())
	}
	decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))
	if clerk.calls() != 1 {
		t.Fatalf("the mint that outlived its caller was not cached (calls: %d)", clerk.calls())
	}
}

// TestM2MSevenDayTokenIsTheLongestAccepted pins the cap from the other side.
func TestM2MSevenDayTokenIsTheLongestAccepted(t *testing.T) {
	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	iat := clock.Now().Unix()
	clerk.payload = jwt.MapClaims{"sub": "mch_x", "iat": iat, "exp": iat + 7*24*3600}
	router := newM2MTestRouter(t, testAuthConfig(), clerkM2MConfig(clerk, clock))

	if _, exp := decodeMinted(t, requestM2M(t, router, "POST", testAutomationCallerSecret, true)); exp != iat+7*24*3600 {
		t.Fatalf("expires_at = %d, want %d", exp, iat+7*24*3600)
	}
}

// TestM2MFailedBackgroundRefreshIsLogged: a refresh past the refresh point
// runs behind a request already answered with the cached token, so no
// request sees its failure. The mint itself must say so, exactly once, with
// the caller and Clerk's status and nothing Clerk or the caller wrote.
func TestM2MFailedBackgroundRefreshIsLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))
	first, _ := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true))

	clerk.setFail(true)
	clock.Advance(13 * time.Hour)
	buf.Reset()
	if tok, _ := decodeMinted(t, requestM2M(t, h, "POST", testAutomationCallerSecret, true)); tok != first {
		t.Fatal("the request did not get the still-valid token")
	}
	settle(t, h)

	logged := buf.String()
	if n := strings.Count(logged, "minting a machine token for automation-service failed"); n != 1 {
		t.Fatalf("a failed background refresh was logged %d times, want 1 (log: %q)", n, logged)
	}
	if !strings.Contains(logged, "status 500") {
		t.Errorf("the failure line does not carry Clerk's status: %q", logged)
	}
	for _, leaked := range []string{"clerk is down", testAutomationCallerSecret, testAutomationMachineKey} {
		if strings.Contains(logged, leaked) {
			t.Errorf("the failure line leaked %q: %q", leaked, logged)
		}
	}
}

// TestM2MFailedMintIsLoggedOnceWhateverTheWaiters: when several requests
// wait on one mint that fails, the failure is one line, not one per waiter.
func TestM2MFailedMintIsLoggedOnceWhateverTheWaiters(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	clock := newFakeClock()
	clerk := newFakeClerk(t, clock)
	clerk.setFail(true)
	clerk.gate = make(chan struct{})
	clerk.arrived = make(chan struct{}, 10)
	h := newM2MTestHandler(t, clerkM2MConfig(clerk, clock))
	buf.Reset()

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			requestM2M(t, h, "POST", testAutomationCallerSecret, true)
		}()
	}
	<-clerk.arrived
	time.Sleep(50 * time.Millisecond) // let the other four join the mint
	close(clerk.gate)
	wg.Wait()

	if n := strings.Count(buf.String(), "failed"); n != 1 || clerk.calls() != 1 {
		t.Fatalf("one failed mint (calls: %d) was logged %d times, want 1 (log: %q)", clerk.calls(), n, buf.String())
	}
}

func TestClerkURLFromEnv(t *testing.T) {
	for base, want := range map[string]string{
		"":                         "",
		"http://stub:1234":         "http://stub:1234/v1/m2m_tokens",
		"http://stub:1234/":        "http://stub:1234/v1/m2m_tokens",
		"https://api.clerk.com":    clerkM2MTokensURL,
		"https://api.clerk.com///": clerkM2MTokensURL,
	} {
		if got := clerkURLFromEnv(base); got != want {
			t.Errorf("clerkURLFromEnv(%q) = %q, want %q", base, got, want)
		}
	}
}

// With CLERK_API_BASE_URL unset the config carries no override, so the handler
// falls back to the production URL: the variable changes nothing in production.
func TestReadM2MConfigClerkBaseURL(t *testing.T) {
	for _, k := range []string{"M2M_CALLER_SECRET_AUTOMATION_SERVICE", "M2M_CALLER_SECRET_AI_SERVICE",
		"M2M_MACHINE_KEY_AUTOMATION_SERVICE", "M2M_MACHINE_KEY_AI_SERVICE", "DEV_M2M_SIGNING_KEY_FILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("CLERK_API_BASE_URL", "")
	cfg, err := ReadM2MConfig("vault", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.clerkURL != "" {
		t.Errorf("unset CLERK_API_BASE_URL must leave the production default, got %q", cfg.clerkURL)
	}
	t.Setenv("CLERK_API_BASE_URL", "http://stub.test:9/")
	cfg, err = ReadM2MConfig("vault", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.clerkURL != "http://stub.test:9/v1/m2m_tokens" {
		t.Errorf("got %q", cfg.clerkURL)
	}
}
