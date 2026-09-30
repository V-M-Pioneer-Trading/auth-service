package api

// POST /auth/v1/m2m-token — auth-design.md decision 22 / meta#59.
//
// auth-service is the only process that holds a Clerk Machine Secret Key. A
// headless service that needs a bearer token of its own presents its own
// caller secret here and gets back a Clerk M2M JWT whose `sub` names its
// Machine and whose `scope` is fixed by the table below. The contract is the
// "Minting a machine token" section of token-introspection.md.
//
// The secret IS the caller's identity. There is no body field in which a
// caller names itself or asks for a scope, so there is nothing to forge: a
// caller can only ever get the token this file says it gets.
//
// Tokens are cached per caller in memory and served again until half their
// lifetime has passed, so Clerk billing is bounded by this process alone
// whatever a caller does. Nothing is persisted.

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// M2MCallerSecretHeader is the header a calling service authenticates with.
const M2MCallerSecretHeader = "X-Service-Secret"

// m2mCallerScopes is the fixed table decision 22 asks for. A caller requests
// nothing; changing what a machine may do is a pull request against this
// table, which is where that review belongs. Order is the order callers are
// read from the environment and reported at startup.
var m2mCallerScopes = []struct {
	Name   string
	Scopes string
	// EnvSuffix names the caller in its two environment variables:
	// M2M_CALLER_SECRET_<suffix> and M2M_MACHINE_KEY_<suffix>.
	EnvSuffix string
}{
	{Name: "automation-service", Scopes: "fleet:control", EnvSuffix: "AUTOMATION_SERVICE"},
	{Name: "ai-service", Scopes: "events:write planner:advise", EnvSuffix: "AI_SERVICE"},
}

// m2mTokenLifetimeSeconds is decision 22's 24 hours, not Clerk's default hour.
// At a refresh at half the lifetime that is two mints per caller per day.
const m2mTokenLifetimeSeconds = 86400

// devM2MKeyID is the `kid` the dev key has always been published under
// (decision 10); automation-service's local signer used the same value.
const devM2MKeyID = "dev-only-do-not-use"

// clerkM2MTokensURL is Clerk's Backend API mint endpoint.
const clerkM2MTokensURL = "https://api.clerk.com/v1/m2m_tokens"

// clerkMintTimeout bounds one call to Clerk. Minting happens twice a day per
// caller, so this is not the hot path; it only has to be finite, so that a
// hung Clerk turns into a 503 (or a stale token) instead of a hung caller.
const clerkMintTimeout = 10 * time.Second

const (
	m2mUnknownCaller = "unknown caller"
	m2mMintFailed    = "the token could not be minted"
)

// M2MCallerConfig is one row of the environment: the secret a caller
// presents, and the Clerk Machine Secret Key its tokens are minted with.
type M2MCallerConfig struct {
	// Name must be a caller in m2mCallerScopes.
	Name string
	// Secret is M2M_CALLER_SECRET_<caller>. Empty disables the caller: its
	// requests get the same 401 as a stranger's.
	Secret string
	// MachineKey is M2M_MACHINE_KEY_<caller>, the production mint source.
	MachineKey string
}

// M2MConfig is everything the mint route needs.
type M2MConfig struct {
	Callers []M2MCallerConfig
	// DevSigningKeyPEM, when set, is the RSA private key every token is signed
	// with locally instead of calling Clerk (DEV_M2M_SIGNING_KEY_FILE).
	DevSigningKeyPEM string
	// Issuer is CLERK_ISSUER. A dev token carries it as `iss` so this same
	// process's introspection, which checks `iss` when configured, accepts it.
	Issuer string

	// Test seams; zero values mean production behaviour.
	clerkURL   string
	httpClient *http.Client
	now        func() time.Time
}

// ReadM2MConfig reads the per-caller environment and DEV_M2M_SIGNING_KEY_FILE,
// then applies the same fail-closed checks SetUpRouter repeats.
func ReadM2MConfig(sharedSecret, introspectionSecret string) (M2MConfig, error) {
	cfg := M2MConfig{Issuer: os.Getenv("CLERK_ISSUER")}
	for _, c := range m2mCallerScopes {
		cfg.Callers = append(cfg.Callers, M2MCallerConfig{
			Name:       c.Name,
			Secret:     os.Getenv("M2M_CALLER_SECRET_" + c.EnvSuffix),
			MachineKey: os.Getenv("M2M_MACHINE_KEY_" + c.EnvSuffix),
		})
	}
	if path := os.Getenv("DEV_M2M_SIGNING_KEY_FILE"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return M2MConfig{}, fmt.Errorf("DEV_M2M_SIGNING_KEY_FILE: %w", err)
		}
		if len(strings.TrimSpace(string(pem))) == 0 {
			return M2MConfig{}, errors.New("DEV_M2M_SIGNING_KEY_FILE (" + path + ") is empty")
		}
		cfg.DevSigningKeyPEM = string(pem)
	}
	if err := validateM2MConfig(cfg, sharedSecret, introspectionSecret); err != nil {
		return M2MConfig{}, err
	}
	return cfg, nil
}

// validateM2MConfig is the fail-closed half of decision 22. Every error names
// environment variables, never values.
//
//   - One trust anchor per process: a machine key next to the dev key would
//     mean some tokens are Clerk's and some are ours, and which one a caller
//     got would depend on a table nobody reads.
//   - An enabled caller with nothing to mint with would answer 503 forever;
//     that is a deploy mistake, and it is cheaper to find at startup.
//   - A caller secret may not equal the vault secret (st-gateway's alone),
//     the introspection secret (held by every service, so every verifier could
//     then mint) or another caller's secret (either could then mint as the
//     other). Same rule, same reason, as ReadIntrospectionSecret.
func validateM2MConfig(cfg M2MConfig, sharedSecret, introspectionSecret string) error {
	known := map[string]bool{}
	for _, c := range m2mCallerScopes {
		known[c.Name] = true
	}
	seen := map[string]string{}
	for _, c := range cfg.Callers {
		if !known[c.Name] {
			return fmt.Errorf("m2m caller %q is not in the scope table", c.Name)
		}
		if c.MachineKey != "" && cfg.DevSigningKeyPEM != "" {
			return errors.New("DEV_M2M_SIGNING_KEY_FILE and a M2M_MACHINE_KEY_* variable are both set: " +
				"one process mints with exactly one trust anchor")
		}
		if c.Secret == "" {
			continue
		}
		if c.MachineKey == "" && cfg.DevSigningKeyPEM == "" {
			return fmt.Errorf("m2m caller %s has a caller secret but no machine key and no DEV_M2M_SIGNING_KEY_FILE to mint with", c.Name)
		}
		if c.Secret == sharedSecret {
			return fmt.Errorf("the m2m caller secret for %s must not be the same value as AUTH_SERVICE_SHARED_SECRET", c.Name)
		}
		if introspectionSecret != "" && c.Secret == introspectionSecret {
			return fmt.Errorf("the m2m caller secret for %s must not be the same value as AUTH_INTROSPECTION_SECRET: "+
				"every service holds that one, so every service could mint", c.Name)
		}
		if other, dup := seen[c.Secret]; dup {
			return fmt.Errorf("the m2m caller secrets for %s and %s must differ: either could mint as the other", other, c.Name)
		}
		seen[c.Secret] = c.Name
	}
	return nil
}

// m2mCaller is one enabled row, with its own cache.
type m2mCaller struct {
	name   string
	secret []byte
	cache  *m2mTokenCache
}

type m2mHandler struct {
	callers []*m2mCaller
}

// newM2MHandler builds the route. It validates again so no future caller of
// SetUpRouter can assemble a collision by hand, as SetUpRouter does for the
// two older secrets.
func newM2MHandler(cfg M2MConfig, sharedSecret, introspectionSecret string, verifierKey *rsa.PublicKey) (*m2mHandler, error) {
	if err := validateM2MConfig(cfg, sharedSecret, introspectionSecret); err != nil {
		return nil, err
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}

	var devKey *rsa.PrivateKey
	if cfg.DevSigningKeyPEM != "" {
		key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.DevSigningKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("DEV_M2M_SIGNING_KEY_FILE is not an RSA private key: %w", err)
		}
		devKey = key
		// Not fatal: pointing CLERK_JWT_KEY at a real Clerk dev instance to
		// drive the UI is a supported local setup, and it leaves the dev key
		// behind. But every token minted here will then answer inactive, and
		// that is worth one line at startup rather than an afternoon.
		if verifierKey != nil && !devKey.PublicKey.Equal(verifierKey) {
			log.Default().Print("DEV_M2M_SIGNING_KEY_FILE does not match the verification key: " +
				"machine tokens minted here will not introspect as active")
		}
	}

	clerkURL := cfg.clerkURL
	if clerkURL == "" {
		clerkURL = clerkM2MTokensURL
	}
	client := cfg.httpClient
	if client == nil {
		client = &http.Client{Timeout: clerkMintTimeout}
	}

	h := &m2mHandler{}
	for _, c := range cfg.Callers {
		if c.Secret == "" {
			continue
		}
		scopes := scopesFor(c.Name)
		var mint func(context.Context) (string, error)
		if devKey != nil {
			mint = devMinter(devKey, c.Name, scopes, cfg.Issuer, now)
		} else {
			mint = clerkMinter(client, clerkURL, c.MachineKey, scopes)
		}
		h.callers = append(h.callers, &m2mCaller{
			name:   c.Name,
			secret: []byte(c.Secret),
			cache:  &m2mTokenCache{mint: mint, now: now},
		})
	}
	return h, nil
}

func scopesFor(name string) string {
	for _, c := range m2mCallerScopes {
		if c.Name == name {
			return c.Scopes
		}
	}
	return ""
}

// lookup compares the presented secret against EVERY enabled caller in
// constant time and never breaks early, so the response time says nothing
// about which caller, if any, came close.
func (h *m2mHandler) lookup(presented string) *m2mCaller {
	if presented == "" {
		return nil
	}
	var match *m2mCaller
	for _, c := range h.callers {
		if subtle.ConstantTimeCompare(c.secret, []byte(presented)) == 1 {
			match = c
		}
	}
	return match
}

type m2mTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func (h *m2mHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	caller := h.lookup(r.Header.Get(M2MCallerSecretHeader))
	if caller == nil {
		// Names no caller and no secret, here or in the log: the request
		// logger has already recorded method and path, which is all there is.
		writeM2M(w, http.StatusUnauthorized, map[string]string{"error": m2mUnknownCaller})
		return
	}
	tok, err := caller.cache.get(r.Context())
	if err != nil {
		log.Default().Printf("minting a machine token for %s failed: %v", caller.name, err)
		writeM2M(w, http.StatusServiceUnavailable, map[string]string{"error": m2mMintFailed})
		return
	}
	writeM2M(w, http.StatusOK, m2mTokenResponse{Token: tok.token, ExpiresAt: tok.expiresAt.Unix()})
}

func writeM2M(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// A bearer token in a shared cache would be handed to whoever asked next.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// cachedM2MToken is a minted token and the two instants the cache acts on.
type cachedM2MToken struct {
	token     string
	expiresAt time.Time
	refreshAt time.Time
}

// m2mTokenCache holds one caller's token. Until refreshAt it answers from
// memory; after it, the next request mints, and concurrent requests wait on
// that one mint rather than starting their own (each one is billed).
type m2mTokenCache struct {
	mint func(context.Context) (string, error)
	now  func() time.Time

	mu       sync.Mutex
	cached   *cachedM2MToken
	inflight *m2mMint
}

type m2mMint struct {
	done   chan struct{}
	result cachedM2MToken
	err    error
}

func (c *m2mTokenCache) get(ctx context.Context) (cachedM2MToken, error) {
	c.mu.Lock()
	if c.cached != nil && c.now().Before(c.cached.refreshAt) {
		tok := *c.cached
		c.mu.Unlock()
		return tok, nil
	}
	call := c.inflight
	if call == nil {
		call = &m2mMint{done: make(chan struct{})}
		c.inflight = call
		go c.run(call)
	}
	c.mu.Unlock()

	select {
	case <-call.done:
	case <-ctx.Done():
		// The caller gave up. The mint carries on in the background and its
		// result is cached for the next request, which is the one that pays.
		return cachedM2MToken{}, ctx.Err()
	}
	if call.err == nil {
		return call.result, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// A token past its refresh point is still a valid token. Serve it over a
	// failed mint, right up to its actual expiry, so a Clerk outage costs
	// nothing until then.
	if c.cached != nil && c.now().Before(c.cached.expiresAt) {
		return *c.cached, nil
	}
	return cachedM2MToken{}, call.err
}

// run mints on a context of its own, not the request's: every waiter shares
// this mint, so the first requester hanging up must not fail the others.
// The Clerk client's timeout is what bounds it.
func (c *m2mTokenCache) run(call *m2mMint) {
	token, err := c.mint(context.Background())
	var tok cachedM2MToken
	if err == nil {
		tok, err = cacheEntryFrom(token)
	}

	c.mu.Lock()
	if err == nil {
		c.cached = &tok
	}
	call.result, call.err = tok, err
	c.inflight = nil
	c.mu.Unlock()
	close(call.done)
}

// cacheEntryFrom reads `iat` and `exp` from the token's payload. No signature
// check: the token came from Clerk over TLS (or from our own key), and this
// is bookkeeping, not trust. A token without a usable lifetime is refused as
// a failed mint — caching it would either never refresh or refresh on every
// request, and the second one is billed.
func cacheEntryFrom(token string) (cachedM2MToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return cachedM2MToken{}, errors.New("minted token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return cachedM2MToken{}, fmt.Errorf("minted token payload: %w", err)
	}
	var claims struct {
		Iat *float64 `json:"iat"`
		Exp *float64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return cachedM2MToken{}, fmt.Errorf("minted token payload: %w", err)
	}
	if claims.Iat == nil || claims.Exp == nil || *claims.Exp <= *claims.Iat {
		return cachedM2MToken{}, errors.New("minted token has no usable iat/exp")
	}
	iat, exp := int64(*claims.Iat), int64(*claims.Exp)
	return cachedM2MToken{
		token:     token,
		expiresAt: time.Unix(exp, 0),
		refreshAt: time.Unix(iat+(exp-iat)/2, 0),
	}, nil
}

// clerkMinter mints through Clerk's Backend API with the caller's own
// Machine Secret Key, so the token's `sub` is that caller's Machine. `scope`
// lands as a flat top-level claim, which is what introspection returns.
func clerkMinter(client *http.Client, url, machineKey, scopes string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		body, err := json.Marshal(map[string]interface{}{
			"token_format":             "jwt",
			"claims":                   map[string]string{"scope": scopes},
			"seconds_until_expiration": m2mTokenLifetimeSeconds,
		})
		if err != nil {
			return "", err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+machineKey)
		req.Header.Set("Content-Type", "application/json")

		res, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("POST /m2m_tokens: %w", err)
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode > 299 {
			// Clerk's error body names the problem and never echoes the key;
			// capped so a misbehaving upstream cannot flood the log.
			detail, _ := io.ReadAll(io.LimitReader(res.Body, 512))
			return "", fmt.Errorf("POST /m2m_tokens: %d %s", res.StatusCode, strings.TrimSpace(string(detail)))
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out); err != nil {
			return "", fmt.Errorf("POST /m2m_tokens: %w", err)
		}
		if out.Token == "" {
			return "", errors.New("POST /m2m_tokens: response carried no token")
		}
		return out.Token, nil
	}
}

// devMinter signs locally with the committed dev key (decision 10), so a
// fresh clone gets real machine tokens with no Clerk account. The token is
// shaped like Clerk's: `sub` names a Machine (mch_local_<caller>, so
// introspection says `kind: "machine"`), `scope` is flat, same lifetime.
func devMinter(key *rsa.PrivateKey, caller, scopes, issuer string, now func() time.Time) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		issuedAt := now().Unix()
		claims := jwt.MapClaims{
			"sub":   "mch_local_" + caller,
			"scope": scopes,
			"iat":   issuedAt,
			"exp":   issuedAt + m2mTokenLifetimeSeconds,
		}
		if issuer != "" {
			claims["iss"] = issuer
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = devM2MKeyID
		return token.SignedString(key)
	}
}
