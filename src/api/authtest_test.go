package api

// Test credentials: an ephemeral keypair, generated once per test binary run.
//
// Tests exercise the real verification path in auth.go — there is no stub
// verifier and no bypass flag. Only the trust anchor differs from
// production, matching agent-service's own authtest_test.go.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	testPrivateKey, testPublicKey = mustGenerateKeyPair()
	foreignPrivateKey, _          = mustGenerateKeyPair()
	testClerkPublicKeyPEM         = mustEncodePublicKeyPEM(testPublicKey)
)

const testSharedSecret = "test-shared-secret"

func mustGenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key, &key.PublicKey
}

func mustEncodePublicKeyPEM(key *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

type testTokenOptions struct {
	scopes           []string
	sub              string
	expiresInSeconds int
	issuer           string

	// scopeRaw, when set, is written to the `scope` claim verbatim instead of
	// joining `scopes`. The fixture carries a scope string with a double
	// space, a tab and a trailing space, and the center must return it
	// untouched — which a join can't express.
	scopeRaw string
	// scopeArray writes `scope` as a JSON array, the other shape Clerk can
	// produce. The contract says the center answers with a space-delimited
	// string either way.
	scopeArray []string
	// omitScope leaves the `scope` claim out of the token entirely. Without it
	// every test token carries at least `"scope":""`, so a token with NO scope
	// claim, which a Clerk session holding no scopes can be, is never exercised.
	omitScope bool
	// expiresAtUnix, when non-zero, pins `exp` absolutely (the fixture's
	// 4102444800) rather than relative to now.
	expiresAtUnix int64
	// notBeforeSeconds offsets `nbf` from now; positive is a token not yet
	// valid. Zero omits the claim.
	notBeforeSeconds int
	// extraClaims land in the token and must never come back out of
	// introspection — the response carries five fields and no more.
	extraClaims map[string]interface{}
}

func testTokenClaims(opts testTokenOptions) jwt.MapClaims {
	if opts.sub == "" {
		opts.sub = "user_2TestOperator"
	}
	if opts.expiresInSeconds == 0 {
		opts.expiresInSeconds = 300
	}
	scope := ""
	for i, s := range opts.scopes {
		if i > 0 {
			scope += " "
		}
		scope += s
	}

	claims := jwt.MapClaims{
		"sub":   opts.sub,
		"scope": scope,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Duration(opts.expiresInSeconds) * time.Second).Unix(),
	}
	if opts.scopeRaw != "" {
		claims["scope"] = opts.scopeRaw
	}
	if opts.scopeArray != nil {
		arr := make([]interface{}, 0, len(opts.scopeArray))
		for _, s := range opts.scopeArray {
			arr = append(arr, s)
		}
		claims["scope"] = arr
	}
	if opts.omitScope {
		delete(claims, "scope")
	}
	if opts.expiresAtUnix != 0 {
		claims["exp"] = opts.expiresAtUnix
	}
	if opts.notBeforeSeconds != 0 {
		claims["nbf"] = time.Now().Add(time.Duration(opts.notBeforeSeconds) * time.Second).Unix()
	}
	if opts.issuer != "" {
		claims["iss"] = opts.issuer
	}
	for k, val := range opts.extraClaims {
		claims[k] = val
	}
	return claims
}

func signTestToken(key *rsa.PrivateKey, opts testTokenOptions) string {
	return signTestTokenWith(jwt.SigningMethodRS256, key, opts)
}

// signTestTokenWith signs with an arbitrary RSA-family method. RS384, RS512 and
// PS256 all take the very same *rsa.PrivateKey and verify against the very same
// *rsa.PublicKey, so neither the key type nor the key function rejects them —
// jwt.WithValidMethods("RS256") is the ONLY thing that does. That is what makes
// these the tokens the alg pin has to be tested with; HS256 and alg=none are
// already stopped by the key type before the pin is reached.
func signTestTokenWith(method jwt.SigningMethod, key *rsa.PrivateKey, opts testTokenOptions) string {
	token := jwt.NewWithClaims(method, testTokenClaims(opts))
	signed, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}
	return signed
}

// signHS256WithPublicKey is the classic algorithm-confusion attack: the
// attacker knows the RSA PUBLIC key (it is public) and signs an HMAC token
// with its PEM bytes as the shared secret. A verifier that trusts the header's
// `alg` and hands the key function's result to HMAC accepts it. Ours pins
// RS256, so the token must never verify.
func signHS256WithPublicKey(opts testTokenOptions) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, testTokenClaims(opts))
	signed, err := token.SignedString([]byte(testClerkPublicKeyPEM))
	if err != nil {
		panic(err)
	}
	return signed
}

// signAlgNone builds an unsigned `{"alg":"none"}` token by hand. golang-jwt
// refuses to produce one through the normal API, which is the point.
func signAlgNone(opts testTokenOptions) string {
	enc := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := enc(map[string]string{"alg": "none", "typ": "JWT"})
	return header + "." + enc(testTokenClaims(opts)) + "."
}

// bearer returns a ready-to-use Authorization header value for an operator
// with agent:reset.
func bearer() string {
	return "Bearer " + signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})
}

// bearerWithoutScope returns a signed-in operator who holds no scope at all.
func bearerWithoutScope() string {
	return "Bearer " + signTestToken(testPrivateKey, testTokenOptions{scopes: []string{}})
}

// expiredBearer returns a well-formed token whose exp has already passed.
//
// -600, not -60: the verifier allows a 60 s leeway, so a token exactly 60 s
// past exp sits ON the boundary and whether it is dead depends on which side of
// a second the test happens to land. Ten minutes is unambiguously expired, and
// the leeway boundary itself is pinned deliberately (from both sides) in
// TestIntrospectionAcceptsAValidTokenWithinTheLeeway.
func expiredBearer() string {
	return "Bearer " + signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}, expiresInSeconds: -600})
}

// foreignBearer is correctly shaped, correct scope, valid exp — signed by a
// key the service has never seen. The one token that proves the signature is
// actually checked rather than the payload merely being decoded.
func foreignBearer() string {
	return "Bearer " + signTestToken(foreignPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})
}

func testAuthConfig() AuthConfig {
	return AuthConfig{ClerkJWTKeyPEM: testClerkPublicKeyPEM}
}
