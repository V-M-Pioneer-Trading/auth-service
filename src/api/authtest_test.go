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
}

func signTestToken(key *rsa.PrivateKey, opts testTokenOptions) string {
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
	if opts.issuer != "" {
		claims["iss"] = opts.issuer
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}
	return signed
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
func expiredBearer() string {
	return "Bearer " + signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}, expiresInSeconds: -60})
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
