package api

// Clerk session verification, performed locally — same shape as
// agent-service/src/api/auth.go and automation-service/fleet-service's
// auth.ts: networkless RS256 verification via a PEM public key
// (CLERK_JWT_KEY), no bypass flag. Only the trust anchor differs between
// local dev, CI and production.
//
// auth-service enforces exactly one scope, per its route table in
// auth-design.md's "New repository: auth-service" section: Restore Token and
// Reset Agent both require agent:reset. GET /auth/v1/status is intentionally
// public — it never returns a token (decision 6/8) — and GET /auth/v1/token
// is gated by a shared secret instead of Clerk, since its only caller
// (st-gateway) has no Clerk session of its own.

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// SCOPEAgentReset is the only scope this service enforces.
const SCOPEAgentReset = "agent:reset"

// AuthConfig holds the Clerk trust anchor.
type AuthConfig struct {
	ClerkJWTKeyPEM string
	ClerkIssuer    string // empty means "don't check"
}

// publicKey is deliberately *rsa.PublicKey and not interface{}: the alg pin in
// verifyToken and the key's concrete type are two independent locks on the same
// door, and a typed field means no future edit can quietly park an HMAC secret
// here.
type verifier struct {
	publicKey *rsa.PublicKey
	issuer    string
}

func newVerifier(cfg AuthConfig) (*verifier, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.ClerkJWTKeyPEM))
	if err != nil {
		return nil, err
	}
	return &verifier{publicKey: key, issuer: cfg.ClerkIssuer}, nil
}

func bearerFrom(r *http.Request) string {
	header := r.Header.Get("Authorization")
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	// Same rule as writeIntrospection's success path: nothing about an
	// authentication decision may sit in a shared cache, where it would outlive
	// the session it describes and answer for a caller it was never about.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]map[string]string{"error": {"message": message}})
}

// verify runs the real check requireScope relies on: a well-formed,
// correctly-signed, unexpired Clerk session carrying agent:reset.
//
// It goes through verifyToken — the SAME in-process function POST
// /auth/v1/introspect answers with (decision 21: "the vault's own two routes
// call the same verification function in-process"). There is one verification
// code path in this service and auth-service never calls itself over HTTP.
// Only the rejection vocabulary differs, because these two routes answer an
// operator while introspection answers a service.
func (v *verifier) verify(w http.ResponseWriter, r *http.Request, hasScope func([]string) bool) bool {
	token := bearerFrom(r)
	if token == "" {
		writeAuthError(w, http.StatusUnauthorized, "a bearer token is required")
		return false
	}

	verified, err := v.verifyToken(token)
	if err != nil {
		// Not surfacing the specific reason — "expired" vs "bad signature" vs
		// "wrong issuer" is a probing oracle, and the remedy is the same.
		writeAuthError(w, http.StatusUnauthorized, "invalid or expired session")
		return false
	}

	// strings.Fields is the whitespace-RUN split every verifier in the fleet
	// performs on the verbatim scope string.
	if !hasScope(strings.Fields(verified.Scope)) {
		writeAuthError(w, http.StatusForbidden, "this action requires a scope this session does not carry")
		return false
	}
	return true
}

func issuerOption(issuer string) jwt.ParserOption {
	if issuer == "" {
		return func(*jwt.Parser) {}
	}
	return jwt.WithIssuer(issuer)
}

// requireScope wraps a handler, rejecting unless the caller presents a valid
// Clerk session carrying the given scope.
func (v *verifier) requireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !v.verify(w, r, func(scopes []string) bool {
			for _, s := range scopes {
				if s == scope {
					return true
				}
			}
			return false
		}) {
			return
		}
		next(w, r)
	}
}

// RequireClerkJWTKey reads Clerk's public key: inline CLERK_JWT_KEY (how
// production passes it from SSM through the bootstrap script) wins over
// CLERK_JWT_KEY_FILE (how compose mounts the local dev key). Neither has a
// default — a service that can start without a trust anchor is one that can
// be deployed with authentication silently off.
func RequireClerkJWTKey() (string, error) {
	if inline := os.Getenv("CLERK_JWT_KEY"); inline != "" {
		return strings.ReplaceAll(inline, `\n`, "\n"), nil
	}
	if path := os.Getenv("CLERK_JWT_KEY_FILE"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if len(strings.TrimSpace(string(pem))) == 0 {
			return "", errors.New("CLERK_JWT_KEY_FILE (" + path + ") is empty")
		}
		return string(pem), nil
	}
	return "", errors.New("CLERK_JWT_KEY or CLERK_JWT_KEY_FILE must be set")
}

// requireSharedSecret gates GET /auth/v1/token — its only caller (st-gateway)
// has no Clerk session, so this route is protected by the same
// shared-secret/network-isolation combination as X-Origin-Verify
// (auth-design.md decision 9), not Clerk.
func requireSharedSecret(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Service-Secret") != expected {
			writeAuthError(w, http.StatusForbidden, "invalid or missing shared secret")
			return
		}
		next(w, r)
	}
}

// RequireSharedSecret reads the shared secret st-gateway presents to
// GET /auth/v1/token. No default, same "fail closed at startup" reasoning as
// RequireClerkJWTKey.
func RequireSharedSecret() (string, error) {
	secret := os.Getenv("AUTH_SERVICE_SHARED_SECRET")
	if secret == "" {
		return "", errors.New("AUTH_SERVICE_SHARED_SECRET must be set")
	}
	return secret, nil
}
