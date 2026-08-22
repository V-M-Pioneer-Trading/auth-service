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

type verifier struct {
	publicKey interface{}
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

// scopesFrom accepts the `scope` claim as either a space-delimited string
// (the OAuth convention Clerk's default session token uses) or an array, so a
// caller is never locked out by a formatting choice made in a dashboard.
func scopesFrom(claims jwt.MapClaims) []string {
	switch v := claims["scope"].(type) {
	case string:
		return strings.Fields(v)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if str, ok := s.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]map[string]string{"error": {"message": message}})
}

// verify runs the real check requireScope relies on: a well-formed,
// correctly-signed, unexpired Clerk session carrying agent:reset.
func (v *verifier) verify(w http.ResponseWriter, r *http.Request, hasScope func([]string) bool) bool {
	token := bearerFrom(r)
	if token == "" {
		writeAuthError(w, http.StatusUnauthorized, "a bearer token is required")
		return false
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return v.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), issuerOption(v.issuer))
	if err != nil || !parsed.Valid {
		// Not surfacing the specific reason — "expired" vs "bad signature" vs
		// "wrong issuer" is a probing oracle, and the remedy is the same.
		writeAuthError(w, http.StatusUnauthorized, "invalid or expired session")
		return false
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !hasScope(scopesFrom(claims)) {
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
