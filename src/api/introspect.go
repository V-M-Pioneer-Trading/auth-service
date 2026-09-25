package api

// POST /auth/v1/introspect — auth-design.md decision 21 / meta#80 step 2.
//
// The one place a Clerk token is verified for the whole fleet. Every other
// service sends the token it received here and acts on the answer; this
// service's own vault routes call the same verifyToken below in-process, so
// there is exactly one verification code path and auth-service never makes an
// HTTP call to itself.
//
// Shape is RFC 7662: form-encoded `token=<jwt>` in the BODY (never a query
// string — a token in a URL lands in access logs), and the answer is always
// 200 with `{"active":false}` for anything that does not verify. Nothing about
// *why* it failed is returned: the remedy is identical for an expired token,
// a foreign signature and a wrong issuer, and distinguishing them is a probing
// oracle.

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IntrospectionSecretHeader is the header a calling service authenticates
// with. Fixed in meta/fixtures/introspection.json; three implementations agree
// on this spelling.
const IntrospectionSecretHeader = "X-Introspection-Secret"

// introspectionSecretRequired is the exact body of the 401 a caller gets when
// its secret is wrong, missing, or when this service has none configured. Quoted
// from meta/fixtures/introspection.json (`center-rejects-our-caller-secret`).
const introspectionSecretRequired = "a valid introspection secret is required"

// maxIntrospectionBody caps the form body. A Clerk session JWT is around 1 KB
// and the M2M token is smaller; 8 KiB leaves generous headroom while keeping an
// unauthenticated-shaped route from being a memory amplifier. An oversized body
// is not an error — it cannot contain a token this service would accept, so it
// answers `{"active":false}` like any other unverifiable input.
const maxIntrospectionBody = 8 << 10

// clockSkewLeeway is the `exp`/`nbf` leeway decision 21 asks for ("a small
// leeway") without naming a value. 60 s is chosen here: the services and the
// center share one host and one clock, so the leeway exists for clock drift
// between Clerk's minting host and ours, not for ours against itself, and a
// minute is the usual NTP-corrected worst case. It is deliberately far below
// a Clerk session token's lifetime, so it can never meaningfully extend a
// revoked session.
const clockSkewLeeway = 60 // seconds

// VerifiedToken is everything the center learned from a token, and the only
// thing it will ever say about one.
type VerifiedToken struct {
	Subject string
	// Scope is returned VERBATIM: whatever the claim held, unsplit and
	// unnormalised, whether it arrived as a string or as an array (an array is
	// joined with single spaces, which is the only transformation there is).
	// Splitting is the caller's job — every client splits on whitespace runs.
	Scope string
	// Expiry is the `exp` claim in seconds since the epoch.
	Expiry int64
}

// Kind is `operator` when the subject starts `user_`, otherwise `machine`.
// This is the one place in the fleet that knows Clerk's `sub` conventions;
// st-gateway and automation-service stop knowing them (decision 21). Clients
// must use this answer verbatim and never re-derive it.
func (v VerifiedToken) Kind() string {
	if strings.HasPrefix(v.Subject, "user_") {
		return "operator"
	}
	return "machine"
}

// errNotVerified is the only failure verifyToken reports. There is no variant
// per reason on purpose — see the file comment.
var errNotVerified = errors.New("token did not verify")

// verifyToken is THE verification function: RS256 pinned, `exp`/`nbf` with
// leeway, `CLERK_ISSUER` checked when configured, networkless, no bypass flag
// (decision 10). `azp` is deliberately NOT checked (owner's decision,
// 2026-09-20; see decision 21's "Not in this epic").
func (v *verifier) verifyToken(token string) (VerifiedToken, error) {
	if token == "" {
		return VerifiedToken{}, errNotVerified
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return v.publicKey, nil
	},
		// WithValidMethods is what makes an alg-confusion token ("none", or
		// HS256 signed with the PEM public key as the HMAC secret) fail before
		// the key function is consulted.
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(clockSkewLeeway*time.Second),
		issuerOption(v.issuer),
	)
	if err != nil || !parsed.Valid {
		return VerifiedToken{}, errNotVerified
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return VerifiedToken{}, errNotVerified
	}

	out := VerifiedToken{Scope: scopeStringFrom(claims)}
	if sub, ok := claims["sub"].(string); ok {
		out.Subject = sub
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		out.Expiry = exp.Unix()
	}
	return out, nil
}

// scopeStringFrom returns the `scope` claim as the single space-delimited
// string the contract promises. A string claim is passed through untouched —
// irregular whitespace and all — because the center returns it verbatim and
// every client splits on whitespace runs.
func scopeStringFrom(claims jwt.MapClaims) string {
	switch s := claims["scope"].(type) {
	case string:
		return s
	case []interface{}:
		parts := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				parts = append(parts, str)
			}
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

// introspectionResponse is the whole wire format, and it is a struct rather
// than a map precisely so no other claim can ever leak into it. A token's
// `iat`, `azp`, `sid`, `email` and anything else Clerk puts in it stay inside
// this process.
//
// Scope has no omitempty. Our contract is stricter than RFC 7662, which
// lets an active answer leave `scope` out: here it is ALWAYS present, as
// "" when the token carries none. A client that reads a missing scope as a
// malformed answer (ts-introspection-client 1.0.0-1.1.0 did, and answered
// 503; 1.1.1 tolerates it) would otherwise fail every signed-in user who
// holds no scopes.
type introspectionResponse struct {
	Active bool   `json:"active"`
	Sub    string `json:"sub,omitempty"`
	Scope  string `json:"scope"`
	Exp    int64  `json:"exp,omitempty"`
	Kind   string `json:"kind,omitempty"`
}

var inactiveResponse = introspectionResponse{Active: false}

// inactiveBody is what an inactive answer is marshalled as. Scope no longer
// has omitempty, so encoding introspectionResponse{Active: false} would emit
// `"scope":""`; an inactive answer must stay exactly {"active":false}.
type inactiveBody struct {
	Active bool `json:"active"`
}

// IntrospectionConfig is how the caller secret reaches the route.
type IntrospectionConfig struct {
	// Secret is AUTH_INTROSPECTION_SECRET. EMPTY MEANS FAIL CLOSED: the route
	// stays mounted and rejects every caller with 401. It is not a startup
	// error, because production does not have the variable yet (meta#80 step 3
	// applies it by hand) and a crash-looping auth-service takes the game
	// credential with it — the 2026-08-22 outage shape.
	Secret string
}

// introspectHandler builds the route. `secret` is compared in constant time;
// an empty configured secret rejects everything, including an empty header.
func (v *verifier) introspectHandler(secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !introspectionSecretOK(secret, r.Header.Get(IntrospectionSecretHeader)) {
			writeAuthError(w, http.StatusUnauthorized, introspectionSecretRequired)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxIntrospectionBody)
		// ParseForm would merge the URL query into r.Form; reading r.PostForm
		// is what makes `?token=…` structurally impossible to honour. A token
		// in a query string is ignored, not accepted, and the request is then
		// a request with no token: `{"active":false}`.
		if err := r.ParseForm(); err != nil {
			writeIntrospection(w, inactiveResponse)
			return
		}

		verified, err := v.verifyToken(r.PostForm.Get("token"))
		if err != nil {
			writeIntrospection(w, inactiveResponse)
			return
		}
		writeIntrospection(w, introspectionResponse{
			Active: true,
			Sub:    verified.Subject,
			Scope:  verified.Scope,
			Exp:    verified.Expiry,
			Kind:   verified.Kind(),
		})
	}
}

// introspectionSecretOK is constant-time, and fails closed on an unconfigured
// secret before any comparison happens — so an empty AUTH_INTROSPECTION_SECRET
// can never be satisfied by an empty or absent header.
func introspectionSecretOK(configured, presented string) bool {
	if configured == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(configured), []byte(presented)) == 1
}

func writeIntrospection(w http.ResponseWriter, resp introspectionResponse) {
	w.Header().Set("Content-Type", "application/json")
	// Deliberately uncacheable: decision 21 forbids caching an introspection
	// result anywhere, because a cache is a second verification path with a
	// different answer and it makes revocation mean nothing for its lifetime.
	w.Header().Set("Cache-Control", "no-store")
	if !resp.Active {
		json.NewEncoder(w).Encode(inactiveBody{Active: false})
		return
	}
	json.NewEncoder(w).Encode(resp)
}

// ReadIntrospectionSecret reads AUTH_INTROSPECTION_SECRET.
//
// Unlike RequireClerkJWTKey and RequireSharedSecret this one has NO error for
// being unset: the service must still start without it, because production
// gets the variable in meta#80 step 3 (a manual `terraform apply`) and a
// service that refuses to boot without it would take the vault down with the
// route it was meant to add. Unset means the route rejects every caller.
//
// It IS an error for the two secrets to be configured identically. That is not
// a typo to tolerate: the vault secret is held by st-gateway alone, and every
// service in the fleet holds the introspection secret — making them equal hands
// the key to GET /auth/v1/token to four more stacks, which is the one thing
// decision 21's infrastructure posture says must never happen. It cannot happen
// by accident in production today (the variable is absent), so failing to start
// costs nothing and a silently shared key would cost everything.
func ReadIntrospectionSecret(sharedSecret string) (string, error) {
	secret := os.Getenv("AUTH_INTROSPECTION_SECRET")
	if secret != "" && secret == sharedSecret {
		return "", errors.New("AUTH_INTROSPECTION_SECRET must not be the same value as AUTH_SERVICE_SHARED_SECRET: " +
			"the vault secret is st-gateway's alone, and the introspection secret is held by every service")
	}
	return secret, nil
}
