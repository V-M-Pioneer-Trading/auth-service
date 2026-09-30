package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"vnm/auth-service/api"
	"vnm/auth-service/db"
	"vnm/auth-service/poller"
)

func main() {
	conn := db.SetUpDatabase()

	clerkJWTKey, err := api.RequireClerkJWTKey()
	if err != nil {
		log.Fatal(err)
	}
	sharedSecret, err := api.RequireSharedSecret()
	if err != nil {
		log.Fatal(err)
	}
	// Deliberately not Require*: an unset AUTH_INTROSPECTION_SECRET is a
	// running service with a route that rejects everyone, not a crash loop.
	// Production has no such variable until meta#80 step 3. The only fatal
	// case is it being set to the vault's secret.
	introspectionSecret, err := api.ReadIntrospectionSecret(sharedSecret)
	if err != nil {
		log.Fatal(err)
	}
	if introspectionSecret == "" {
		log.Default().Print("AUTH_INTROSPECTION_SECRET is not set: POST /auth/v1/introspect will reject every caller")
	}

	// Unlike the introspection secret, a mis-set mint table IS fatal: a caller
	// secret colliding with another secret, or a caller with nothing to mint
	// with, is a deploy mistake. Unset caller secrets are not an error — they
	// disable the caller — so production without meta#59's parameters still
	// boots and the vault stays up.
	m2m, err := api.ReadM2MConfig(sharedSecret, introspectionSecret)
	if err != nil {
		log.Fatal(err)
	}
	logM2MCallers(m2m)

	p := poller.New(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	r, err := api.SetUpRouter(api.Config{
		Conn:                conn,
		Auth:                api.AuthConfig{ClerkJWTKeyPEM: clerkJWTKey, ClerkIssuer: os.Getenv("CLERK_ISSUER")},
		SharedSecret:        sharedSecret,
		IntrospectionSecret: introspectionSecret,
		M2M:                 m2m,
		Poller:              p,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Default 80 matches local compose (isolated per-container, no conflict).
	// Production sets PORT explicitly: this host runs every service on
	// --network host, and agent-service already hardcodes :80, so auth-service
	// needs its own distinct port there (see auth-service's Terraform stack).
	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// logM2MCallers says which callers can mint, and from what, by name only.
func logM2MCallers(cfg api.M2MConfig) {
	source := "Clerk"
	if cfg.DevSigningKeyPEM != "" {
		source = "the local dev key (DEV_M2M_SIGNING_KEY_FILE)"
	}
	enabled := 0
	for _, c := range cfg.Callers {
		if c.Secret != "" {
			enabled++
			log.Default().Printf("POST /auth/v1/m2m-token: %s mints via %s", c.Name, source)
		}
	}
	if enabled == 0 {
		log.Default().Print("no M2M_CALLER_SECRET_* is set: POST /auth/v1/m2m-token will reject every caller")
	}
}
