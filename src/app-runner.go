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

	p := poller.New(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	r, err := api.SetUpRouter(api.Config{
		Conn:                conn,
		Auth:                api.AuthConfig{ClerkJWTKeyPEM: clerkJWTKey, ClerkIssuer: os.Getenv("CLERK_ISSUER")},
		SharedSecret:        sharedSecret,
		IntrospectionSecret: introspectionSecret,
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
