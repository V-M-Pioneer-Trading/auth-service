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

	p := poller.New(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	r, err := api.SetUpRouter(api.Config{
		Conn:         conn,
		Auth:         api.AuthConfig{ClerkJWTKeyPEM: clerkJWTKey, ClerkIssuer: os.Getenv("CLERK_ISSUER")},
		SharedSecret: sharedSecret,
		Poller:       p,
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
