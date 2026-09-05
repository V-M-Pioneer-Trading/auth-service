package poller

import (
	"database/sql"
	"testing"
	"time"

	"vnm/auth-service/db"
	"vnm/auth-service/spacetraders"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func seedCredential(t *testing.T, conn *sql.DB, c db.Credential, now time.Time) {
	t.Helper()
	if err := db.UpsertCredential(conn, c, now); err != nil {
		t.Fatal(err)
	}
}

func mustParse(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestTickAdoptsResetDateOnFirstEverPollWithoutTreatingItAsAWipe(t *testing.T) {
	conn := testDB(t)
	now := mustParse("2026-08-22T12:00:00Z")
	seedCredential(t, conn, db.Credential{AccountToken: "acc", AgentToken: "agt", AgentSymbol: "RADOMSKY", Faction: "COSMIC"}, now)

	registerCalled := false
	p := &Poller{
		Conn:  conn,
		Clock: func() time.Time { return now },
		FetchRoot: func() (spacetraders.RootInfo, error) {
			return spacetraders.RootInfo{ResetDate: mustParse("2026-08-01T00:00:00Z")}, nil
		},
		Register: func(accountToken, symbol, faction, email string) (spacetraders.RegisterResult, error) {
			registerCalled = true
			return spacetraders.RegisterResult{}, nil
		},
	}

	if err := p.Tick(false); err != nil {
		t.Fatal(err)
	}
	if registerCalled {
		t.Fatal("first-ever poll adopted a resetDate but was treated as a wipe")
	}

	cred, ok, err := db.GetCredential(conn)
	if err != nil || !ok {
		t.Fatalf("expected a credential row, ok=%v err=%v", ok, err)
	}
	if !cred.ResetDate.Equal(mustParse("2026-08-01T00:00:00Z")) {
		t.Fatalf("expected resetDate to be adopted, got %v", cred.ResetDate)
	}
}

func TestTickReregistersOnAnObservedResetDateChange(t *testing.T) {
	conn := testDB(t)
	seedAt := mustParse("2026-08-01T00:00:00Z")
	seedCredential(t, conn, db.Credential{
		AccountToken: "acc", AgentToken: "old-token", AgentSymbol: "RADOMSKY", Faction: "COSMIC", Email: "op@example.com",
		ResetDate: mustParse("2026-07-01T00:00:00Z"),
	}, seedAt)

	now := mustParse("2026-08-22T12:00:00Z")
	var registeredWith struct{ symbol, faction, email string }
	p := &Poller{
		Conn:  conn,
		Clock: func() time.Time { return now },
		FetchRoot: func() (spacetraders.RootInfo, error) {
			return spacetraders.RootInfo{ResetDate: mustParse("2026-08-22T00:00:00Z")}, nil
		},
		Register: func(accountToken, symbol, faction, email string) (spacetraders.RegisterResult, error) {
			registeredWith.symbol, registeredWith.faction, registeredWith.email = symbol, faction, email
			return spacetraders.RegisterResult{AgentToken: "new-token", AgentSymbol: symbol}, nil
		},
	}

	if err := p.Tick(false); err != nil {
		t.Fatal(err)
	}

	if registeredWith.symbol != "RADOMSKY" || registeredWith.faction != "COSMIC" || registeredWith.email != "op@example.com" {
		t.Fatalf("expected re-registration to reuse the reserved call sign/faction/email, got %+v", registeredWith)
	}

	cred, _, err := db.GetCredential(conn)
	if err != nil {
		t.Fatal(err)
	}
	if cred.AgentToken != "new-token" {
		t.Fatalf("expected the new agent token to be persisted, got %q", cred.AgentToken)
	}
	if cred.TokenExpired {
		t.Fatal("expected token_expired to clear on a successful re-registration")
	}
}

func TestTickMarksTokenExpiredOnlyWhenForcedAndResetDateUnchanged(t *testing.T) {
	conn := testDB(t)
	now := mustParse("2026-08-22T12:00:00Z")
	seedCredential(t, conn, db.Credential{
		AccountToken: "acc", AgentToken: "agt", AgentSymbol: "RADOMSKY", Faction: "COSMIC",
		ResetDate: mustParse("2026-08-01T00:00:00Z"),
	}, now)

	p := &Poller{
		Conn:  conn,
		Clock: func() time.Time { return now },
		FetchRoot: func() (spacetraders.RootInfo, error) {
			return spacetraders.RootInfo{ResetDate: mustParse("2026-08-01T00:00:00Z")}, nil
		},
		Register: func(accountToken, symbol, faction, email string) (spacetraders.RegisterResult, error) {
			t.Fatal("should not re-register")
			return spacetraders.RegisterResult{}, nil
		},
	}

	// Unforced tick with an unchanged resetDate: not a signal of anything.
	if err := p.Tick(false); err != nil {
		t.Fatal(err)
	}
	if cred, _, _ := db.GetCredential(conn); cred.TokenExpired {
		t.Fatal("an unforced tick must not mark the token expired")
	}

	// Forced (post-401) tick with an unchanged resetDate: this is exactly
	// decision 8's APP_TOKEN_EXPIRED trigger.
	if err := p.Tick(true); err != nil {
		t.Fatal(err)
	}
	cred, _, err := db.GetCredential(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !cred.TokenExpired {
		t.Fatal("expected token_expired after a forced tick with no resetDate change")
	}
}

func TestPollNowRateLimitsForcedPolls(t *testing.T) {
	conn := testDB(t)
	now := mustParse("2026-08-22T12:00:00Z")
	seedCredential(t, conn, db.Credential{AccountToken: "acc", AgentToken: "agt", AgentSymbol: "RADOMSKY", Faction: "COSMIC"}, now)

	calls := 0
	p := &Poller{
		Conn:      conn,
		Clock:     func() time.Time { return now },
		FetchRoot: func() (spacetraders.RootInfo, error) { calls++; return spacetraders.RootInfo{}, nil },
		Register: func(accountToken, symbol, faction, email string) (spacetraders.RegisterResult, error) {
			return spacetraders.RegisterResult{}, nil
		},
	}

	if err := p.PollNow(); err != nil {
		t.Fatal(err)
	}
	if err := p.PollNow(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected the second immediate call to be rate-limited, got %d fetches", calls)
	}

	now = now.Add(11 * time.Second)
	if err := p.PollNow(); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected a call after the cooldown elapsed, got %d fetches", calls)
	}
}

func TestTickIsANoOpWhenUnconfigured(t *testing.T) {
	conn := testDB(t)
	now := mustParse("2026-08-22T12:00:00Z")

	called := false
	p := &Poller{
		Conn:      conn,
		Clock:     func() time.Time { return now },
		FetchRoot: func() (spacetraders.RootInfo, error) { called = true; return spacetraders.RootInfo{}, nil },
		Register: func(accountToken, symbol, faction, email string) (spacetraders.RegisterResult, error) {
			return spacetraders.RegisterResult{}, nil
		},
	}

	if err := p.Tick(false); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("expected no poll while UNCONFIGURED (no credential to compare against)")
	}
}
