// Package poller implements auth-design.md decision 7: auth-service polls
// SpaceTraders' unauthenticated GET / through st-gateway at background
// priority, adopts a resetDate change as proof a wipe already happened (the
// only trigger that re-registers), and treats a 401 with no resetDate change
// as a dead-not-wiped token (decision 8's APP_TOKEN_EXPIRED).
package poller

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"

	"vnm/auth-service/db"
	"vnm/auth-service/spacetraders"
	"vnm/auth-service/state"
)

// forcedPollCooldown bounds how often an out-of-cycle poll (triggered by
// st-gateway forwarding a 401) can actually hit SpaceTraders — st-gateway's
// own retry loop could otherwise turn a burst of 401s into a poll storm.
const forcedPollCooldown = 10 * time.Second

type Poller struct {
	Conn      *sql.DB
	FetchRoot func() (spacetraders.RootInfo, error)
	Register  func(accountToken, symbol, faction, email string) (spacetraders.RegisterResult, error)
	Clock     func() time.Time

	mu         sync.Mutex
	lastForced time.Time
}

func New(conn *sql.DB) *Poller {
	return &Poller{
		Conn:      conn,
		FetchRoot: spacetraders.GetRoot,
		Register:  spacetraders.Register,
		Clock:     time.Now,
	}
}

// Run ticks forever at the cadence decision 7 specifies, recomputed after
// every poll so a fresh prediction immediately takes effect. Errors are
// logged, not fatal — a transient st-gateway/SpaceTraders failure should not
// crash the service that exists to survive exactly that kind of hiccup.
func (p *Poller) Run(ctx context.Context) {
	for {
		if err := p.Tick(false); err != nil {
			log.Default().Printf("poller tick failed: %v", err)
		}

		next := p.nextInterval()
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

func (p *Poller) nextInterval() time.Duration {
	cred, ok, err := db.GetCredential(p.Conn)
	if err != nil || !ok {
		return 24 * time.Hour
	}
	return state.NextPollInterval(p.Clock(), cred.NextPredictedReset)
}

// PollNow is the out-of-cycle path decision 7 requires: st-gateway calls this
// (via GET /auth/v1/token?afterUnauthorized=true) the moment it sees a 401
// from SpaceTraders, forcing detection instead of waiting for the schedule.
// Scheduled ticks (Run) call Tick directly and skip the cooldown — only the
// forced path needs rate limiting.
func (p *Poller) PollNow() error {
	p.mu.Lock()
	now := p.Clock()
	if now.Sub(p.lastForced) < forcedPollCooldown {
		p.mu.Unlock()
		return nil
	}
	p.lastForced = now
	p.mu.Unlock()

	return p.Tick(true)
}

// Tick runs one poll-and-react cycle. afterUnauthorized distinguishes "we're
// polling because a 401 just happened" from "we're polling on schedule" —
// only the former can conclude APP_TOKEN_EXPIRED, since a scheduled poll
// finding an unchanged resetDate says nothing about whether the token still
// works.
func (p *Poller) Tick(afterUnauthorized bool) error {
	now := p.Clock()

	cred, ok, err := db.GetCredential(p.Conn)
	if err != nil {
		return err
	}
	if !ok {
		// UNCONFIGURED: nothing to compare a fetched resetDate against yet.
		return nil
	}

	root, err := p.FetchRoot()
	if err != nil {
		return err
	}

	resetChanged := !cred.ResetDate.IsZero() && !root.ResetDate.IsZero() && !root.ResetDate.Equal(cred.ResetDate)

	switch {
	case resetChanged:
		if err := db.AppendHistory(p.Conn, now, "wipe_detected", "observed resetDate change"); err != nil {
			log.Default().Printf("failed to record wipe_detected: %v", err)
		}
		if err := p.reregister(cred, now); err != nil {
			// The reset is real regardless; leave token_expired alone (a
			// failed auto-reregistration is not the same claim as a
			// confirmed-dead token) and let the next tick retry.
			return err
		}
	case afterUnauthorized:
		if err := db.SetTokenExpired(p.Conn, true, now); err != nil {
			return err
		}
		if err := db.AppendHistory(p.Conn, now, "token_expired_detected", "401 with no resetDate change"); err != nil {
			log.Default().Printf("failed to record token_expired_detected: %v", err)
		}
	}

	return db.UpdateResetInfo(p.Conn, root.ResetDate, root.NextReset, now)
}

// reregister re-mints the agent using the account token and reserved call
// sign already on file — decision 7's "reserve the call sign and pass it",
// so the event log and metrics keep correlating across a reset instead of
// silently starting over under a new agent symbol.
func (p *Poller) reregister(cred db.Credential, now time.Time) error {
	result, err := p.Register(cred.AccountToken, cred.AgentSymbol, cred.Faction, cred.Email)
	if err != nil {
		return err
	}

	updated := cred
	updated.AgentToken = result.AgentToken
	if err := db.UpsertCredential(p.Conn, updated, now); err != nil {
		return err
	}
	return db.AppendHistory(p.Conn, now, "registered", "automatic re-registration after observed reset")
}
