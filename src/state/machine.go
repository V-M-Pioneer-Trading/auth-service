// Package state computes auth-service's own lifecycle — HEALTHY /
// WIPE_IMMINENT / APP_TOKEN_EXPIRED / UNCONFIGURED — the second state machine
// auth-design.md decision 8 describes, deliberately not composed with
// automation-service's armed/disarmed/paused/aborted axis. Compute is a pure
// function of the persisted row and the wall clock so it needs no database or
// network access to test.
package state

import "time"

type State string

const (
	Unconfigured    State = "UNCONFIGURED"
	Healthy         State = "HEALTHY"
	WipeImminent    State = "WIPE_IMMINENT"
	AppTokenExpired State = "APP_TOKEN_EXPIRED"
)

// wipeWindow is how far ahead of a predicted reset WIPE_IMMINENT fires —
// auth-design.md decision 7/8.
const wipeWindow = 24 * time.Hour

type Input struct {
	HasCredential      bool
	AgentSymbol        string
	ResetDate          time.Time // zero value = never observed
	NextPredictedReset time.Time // zero value = unknown
	TokenExpired       bool
}

// Status is the pure Go-facing result — no JSON tags here, since a zero-value
// time.Time doesn't trigger encoding/json's omitempty (it's a struct, not a
// primitive). The API layer owns the wire format and decides how to render
// "never observed" instead.
type Status struct {
	State              State
	AgentSymbol        string
	ResetDate          time.Time
	NextPredictedReset time.Time
}

// Compute derives the current state. Order matters: no credential at all
// outranks everything else, and a confirmed-expired token outranks the
// imminent-wipe forecast — decision 8 says the forecast is advisory, but a
// dead token needs a human regardless of how close the next predicted reset
// is.
func Compute(in Input, now time.Time) Status {
	s := Status{AgentSymbol: in.AgentSymbol, ResetDate: in.ResetDate, NextPredictedReset: in.NextPredictedReset}

	switch {
	case !in.HasCredential:
		s.State = Unconfigured
	case in.TokenExpired:
		s.State = AppTokenExpired
	case !in.NextPredictedReset.IsZero() && !now.Before(in.NextPredictedReset.Add(-wipeWindow)):
		s.State = WipeImminent
	default:
		s.State = Healthy
	}
	return s
}

// NextPollInterval implements decision 7's polling cadence as a pure
// function: once a day normally, hourly inside the 24h window before a
// predicted reset. The schedule only governs how often the prediction is
// refreshed — it never decides WIPE_IMMINENT itself (Compute's own clock
// comparison does that independently, so a missed tick can't silently shrink
// the warning window).
func NextPollInterval(now, nextPredictedReset time.Time) time.Duration {
	if nextPredictedReset.IsZero() {
		return 24 * time.Hour
	}
	if !now.Before(nextPredictedReset.Add(-wipeWindow)) {
		return time.Hour
	}
	return 24 * time.Hour
}
