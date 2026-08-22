package state

import (
	"testing"
	"time"
)

func mustParse(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestComputeUnconfiguredWhenNoCredentialExists(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	got := Compute(Input{HasCredential: false}, now)
	if got.State != Unconfigured {
		t.Fatalf("expected UNCONFIGURED, got %s", got.State)
	}
}

func TestComputeHealthyWithNoPredictedResetYet(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	got := Compute(Input{HasCredential: true, AgentSymbol: "RADOMSKY"}, now)
	if got.State != Healthy {
		t.Fatalf("expected HEALTHY, got %s", got.State)
	}
}

func TestComputeHealthyWellBeforeThePredictedReset(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	next := mustParse("2026-08-29T12:00:00Z") // a week out
	got := Compute(Input{HasCredential: true, NextPredictedReset: next}, now)
	if got.State != Healthy {
		t.Fatalf("expected HEALTHY, got %s", got.State)
	}
}

func TestComputeWipeImminentInsideThe24HourWindow(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	next := mustParse("2026-08-23T06:00:00Z") // 18h out
	got := Compute(Input{HasCredential: true, NextPredictedReset: next}, now)
	if got.State != WipeImminent {
		t.Fatalf("expected WIPE_IMMINENT, got %s", got.State)
	}
}

func TestComputeWipeImminentAtExactlyTheBoundary(t *testing.T) {
	next := mustParse("2026-08-23T12:00:00Z")
	now := next.Add(-24 * time.Hour) // exactly on the boundary
	got := Compute(Input{HasCredential: true, NextPredictedReset: next}, now)
	if got.State != WipeImminent {
		t.Fatalf("expected WIPE_IMMINENT exactly at the 24h boundary, got %s", got.State)
	}
}

func TestComputeAppTokenExpiredOutranksAnImminentWipeForecast(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	next := mustParse("2026-08-23T06:00:00Z") // also inside the window
	got := Compute(Input{HasCredential: true, NextPredictedReset: next, TokenExpired: true}, now)
	if got.State != AppTokenExpired {
		t.Fatalf("expected APP_TOKEN_EXPIRED to outrank WIPE_IMMINENT, got %s", got.State)
	}
}

func TestComputeNoCredentialOutranksEverythingElse(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	got := Compute(Input{HasCredential: false, TokenExpired: true}, now)
	if got.State != Unconfigured {
		t.Fatalf("expected UNCONFIGURED to outrank APP_TOKEN_EXPIRED, got %s", got.State)
	}
}

func TestNextPollIntervalIsDailyFarFromAReset(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	next := mustParse("2026-08-29T12:00:00Z")
	if got := NextPollInterval(now, next); got != 24*time.Hour {
		t.Fatalf("expected 24h, got %s", got)
	}
}

func TestNextPollIntervalIsHourlyInsideTheWindow(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	next := mustParse("2026-08-23T06:00:00Z")
	if got := NextPollInterval(now, next); got != time.Hour {
		t.Fatalf("expected 1h, got %s", got)
	}
}

func TestNextPollIntervalIsDailyWithNoPredictionYet(t *testing.T) {
	now := mustParse("2026-08-22T12:00:00Z")
	if got := NextPollInterval(now, time.Time{}); got != 24*time.Hour {
		t.Fatalf("expected 24h with no prediction, got %s", got)
	}
}
