package db

import (
	"database/sql"
	"errors"
	"time"
)

// Credential is the single persisted row this service exists to hold —
// auth-design.md decision 6: the account token is at rest here, never in SSM
// or an environment variable, so the fleet can recover unattended.
type Credential struct {
	AccountToken       string
	AgentToken         string
	AgentSymbol        string
	Faction            string
	Email              string
	ResetDate          time.Time // zero value = never observed
	NextPredictedReset time.Time // zero value = unknown
	TokenExpired       bool
}

// ErrNoCredentialConfigured is returned by UpdateAgentToken when no
// credential row exists yet — Restore Token only makes sense for an agent
// that has already been registered once.
var ErrNoCredentialConfigured = errors.New("no credential configured to restore a token onto")

const timeLayout = time.RFC3339

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(timeLayout)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// GetCredential returns the stored row and whether one exists at all — no row
// means UNCONFIGURED (auth-design.md decision 8), not an error.
func GetCredential(conn *sql.DB) (Credential, bool, error) {
	row := conn.QueryRow(`SELECT account_token, agent_token, agent_symbol, faction, email,
		reset_date, next_predicted_reset, token_expired FROM credential WHERE id = 1`)

	var c Credential
	var resetDate, nextReset string
	var tokenExpired int
	err := row.Scan(&c.AccountToken, &c.AgentToken, &c.AgentSymbol, &c.Faction, &c.Email,
		&resetDate, &nextReset, &tokenExpired)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, err
	}
	c.ResetDate = parseTime(resetDate)
	c.NextPredictedReset = parseTime(nextReset)
	c.TokenExpired = tokenExpired != 0
	return c, true, nil
}

// UpsertCredential writes the full row — used on initial registration and on
// automatic re-registration after an observed wipe. Always clears
// TokenExpired: a fresh agent token is by definition not expired.
func UpsertCredential(conn *sql.DB, c Credential, now time.Time) error {
	_, err := conn.Exec(`
		INSERT INTO credential (id, account_token, agent_token, agent_symbol, faction, email,
			reset_date, next_predicted_reset, token_expired, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, 0, ?)
		ON CONFLICT(id) DO UPDATE SET
			account_token = excluded.account_token,
			agent_token = excluded.agent_token,
			agent_symbol = excluded.agent_symbol,
			faction = excluded.faction,
			email = excluded.email,
			reset_date = excluded.reset_date,
			next_predicted_reset = excluded.next_predicted_reset,
			token_expired = 0,
			updated_at = excluded.updated_at`,
		c.AccountToken, c.AgentToken, c.AgentSymbol, c.Faction, c.Email,
		formatTime(c.ResetDate), formatTime(c.NextPredictedReset), formatTime(now))
	return err
}

// UpdateAgentToken is Restore Token (auth-design.md decision 8): the account
// token, symbol and reset history are untouched — only the ship-fleet token
// changes, and the expired flag clears since the operator just supplied a
// live one.
func UpdateAgentToken(conn *sql.DB, agentToken string, now time.Time) error {
	res, err := conn.Exec(`UPDATE credential SET agent_token = ?, token_expired = 0, updated_at = ?
		WHERE id = 1`, agentToken, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNoCredentialConfigured
	}
	return nil
}

// UpdateResetInfo persists the latest poll of SpaceTraders' unauthenticated
// GET / — auth-design.md decision 7.
func UpdateResetInfo(conn *sql.DB, resetDate, nextPredictedReset time.Time, now time.Time) error {
	_, err := conn.Exec(`UPDATE credential SET reset_date = ?, next_predicted_reset = ?, updated_at = ?
		WHERE id = 1`, formatTime(resetDate), formatTime(nextPredictedReset), formatTime(now))
	return err
}

// SetTokenExpired flips the flag decision 7's "401 with no resetDate change"
// path sets — the sole trigger for APP_TOKEN_EXPIRED.
func SetTokenExpired(conn *sql.DB, expired bool, now time.Time) error {
	val := 0
	if expired {
		val = 1
	}
	_, err := conn.Exec(`UPDATE credential SET token_expired = ?, updated_at = ? WHERE id = 1`, val, formatTime(now))
	return err
}

// AppendHistory records one entry in the append-only registration history —
// the "handful of rows plus a registration history" the design doc names as
// SQLite's whole justification here.
func AppendHistory(conn *sql.DB, now time.Time, event, detail string) error {
	_, err := conn.Exec(`INSERT INTO registration_history (occurred_at, event, detail) VALUES (?, ?, ?)`,
		formatTime(now), event, detail)
	return err
}
