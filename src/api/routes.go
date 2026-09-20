package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"vnm/auth-service/db"
	"vnm/auth-service/poller"
	"vnm/auth-service/spacetraders"
	"vnm/auth-service/state"
)

// Config is everything SetUpRouter needs to wire the five routes in
// auth-design.md's "New repository: auth-service" table.
type Config struct {
	Conn         *sql.DB
	Auth         AuthConfig
	SharedSecret string
	// IntrospectionSecret gates POST /auth/v1/introspect. Empty is legal and
	// means the route rejects every caller (see introspect.go) — production
	// has no AUTH_INTROSPECTION_SECRET until meta#80 step 3 applies it.
	IntrospectionSecret string
	Poller              *poller.Poller
}

type handlers struct {
	conn   *sql.DB
	poller *poller.Poller
}

func SetUpRouter(cfg Config) (*mux.Router, error) {
	h := &handlers{conn: cfg.Conn, poller: cfg.Poller}
	v, err := newVerifier(cfg.Auth)
	if err != nil {
		return nil, err
	}
	// Refuse to wire anything if the two secrets are the same value. main
	// already checks this while reading the environment; it is repeated here
	// so no future caller of SetUpRouter can assemble the collision by hand.
	// Empty is not a collision — it is the fail-closed state.
	if cfg.IntrospectionSecret != "" && cfg.IntrospectionSecret == cfg.SharedSecret {
		return nil, errors.New("the introspection secret must not be the same value as the vault's shared secret")
	}

	r := mux.NewRouter()
	r.Use(loggingMiddleware, corsMiddleware)
	// Catch-all for CORS preflight: corsMiddleware answers OPTIONS itself and
	// never calls this handler, but a route has to exist here for OPTIONS to
	// match at all.
	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	r.HandleFunc("/health", handleHealth).Methods(http.MethodGet)

	// GET /auth/v1/token is deliberately bare, no /api prefix, and shared-
	// secret gated rather than Clerk-gated — its only legitimate caller is
	// st-gateway on the authnet bridge, and auth-design.md decision 9 is
	// explicit that this path must never get a public (Caddy) route at any
	// method. It is the only route in this service that can return a token.
	r.HandleFunc("/auth/v1/token", requireSharedSecret(cfg.SharedSecret, h.getToken)).Methods(http.MethodGet)

	// POST /auth/v1/introspect is mounted bare and on the existing listener —
	// one process, one port, no new container (decision 21). It is deliberately
	// NOT under /api/auth: its callers are sibling services on the host, never
	// a browser through CloudFront, and the path is fixed by
	// meta/fixtures/introspection.json. Methods(POST) is what makes a GET a 405
	// rather than an answer — a token must never travel in a URL.
	r.HandleFunc("/auth/v1/introspect", v.introspectHandler(cfg.IntrospectionSecret)).Methods(http.MethodPost)

	// GET /auth/v1/status is also mounted bare: decision 8 calls it "the
	// second instance" of the existing GET /autopilot/status pattern, which
	// command-interface polls directly rather than through /api/*.
	r.HandleFunc("/auth/v1/status", h.getStatus).Methods(http.MethodGet)

	api := r.PathPrefix("/api/auth").Subrouter()
	// Health mounted both bare above (local dev/compose) and here
	// (production CloudFront only routes requests matching a configured path
	// pattern) — same rationale as every sibling service.
	api.HandleFunc("/health", handleHealth).Methods(http.MethodGet)

	v1 := api.PathPrefix("/v1").Subrouter()
	v1.HandleFunc("/status", h.getStatus).Methods(http.MethodGet)
	// Restore Token and Reset Agent both require agent:reset — the only
	// scope this service enforces.
	v1.HandleFunc("/agent-token", v.requireScope(SCOPEAgentReset, h.restoreToken)).Methods(http.MethodPost)
	v1.HandleFunc("/register", v.requireScope(SCOPEAgentReset, h.registerAgent)).Methods(http.MethodPost)

	return r, nil
}

// getToken is st-gateway's only way to obtain the agent token it injects on
// every upstream call (auth-design.md decision 5). ?afterUnauthorized=true
// is how decision 7's "a 401 forces an immediate, out-of-cycle poll" reaches
// this service — st-gateway sets it the moment SpaceTraders itself returns
// 401, rather than waiting for the daily/hourly schedule.
func (h *handlers) getToken(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("afterUnauthorized") == "true" {
		if err := h.poller.PollNow(); err != nil {
			log.Default().Printf("forced poll after 401 failed: %v", err)
		}
	}

	cred, ok, err := db.GetCredential(h.conn)
	if err != nil {
		http.Error(w, "failed to load credential: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || cred.AgentToken == "" {
		http.Error(w, "no agent token configured", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]string{"agentToken": cred.AgentToken})
}

// statusResponse is the wire format for GET /auth/v1/status. Timestamps are
// formatted explicitly and omitted when zero — encoding/json's omitempty
// does not treat a zero-value time.Time as empty, since it's a struct, not a
// primitive.
type statusResponse struct {
	State              state.State `json:"state"`
	AgentSymbol        string      `json:"agentSymbol,omitempty"`
	ResetDate          string      `json:"resetDate,omitempty"`
	NextPredictedReset string      `json:"nextPredictedReset,omitempty"`
}

func toStatusResponse(s state.Status) statusResponse {
	resp := statusResponse{State: s.State, AgentSymbol: s.AgentSymbol}
	if !s.ResetDate.IsZero() {
		resp.ResetDate = s.ResetDate.Format(time.RFC3339)
	}
	if !s.NextPredictedReset.IsZero() {
		resp.NextPredictedReset = s.NextPredictedReset.Format(time.RFC3339)
	}
	return resp
}

// getStatus never returns a token in any state (decision 6/8) — it exists so
// the dashboard (and anonymous visitors) can render the two lifecycle
// banners without needing a session.
func (h *handlers) getStatus(w http.ResponseWriter, r *http.Request) {
	cred, ok, err := db.GetCredential(h.conn)
	if err != nil {
		http.Error(w, "failed to load status: "+err.Error(), http.StatusInternalServerError)
		return
	}
	status := state.Compute(state.Input{
		HasCredential:      ok,
		AgentSymbol:        cred.AgentSymbol,
		ResetDate:          cred.ResetDate,
		NextPredictedReset: cred.NextPredictedReset,
		TokenExpired:       cred.TokenExpired,
	}, time.Now())
	writeJSON(w, toStatusResponse(status))
}

type restoreTokenRequest struct {
	AgentToken string `json:"agentToken"`
}

// restoreToken is decision 8's Restore Token: a regenerated agent token for
// the *existing* agent, the only valid recovery from APP_TOKEN_EXPIRED. The
// account token, symbol and reset history are left untouched.
func (h *handlers) restoreToken(w http.ResponseWriter, r *http.Request) {
	var body restoreTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.AgentToken == "" {
		http.Error(w, "agentToken is required", http.StatusBadRequest)
		return
	}

	now := time.Now()
	if err := db.UpdateAgentToken(h.conn, body.AgentToken, now); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, db.ErrNoCredentialConfigured) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	if err := db.AppendHistory(h.conn, now, "token_restored", ""); err != nil {
		log.Default().Printf("failed to record token_restored: %v", err)
	}
	writeJSON(w, map[string]string{"status": "restored"})
}

type registerRequest struct {
	AccountToken string `json:"accountToken"`
	Symbol       string `json:"symbol"`
	Faction      string `json:"faction"`
	Email        string `json:"email,omitempty"`
}

// registerAgent is decision 7's Reset Agent: mints a new agent with the
// account token and persists the reserved call sign so future automatic
// re-registrations (poller.Tick) can reuse it across a reset.
func (h *handlers) registerAgent(w http.ResponseWriter, r *http.Request) {
	var body registerRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.AccountToken == "" || body.Symbol == "" || body.Faction == "" {
		http.Error(w, "accountToken, symbol and faction are required", http.StatusBadRequest)
		return
	}

	result, err := h.poller.Register(body.AccountToken, body.Symbol, body.Faction, body.Email)
	if !writeIfError(w, err) {
		return
	}

	now := time.Now()
	cred := db.Credential{
		AccountToken: body.AccountToken,
		AgentToken:   result.AgentToken,
		AgentSymbol:  result.AgentSymbol,
		Faction:      body.Faction,
		Email:        body.Email,
	}
	if err := db.UpsertCredential(h.conn, cred, now); err != nil {
		http.Error(w, "registered but failed to persist credential: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := db.AppendHistory(h.conn, now, "registered", "manual registration via POST /register"); err != nil {
		log.Default().Printf("failed to record registered: %v", err)
	}

	// Populate resetDate/nextPredictedReset immediately rather than waiting
	// for the next scheduled tick, so GET /auth/v1/status reflects real data
	// right away.
	if err := h.poller.Tick(false); err != nil {
		log.Default().Printf("post-registration poll failed: %v", err)
	}

	writeJSON(w, map[string]string{"agentSymbol": result.AgentSymbol, "status": "registered"})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

// writeIfError maps an *UpstreamError to its SpaceTraders-reported status
// code (or 502 for anything else, e.g. network failures) and writes it to
// the response. Returns false when an error was written, so callers can
// `if !writeIfError(w, err) { return }`.
func writeIfError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	var upstreamErr *spacetraders.UpstreamError
	if errors.As(err, &upstreamErr) {
		status := upstreamErr.StatusCode
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		http.Error(w, upstreamErr.Message, status)
		return false
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
	return false
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Default().Printf("failed to write JSON response: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path, never r.RequestURI: the latter carries the query string,
		// and a caller that (wrongly) sends `?token=…` to /auth/v1/introspect
		// would write a live credential into every log sink on the host. The
		// route already ignores a query-string token; the log must not keep it.
		log.Default().Printf("%s request: to %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	allowedOrigin := os.Getenv("CORS_ALLOWED_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "http://localhost:3000"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Auth-Service-Secret")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
