package spacetraders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// All SpaceTraders calls route through st-gateway's shared rate budget, same
// as every other service in this family.
func gatewayBaseURL() string {
	if v := os.Getenv("ST_GATEWAY_URL"); v != "" {
		return v + "/proxy"
	}
	return "http://localhost:3002/proxy"
}

type RootInfo struct {
	ResetDate time.Time
	NextReset time.Time
	Frequency string
}

// rawRootResponse mirrors the fields of SpaceTraders' unauthenticated GET /
// that auth-service cares about. resetDate is documented as a bare date
// ("2024-05-10"); serverResets.next is a full timestamp — parseFlexibleTime
// accepts either shape so a format change on either field degrades to "poll
// again later" rather than a crash.
type rawRootResponse struct {
	ResetDate    string `json:"resetDate"`
	ServerResets struct {
		Next      string `json:"next"`
		Frequency string `json:"frequency"`
	} `json:"serverResets"`
}

func parseFlexibleTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetRoot calls the one unauthenticated SpaceTraders endpoint — no
// Authorization header, since resetDate/serverResets need no credential at
// all (auth-design.md decision 7).
func GetRoot() (RootInfo, error) {
	req, err := http.NewRequest(http.MethodGet, gatewayBaseURL()+"/", nil)
	if err != nil {
		return RootInfo{}, err
	}

	body, status, err := do(req)
	if err != nil {
		return RootInfo{}, err
	}
	if status >= 400 {
		return RootInfo{}, &UpstreamError{StatusCode: status, Message: fmt.Sprintf("GET /: %s", string(body))}
	}

	var raw rawRootResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return RootInfo{}, err
	}
	return RootInfo{
		ResetDate: parseFlexibleTime(raw.ResetDate),
		NextReset: parseFlexibleTime(raw.ServerResets.Next),
		Frequency: raw.ServerResets.Frequency,
	}, nil
}

type RegisterResult struct {
	AgentToken  string
	AgentSymbol string
	Credits     int
}

type registerRequestBody struct {
	Symbol  string `json:"symbol"`
	Faction string `json:"faction"`
	Email   string `json:"email,omitempty"`
}

type rawRegisterResponse struct {
	Data struct {
		Token string `json:"token"`
		Agent struct {
			Symbol  string `json:"symbol"`
			Credits int    `json:"credits"`
		} `json:"agent"`
	} `json:"data"`
}

// Register mints (or, on a reserved call sign, re-attaches) an agent — the
// only operation the account token exists for (auth-design.md decision 6/7).
// email reserves the call sign across a reset, so pass it whenever a prior
// registration recorded one.
func Register(accountToken, symbol, faction, email string) (RegisterResult, error) {
	payload, err := json.Marshal(registerRequestBody{Symbol: symbol, Faction: faction, Email: email})
	if err != nil {
		return RegisterResult{}, err
	}

	req, err := http.NewRequest(http.MethodPost, gatewayBaseURL()+"/register", bytes.NewReader(payload))
	if err != nil {
		return RegisterResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accountToken)
	req.Header.Set("Content-Type", "application/json")

	body, status, err := do(req)
	if err != nil {
		return RegisterResult{}, err
	}
	if status >= 400 {
		return RegisterResult{}, &UpstreamError{StatusCode: status, Message: fmt.Sprintf("POST /register: %s", string(body))}
	}

	var raw rawRegisterResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{
		AgentToken:  raw.Data.Token,
		AgentSymbol: raw.Data.Agent.Symbol,
		Credits:     raw.Data.Agent.Credits,
	}, nil
}

// httpClient is shared and bounded: a gateway that never answers would
// otherwise pin the poller's Tick — and, through PollNow, st-gateway's own
// 401-refresh path — indefinitely. 30s matches the sibling clients.
var httpClient = &http.Client{Timeout: 30 * time.Second}

func do(req *http.Request) ([]byte, int, error) {
	client := httpClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}
