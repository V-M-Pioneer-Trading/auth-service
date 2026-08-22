package spacetraders

import "fmt"

// UpstreamError represents a non-2xx response from the SpaceTraders API.
// Handlers map StatusCode to the equivalent HTTP response instead of panicking.
type UpstreamError struct {
	StatusCode int
	Message    string
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("spacetraders upstream error (%d): %s", e.StatusCode, e.Message)
}
