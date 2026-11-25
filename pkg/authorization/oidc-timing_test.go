package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

// A loopback socket cannot become durably blocked in a synctest bubble. Keep
// provider I/O in the bubble while exercising the real OAuth client and timers.
// The TLS/redirect integration tests continue to use real loopback servers.
func oidcTimingTestContext(t *testing.T, handler http.HandlerFunc) context.Context {
	t.Helper()
	client := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			defer req.Body.Close()
		}
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		response := httptest.NewRecorder()
		handler(response, req)
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		return response.Result(), nil
	})}
	return context.WithValue(t.Context(), oauth2.HTTPClient, client)
}
