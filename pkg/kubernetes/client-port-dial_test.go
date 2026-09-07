package kubernetes

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (this roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return this(req)
}

func TestContextRoundTripperAppliesDialContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := contextRoundTripper{
		ctx: ctx,
		delegate: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, req.Context().Err()
		}),
	}
	req, err := http.NewRequest(http.MethodPost, "https://example.test", nil)
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.ErrorIs(t, err, context.Canceled)
}
