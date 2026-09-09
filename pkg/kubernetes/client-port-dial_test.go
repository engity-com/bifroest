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

func TestPortForwardStreamErrorMarksRefusedPodEndpointAsNotReady(t *testing.T) {
	err := portForwardStreamError(`failed to execute portforward in network namespace "/var/run/netns/test": failed to connect to localhost:8683 inside namespace "container", IPv4: dial tcp4 127.0.0.1:8683: connect: connection refused IPv6 dial tcp6: address localhost: no suitable address found`)

	require.ErrorIs(t, err, ErrEndpointNotReady)
	require.ErrorContains(t, err, "failed to connect to localhost:8683")
}

func TestPortForwardStreamErrorPreservesUnrelatedFailure(t *testing.T) {
	err := portForwardStreamError("unable to create stream")

	require.NotErrorIs(t, err, ErrEndpointNotReady)
	require.ErrorContains(t, err, "unable to create stream")
}
