package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-github/v65/github"
	"github.com/stretchr/testify/require"
)

func TestRetryGitHubRead(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		failures int
		calls    int
		elapsed  time.Duration
	}{
		{name: "success", calls: 1},
		{name: "internal server error", status: 500, failures: 1, calls: 2, elapsed: time.Second},
		{name: "bad gateway", status: 502, failures: 1, calls: 2, elapsed: time.Second},
		{name: "service unavailable", status: 503, failures: 2, calls: 3, elapsed: 3 * time.Second},
		{name: "gateway timeout", status: 504, failures: 1, calls: 2, elapsed: time.Second},
		{name: "exhausted", status: 503, failures: 10, calls: 3, elapsed: 3 * time.Second},
		{name: "unauthorized", status: 401, failures: 1, calls: 1},
		{name: "forbidden", status: 403, failures: 1, calls: 1},
		{name: "not found", status: 404, failures: 1, calls: 1},
		{name: "rate limited", status: 429, failures: 1, calls: 1},
		{name: "transport error", failures: 1, calls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				failure := errors.New("injected GitHub failure")
				calls := 0
				start := time.Now()
				err := retryGitHubRead(t.Context(), func() (*github.Response, error) {
					calls++
					if calls > test.failures {
						return nil, nil
					}
					if test.status == 0 {
						return nil, failure
					}
					return &github.Response{Response: &http.Response{StatusCode: test.status}}, failure
				})
				if test.calls > test.failures {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, failure)
				}
				require.Equal(t, test.calls, calls)
				require.Equal(t, test.elapsed, time.Since(start))
			})
		})
	}
}

func TestRetryGitHubReadHonorsCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		calls := 0
		start := time.Now()
		err := retryGitHubRead(ctx, func() (*github.Response, error) {
			calls++
			return &github.Response{Response: &http.Response{StatusCode: 503}}, errors.New("unavailable")
		})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, 1, calls)
		require.Equal(t, 100*time.Millisecond, time.Since(start))

		ctx, cancel = context.WithCancel(t.Context())
		cancel()
		err = retryGitHubRead(ctx, func() (*github.Response, error) {
			t.Fatal("an already canceled read must not be attempted")
			return nil, nil
		})
		require.ErrorIs(t, err, context.Canceled)
	})
}
