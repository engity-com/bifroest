package main

import (
	"context"
	"net/http"
	"time"

	"github.com/echocat/slf4g"
	"github.com/google/go-github/v65/github"
)

// Only use this for read-only requests: retrying mutations may repeat a change
// whose response was lost. Authentication and other permanent errors fail fast.
func retryGitHubRead(ctx context.Context, read func() (*github.Response, error)) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		response, err := read()
		if err == nil || attempt == 2 || response == nil || response.Response == nil {
			return err
		}
		switch response.StatusCode {
		case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		default:
			return err
		}
		delay := time.Second << attempt
		log.WithError(err).With("retryIn", delay).Warn("GitHub read failed; retrying")
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
