package session

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type expiredPredicateTestSession struct {
	Session
	info expiredPredicateTestInfo
}

func (this expiredPredicateTestSession) Info(context.Context) (Info, error) { return this.info, nil }

type expiredPredicateTestInfo struct {
	Info
	state      State
	validUntil time.Time
}

func (this expiredPredicateTestInfo) State() State { return this.state }
func (this expiredPredicateTestInfo) ValidUntil(context.Context) (time.Time, error) {
	return this.validUntil, nil
}

func TestExpiredSessionRetentionRespectsValidUntilAfterDisposal(t *testing.T) {
	for _, tc := range []struct {
		name       string
		state      State
		validUntil time.Time
		threshold  time.Duration
		want       bool
	}{
		{name: "recently expired and disposed", state: StateDisposed, validUntil: time.Now().Add(-time.Minute), threshold: time.Hour},
		{name: "retention elapsed and disposed", state: StateDisposed, validUntil: time.Now().Add(-2 * time.Hour), threshold: time.Hour, want: true},
		{name: "immediately disposed with zero retention", state: StateDisposed, validUntil: time.Now().Add(time.Hour), want: true},
		{name: "disposed without a validity deadline", state: StateDisposed, threshold: time.Hour, want: true},
		{name: "recently expired and active", state: StateAuthorized, validUntil: time.Now().Add(-time.Minute), threshold: time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := expiredPredicateTestSession{info: expiredPredicateTestInfo{state: tc.state, validUntil: tc.validUntil}}
			got, err := IsExpiredWithThreshold(tc.threshold)(t.Context(), candidate)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
