package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type samRestrictionModel struct {
	t                                      *testing.T
	ctx                                    context.Context
	cancel                                 context.CancelFunc
	failure                                error
	failAt, cancelAt                       string
	blank, restricted                      bool
	blankAfter, restrictedAfter            bool
	changeAfter, nullToken, tokenWithError bool
	failed, issued                         bool
	closed                                 int
	counts                                 map[string]int
	calls                                  []string
}

func newSAMRestrictionModel(t *testing.T) *samRestrictionModel {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &samRestrictionModel{t: t, ctx: ctx, cancel: cancel, failure: errors.New("injected native restriction error"), counts: map[string]int{}}
}

func (m *samRestrictionModel) step(operation string) error {
	m.counts[operation]++
	name := operation
	if operation != "s4u" && operation != "token" && operation != "close" {
		name = fmt.Sprintf("%s-%d", operation, m.counts[operation])
	}
	m.calls = append(m.calls, name)
	if m.failed && operation != "close" {
		m.t.Errorf("failure or cancellation reached another policy operation: %s", name)
	}
	if m.cancelAt == name {
		m.failed = true
		m.cancel()
	}
	if m.failAt == name {
		m.failed = true
		return m.failure
	}
	return nil
}

func (m *samRestrictionModel) operations() samPasswordRestrictionOperations {
	return samPasswordRestrictionOperations{
		system:       func() error { return m.step("system") },
		identity:     func() error { return m.step("identity") },
		accountState: func() error { return m.step("state") },
		blankPassword: func() (bool, error) {
			err := m.step("blank")
			if m.changeAfter && m.counts["blank"] == 2 {
				return m.blankAfter, err
			}
			return m.blank, err
		},
		blankNetwork: func() (bool, error) {
			err := m.step("network")
			if m.changeAfter && m.counts["network"] == 2 {
				return m.restrictedAfter, err
			}
			return m.restricted, err
		},
		s4u: func() (uintptr, error) {
			err := m.step("s4u")
			if m.nullToken || err != nil && !m.tokenWithError {
				return 0, err
			}
			m.issued = true
			return 19, err
		},
		tokenIdentity: func(token uintptr) error { require.Equal(m.t, uintptr(19), token); return m.step("token") },
		closeToken:    func(token uintptr) error { require.Equal(m.t, uintptr(19), token); m.closed++; return m.step("close") },
	}
}

func (m *samRestrictionModel) requireCleanup() {
	m.t.Helper()
	if m.issued {
		require.Equal(m.t, 1, m.closed, "each token output receives exactly one close attempt before returning")
	} else {
		require.Zero(m.t, m.closed)
	}
	if m.counts["state"] == 2 {
		require.True(m.t, strings.Index(strings.Join(m.calls, ","), "close") < strings.Index(strings.Join(m.calls, ","), "state-2"), "token cleanup must finish before the final restriction snapshot")
	}
}

func TestSAMCombinedRestrictionsRequireOperatorAndNativeBlankPermission(t *testing.T) {
	for _, blank := range []bool{false, true} {
		for _, restricted := range []bool{false, true} {
			for _, allowEmpty := range []bool{false, true} {
				t.Run(fmt.Sprintf("blank=%t/network=%t/operator=%t", blank, restricted, allowEmpty), func(t *testing.T) {
					m := newSAMRestrictionModel(t)
					m.blank = blank
					m.restricted = restricted
					err := checkSAMPasswordRestrictionsFlow(m.ctx, allowEmpty, m.operations())
					denied := blank && (!allowEmpty || restricted)
					if denied {
						require.ErrorIs(t, err, errSAMPasswordRestriction)
						require.Zero(t, m.counts["s4u"])
					} else {
						require.NoError(t, err)
						require.Equal(t, []string{"system-1", "identity-1", "state-1", "blank-1", "network-1", "identity-2", "s4u", "token", "close", "identity-3", "state-2", "blank-2", "network-2", "identity-4", "system-2"}, m.calls)
					}
					m.requireCleanup()
				})
			}
		}
	}
}

func TestSAMCombinedRestrictionsRejectEveryErrorAndCancellationBoundary(t *testing.T) {
	for _, phase := range []string{"system-1", "identity-1", "state-1", "blank-1", "network-1", "identity-2", "s4u", "token", "close", "identity-3", "state-2", "blank-2", "network-2", "identity-4", "system-2"} {
		for _, cancel := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%t", phase, cancel), func(t *testing.T) {
				m := newSAMRestrictionModel(t)
				if cancel {
					m.cancelAt = phase
				} else {
					m.failAt = phase
				}
				err := checkSAMPasswordRestrictionsFlow(m.ctx, true, m.operations())
				if cancel {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.ErrorIs(t, err, m.failure)
				}
				m.requireCleanup()
			})
		}
	}
}

func TestSAMCombinedRestrictionsOwnUnexpectedTokenOutputsAndCleanupErrors(t *testing.T) {
	t.Run("error-with-token", func(t *testing.T) {
		m := newSAMRestrictionModel(t)
		m.failAt = "s4u"
		m.tokenWithError = true
		err := checkSAMPasswordRestrictionsFlow(m.ctx, true, m.operations())
		require.ErrorIs(t, err, m.failure)
		require.Zero(t, m.counts["token"])
		m.requireCleanup()
	})
	t.Run("null-success", func(t *testing.T) {
		m := newSAMRestrictionModel(t)
		m.nullToken = true
		err := checkSAMPasswordRestrictionsFlow(m.ctx, true, m.operations())
		require.ErrorContains(t, err, "no token")
		require.Zero(t, m.counts["token"])
		require.Zero(t, m.counts["state"]-1)
		m.requireCleanup()
	})
	t.Run("identity-and-close-and-cancel", func(t *testing.T) {
		m := newSAMRestrictionModel(t)
		m.failAt = "token"
		api := m.operations()
		closeToken := api.closeToken
		closeFailure := errors.New("token close failed")
		api.closeToken = func(token uintptr) error { _ = closeToken(token); m.cancel(); return closeFailure }
		err := checkSAMPasswordRestrictionsFlow(m.ctx, true, api)
		require.ErrorIs(t, err, m.failure)
		require.ErrorIs(t, err, closeFailure)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 1, m.counts["state"])
		m.requireCleanup()
	})
}

func TestSAMCombinedRestrictionsRecheckPolicyAfterTokenCleanup(t *testing.T) {
	for _, scenario := range []string{"password-became-blank", "native-network-restriction-enabled"} {
		t.Run(scenario, func(t *testing.T) {
			m := newSAMRestrictionModel(t)
			m.changeAfter = true
			allowEmpty := scenario != "password-became-blank"
			m.blank = allowEmpty
			m.blankAfter = true
			m.restrictedAfter = allowEmpty
			err := checkSAMPasswordRestrictionsFlow(m.ctx, allowEmpty, m.operations())
			require.ErrorIs(t, err, errSAMPasswordRestriction)
			require.Equal(t, 1, m.counts["s4u"])
			require.Equal(t, 2, m.counts["blank"])
			m.requireCleanup()
		})
	}
}

func TestSAMCombinedRestrictionsRequireLiveContextAndAllOperations(t *testing.T) {
	for _, missing := range []struct {
		name  string
		apply func(*samPasswordRestrictionOperations)
	}{
		{"system", func(v *samPasswordRestrictionOperations) { v.system = nil }},
		{"identity", func(v *samPasswordRestrictionOperations) { v.identity = nil }},
		{"state", func(v *samPasswordRestrictionOperations) { v.accountState = nil }},
		{"blank", func(v *samPasswordRestrictionOperations) { v.blankPassword = nil }},
		{"network", func(v *samPasswordRestrictionOperations) { v.blankNetwork = nil }},
		{"s4u", func(v *samPasswordRestrictionOperations) { v.s4u = nil }},
		{"token", func(v *samPasswordRestrictionOperations) { v.tokenIdentity = nil }},
		{"close", func(v *samPasswordRestrictionOperations) { v.closeToken = nil }},
	} {
		t.Run(missing.name, func(t *testing.T) {
			m := newSAMRestrictionModel(t)
			api := m.operations()
			missing.apply(&api)
			require.Error(t, checkSAMPasswordRestrictionsFlow(m.ctx, true, api))
			require.Empty(t, m.calls)
		})
	}
	t.Run("nil-context", func(t *testing.T) {
		m := newSAMRestrictionModel(t)
		require.Error(t, checkSAMPasswordRestrictionsFlow(nil, true, m.operations()))
		require.Empty(t, m.calls)
	})
	t.Run("already-canceled", func(t *testing.T) {
		m := newSAMRestrictionModel(t)
		m.cancel()
		require.ErrorIs(t, checkSAMPasswordRestrictionsFlow(m.ctx, true, m.operations()), context.Canceled)
		require.Empty(t, m.calls)
	})
}
