package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type s4uFlowModel struct {
	t                                               *testing.T
	ctx                                             context.Context
	cancel                                          context.CancelFunc
	failure                                         error
	failAt, cancelAt                                string
	registerOnError, tokenOnError, profileOnError   bool
	nullRegistration, nullToken, noProfile          bool
	failed                                          bool
	calls                                           []string
	registered, tokenIssued, profileIssued          bool
	deregisterAttempts, freeAttempts, closeAttempts int
}

func newS4UFlowModel(t *testing.T) *s4uFlowModel {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &s4uFlowModel{t: t, ctx: ctx, cancel: cancel, failure: errors.New("injected S4U native failure")}
}

func (m *s4uFlowModel) step(name string) error {
	m.calls = append(m.calls, name)
	if m.failed && name != "free" && name != "deregister" && name != "close" {
		m.t.Errorf("failed S4U flow reached another native operation: %s", name)
	}
	if name == m.cancelAt {
		m.failed = true
		m.cancel()
	}
	if name == m.failAt {
		m.failed = true
		return m.failure
	}
	return nil
}

func (m *s4uFlowModel) operations() s4uTokenOperations {
	return s4uTokenOperations{
		register: func() (uintptr, error) {
			err := m.step("register")
			if m.nullRegistration {
				m.failed = true
				return 0, err
			}
			if err != nil && !m.registerOnError {
				return 0, err
			}
			m.registered = true
			return 101, err
		},
		lookupPackage: func(handle uintptr) (uint32, error) {
			require.Equal(m.t, uintptr(101), handle)
			return 0, m.step("lookup")
		}, // PackageID zero is valid.
		allocateLUID: func() error { return m.step("allocate") },
		logon: func(handle uintptr, packageID uint32) (s4uLogonOutput, error) {
			require.Equal(m.t, uintptr(101), handle)
			require.Zero(m.t, packageID)
			err := m.step("logon")
			result := s4uLogonOutput{}
			if !m.nullToken && (err == nil || m.tokenOnError) {
				result.token = 303
				m.tokenIssued = true
			}
			if !m.noProfile && (err == nil || m.profileOnError) {
				result.profile = 202
				m.profileIssued = true
			}
			if m.nullToken {
				m.failed = true
			}
			return result, err
		},
		freeProfile: func(profile uintptr) error {
			require.Equal(m.t, uintptr(202), profile)
			m.freeAttempts++
			return m.step("free")
		},
		deregister: func(handle uintptr) error {
			require.Equal(m.t, uintptr(101), handle)
			m.deregisterAttempts++
			return m.step("deregister")
		},
		closeToken: func(token uintptr) error {
			require.Equal(m.t, uintptr(303), token)
			m.closeAttempts++
			return m.step("close")
		},
	}
}

func (m *s4uFlowModel) requireOwnership(result uintptr) {
	m.t.Helper()
	wantDeregister, wantFree, wantClose := 0, 0, 0
	if m.registered {
		wantDeregister = 1
	}
	if m.profileIssued {
		wantFree = 1
	}
	if m.tokenIssued && result == 0 {
		wantClose = 1
	}
	require.Equal(m.t, wantDeregister, m.deregisterAttempts, "exactly one deregistration attempt per registration output")
	require.Equal(m.t, wantFree, m.freeAttempts, "exactly one free attempt per profile output")
	require.Equal(m.t, wantClose, m.closeAttempts, "an issued token transfers only on success; otherwise exactly one close attempt")
	var expected, actual []string
	if m.profileIssued {
		expected = append(expected, "free")
	}
	if m.registered {
		expected = append(expected, "deregister")
	}
	if m.tokenIssued && result == 0 {
		expected = append(expected, "close")
	}
	for _, name := range m.calls {
		if name == "free" || name == "deregister" || name == "close" {
			actual = append(actual, name)
		}
	}
	require.Equal(m.t, expected, actual, "profile free must precede deregistration and token cleanup on every outcome")
}

func TestS4UFlowTransfersTokenOnlyAfterCleanup(t *testing.T) {
	for _, withoutProfile := range []bool{false, true} {
		t.Run(fmt.Sprintf("no-profile=%t", withoutProfile), func(t *testing.T) {
			m := newS4UFlowModel(t)
			m.noProfile = withoutProfile
			result, err := acquireS4UToken(m.ctx, m.operations())
			require.NoError(t, err)
			require.Equal(t, uintptr(303), result)
			expected := []string{"register", "lookup", "allocate", "logon"}
			if !withoutProfile {
				expected = append(expected, "free")
			}
			expected = append(expected, "deregister")
			require.Equal(t, expected, m.calls)
			m.requireOwnership(result)
		})
	}
}

func TestS4UFlowRejectsErrorsAndCleansReturnedResources(t *testing.T) {
	for _, withOutput := range []bool{false, true} {
		t.Run(fmt.Sprintf("register/output=%t", withOutput), func(t *testing.T) {
			m := newS4UFlowModel(t)
			m.failAt = "register"
			m.registerOnError = withOutput
			result, err := acquireS4UToken(m.ctx, m.operations())
			require.Zero(t, result)
			require.ErrorIs(t, err, m.failure)
			m.requireOwnership(result)
		})
	}
	for _, phase := range []string{"lookup", "allocate", "free", "deregister"} {
		t.Run(phase, func(t *testing.T) {
			m := newS4UFlowModel(t)
			m.failAt = phase
			result, err := acquireS4UToken(m.ctx, m.operations())
			require.Zero(t, result)
			require.ErrorIs(t, err, m.failure)
			m.requireOwnership(result)
		})
	}
	for _, token := range []bool{false, true} {
		for _, profile := range []bool{false, true} {
			t.Run(fmt.Sprintf("logon/token=%t/profile=%t", token, profile), func(t *testing.T) {
				m := newS4UFlowModel(t)
				m.failAt = "logon"
				m.tokenOnError = token
				m.profileOnError = profile
				result, err := acquireS4UToken(m.ctx, m.operations())
				require.Zero(t, result)
				require.ErrorIs(t, err, m.failure)
				m.requireOwnership(result)
			})
		}
	}
	for _, phase := range []string{"registration", "token"} {
		t.Run("null-"+phase, func(t *testing.T) {
			m := newS4UFlowModel(t)
			m.nullRegistration = phase == "registration"
			m.nullToken = phase == "token"
			result, err := acquireS4UToken(m.ctx, m.operations())
			require.Zero(t, result)
			require.ErrorContains(t, err, "returned no")
			m.requireOwnership(result)
		})
	}
}

func TestS4UFlowCancellationAtEveryBoundaryStopsNativeWork(t *testing.T) {
	for _, phase := range []string{"register", "lookup", "allocate", "logon", "free", "deregister", "close"} {
		t.Run(phase, func(t *testing.T) {
			m := newS4UFlowModel(t)
			m.cancelAt = phase
			if phase == "close" {
				m.failAt = "free"
			}
			result, err := acquireS4UToken(m.ctx, m.operations())
			require.Zero(t, result)
			require.ErrorIs(t, err, context.Canceled)
			if phase == "close" {
				require.ErrorIs(t, err, m.failure)
			}
			m.requireOwnership(result)
		})
	}
}

func TestS4UFlowPreservesAllCleanupErrorsAndCancellation(t *testing.T) {
	m := newS4UFlowModel(t)
	api := m.operations()
	freeFailure, deregisterFailure, closeFailure := errors.New("free failed"), errors.New("deregister failed"), errors.New("close failed")
	free, deregister, closeToken := api.freeProfile, api.deregister, api.closeToken
	api.freeProfile = func(value uintptr) error { _ = free(value); m.failed = true; return freeFailure }
	api.deregister = func(value uintptr) error { _ = deregister(value); return deregisterFailure }
	api.closeToken = func(value uintptr) error { _ = closeToken(value); m.cancel(); return closeFailure }
	result, err := acquireS4UToken(m.ctx, api)
	require.Zero(t, result)
	require.ErrorIs(t, err, freeFailure)
	require.ErrorIs(t, err, deregisterFailure)
	require.ErrorIs(t, err, closeFailure)
	require.ErrorIs(t, err, context.Canceled)
	m.requireOwnership(result)
}

func TestS4UFlowRequiresContextAndCompleteOperations(t *testing.T) {
	for _, missing := range []struct {
		name  string
		apply func(*s4uTokenOperations)
	}{
		{"register", func(v *s4uTokenOperations) { v.register = nil }},
		{"lookup", func(v *s4uTokenOperations) { v.lookupPackage = nil }},
		{"allocate", func(v *s4uTokenOperations) { v.allocateLUID = nil }},
		{"logon", func(v *s4uTokenOperations) { v.logon = nil }},
		{"free", func(v *s4uTokenOperations) { v.freeProfile = nil }},
		{"deregister", func(v *s4uTokenOperations) { v.deregister = nil }},
		{"close", func(v *s4uTokenOperations) { v.closeToken = nil }},
	} {
		t.Run(missing.name, func(t *testing.T) {
			m := newS4UFlowModel(t)
			api := m.operations()
			missing.apply(&api)
			result, err := acquireS4UToken(m.ctx, api)
			require.Zero(t, result)
			require.Error(t, err)
			require.Empty(t, m.calls)
		})
	}
	t.Run("nil-context", func(t *testing.T) {
		m := newS4UFlowModel(t)
		result, err := acquireS4UToken(nil, m.operations())
		require.Zero(t, result)
		require.Error(t, err)
		require.Empty(t, m.calls)
	})
	t.Run("already-canceled", func(t *testing.T) {
		m := newS4UFlowModel(t)
		m.cancel()
		result, err := acquireS4UToken(m.ctx, m.operations())
		require.Zero(t, result)
		require.ErrorIs(t, err, context.Canceled)
		require.Empty(t, m.calls)
	})
}
