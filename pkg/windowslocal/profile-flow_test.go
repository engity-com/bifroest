package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type samProfileModel struct {
	t                        *testing.T
	ctx                      context.Context
	cancel                   context.CancelFunc
	failure                  error
	failAt, cancelAt, nullAt string
	outputOnError, failed    bool
	issued, closed           map[uintptr]int
	loaded, unloaded         int
	counts                   map[string]int
	calls                    []string
}

func newSAMProfileModel(t *testing.T) *samProfileModel {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &samProfileModel{t: t, ctx: ctx, cancel: cancel, failure: errors.New("native profile operation failed"), issued: map[uintptr]int{}, closed: map[uintptr]int{}, counts: map[string]int{}}
}

func (m *samProfileModel) step(name string) error {
	if name == "identity" || name == "system" {
		m.counts[name]++
		name = fmt.Sprintf("%s%d", name, m.counts[name])
	}
	m.calls = append(m.calls, name)
	if m.failed && name != "unload" && name != "close22" && name != "close11" {
		m.t.Errorf("failed profile flow reached another native operation: %s", name)
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

func (m *samProfileModel) token(name string, value uintptr) (uintptr, error) {
	err := m.step(name)
	if name == m.nullAt {
		m.failed = true
		return 0, err
	}
	if err != nil && !m.outputOnError {
		return 0, err
	}
	m.issued[value]++
	return value, err
}

func (m *samProfileModel) operations() samProfileOperations {
	return samProfileOperations{
		identity: func() error { return m.step("identity") },
		system:   func() error { return m.step("system") },
		s4u:      func() (uintptr, error) { return m.token("s4u", 11) },
		duplicate: func(value uintptr) (uintptr, error) {
			require.Equal(m.t, uintptr(11), value)
			return m.token("duplicate", 22)
		},
		tokenIdentity: func(value uintptr) error { require.Equal(m.t, uintptr(22), value); return m.step("token") },
		load: func(value uintptr) (uintptr, error) {
			require.Equal(m.t, uintptr(22), value)
			err := m.step("load")
			if m.nullAt == "load" {
				m.failed = true
				return 0, err
			}
			if err != nil && !m.outputOnError {
				return 0, err
			}
			m.loaded++
			return 33, err
		},
		directory: func(value uintptr) (string, error) {
			require.Equal(m.t, uintptr(22), value)
			err := m.step("directory")
			if m.nullAt == "directory" {
				m.failed = true
				return "", err
			}
			return `C:\Users\owned-fixture`, err
		},
		unload: func(token, profile uintptr) error {
			require.Equal(m.t, uintptr(22), token)
			require.Equal(m.t, uintptr(33), profile)
			m.unloaded++
			return m.step("unload")
		},
		closeToken: func(value uintptr) error { m.closed[value]++; return m.step(fmt.Sprintf("close%d", value)) },
	}
}

func (m *samProfileModel) requireCleanup() {
	m.t.Helper()
	require.Equal(m.t, m.issued, m.closed, "every token output must receive exactly one close attempt, not a physical-release guarantee")
	require.Equal(m.t, m.loaded, m.unloaded, "every profile output must receive one unload attempt")
	var expected, actual []string
	if m.loaded > 0 {
		expected = append(expected, "unload")
	}
	if m.issued[22] > 0 {
		expected = append(expected, "close22")
	}
	if m.issued[11] > 0 {
		expected = append(expected, "close11")
	}
	for _, name := range m.calls {
		if name == "unload" || name == "close22" || name == "close11" {
			actual = append(actual, name)
		}
	}
	require.Equal(m.t, expected, actual, "profile unload must precede primary-token then impersonation-token close, even after errors")
}

func TestSAMProfileDirectoryReturnsOnlyAfterCleanupAndFreshIdentity(t *testing.T) {
	m := newSAMProfileModel(t)
	home, err := readSAMProfileDirectory(m.ctx, m.operations())
	require.NoError(t, err)
	require.Equal(t, `C:\Users\owned-fixture`, home)
	require.Equal(t, []string{"identity1", "system1", "s4u", "duplicate", "token", "identity2", "load", "directory", "identity3", "unload", "close22", "close11", "identity4", "system2"}, m.calls)
	m.requireCleanup()
}

func TestSAMProfileDirectoryDiscardsEveryNativeAndCleanupFailure(t *testing.T) {
	for _, phase := range []string{"identity1", "system1", "s4u", "duplicate", "token", "identity2", "load", "directory", "identity3", "unload", "close22", "close11", "identity4", "system2"} {
		for _, output := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/output=%t", phase, output), func(t *testing.T) {
				m := newSAMProfileModel(t)
				m.failAt = phase
				m.outputOnError = output
				home, err := readSAMProfileDirectory(m.ctx, m.operations())
				require.Empty(t, home)
				require.ErrorIs(t, err, m.failure)
				m.requireCleanup()
			})
		}
	}
}

func TestSAMProfileDirectoryJoinsCancellationAtEveryBoundary(t *testing.T) {
	for _, phase := range []string{"identity1", "system1", "s4u", "duplicate", "token", "identity2", "load", "directory", "identity3", "unload", "close22", "close11", "identity4", "system2"} {
		t.Run(phase, func(t *testing.T) {
			m := newSAMProfileModel(t)
			m.cancelAt = phase
			home, err := readSAMProfileDirectory(m.ctx, m.operations())
			require.Empty(t, home)
			require.ErrorIs(t, err, context.Canceled)
			m.requireCleanup()
		})
	}
}

func TestSAMProfileDirectoryRejectsNullOutputsAndPreservesAllCleanupErrors(t *testing.T) {
	for _, phase := range []string{"s4u", "duplicate", "load", "directory"} {
		t.Run("null-"+phase, func(t *testing.T) {
			m := newSAMProfileModel(t)
			m.nullAt = phase
			home, err := readSAMProfileDirectory(m.ctx, m.operations())
			require.Empty(t, home)
			require.Error(t, err)
			m.requireCleanup()
		})
	}
	t.Run("combined-cleanup-and-cancel", func(t *testing.T) {
		m := newSAMProfileModel(t)
		api := m.operations()
		unload, closeToken := api.unload, api.closeToken
		unloadError, closePrimary, closeImpersonation := errors.New("unload failed"), errors.New("close primary failed"), errors.New("close impersonation failed")
		api.unload = func(token, profile uintptr) error { _ = unload(token, profile); m.failed = true; return unloadError }
		api.closeToken = func(token uintptr) error {
			_ = closeToken(token)
			if token == 22 {
				return closePrimary
			}
			m.cancel()
			return closeImpersonation
		}
		home, err := readSAMProfileDirectory(m.ctx, api)
		require.Empty(t, home)
		require.ErrorIs(t, err, unloadError)
		require.ErrorIs(t, err, closePrimary)
		require.ErrorIs(t, err, closeImpersonation)
		require.ErrorIs(t, err, context.Canceled)
		m.requireCleanup()
	})
}

func TestSAMProfileDirectoryRequiresContextAndCompleteOperations(t *testing.T) {
	for _, missing := range []struct {
		name  string
		apply func(*samProfileOperations)
	}{
		{"identity", func(v *samProfileOperations) { v.identity = nil }},
		{"system", func(v *samProfileOperations) { v.system = nil }},
		{"s4u", func(v *samProfileOperations) { v.s4u = nil }},
		{"duplicate", func(v *samProfileOperations) { v.duplicate = nil }},
		{"token", func(v *samProfileOperations) { v.tokenIdentity = nil }},
		{"load", func(v *samProfileOperations) { v.load = nil }},
		{"directory", func(v *samProfileOperations) { v.directory = nil }},
		{"unload", func(v *samProfileOperations) { v.unload = nil }},
		{"close", func(v *samProfileOperations) { v.closeToken = nil }},
	} {
		t.Run(missing.name, func(t *testing.T) {
			m := newSAMProfileModel(t)
			api := m.operations()
			missing.apply(&api)
			home, err := readSAMProfileDirectory(m.ctx, api)
			require.Empty(t, home)
			require.Error(t, err)
			require.Empty(t, m.calls)
		})
	}
	t.Run("nil-context", func(t *testing.T) {
		m := newSAMProfileModel(t)
		home, err := readSAMProfileDirectory(nil, m.operations())
		require.Empty(t, home)
		require.Error(t, err)
		require.Empty(t, m.calls)
	})
	t.Run("already-canceled", func(t *testing.T) {
		m := newSAMProfileModel(t)
		m.cancel()
		home, err := readSAMProfileDirectory(m.ctx, m.operations())
		require.Empty(t, home)
		require.ErrorIs(t, err, context.Canceled)
		require.Empty(t, m.calls)
	})
}
