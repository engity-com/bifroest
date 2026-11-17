package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type samLogonUIModel struct {
	t                         *testing.T
	ctx                       context.Context
	cancel                    context.CancelFunc
	apiError                  error
	failAt, cancelAt, zeroAt  string
	resourceOnError           bool
	failed                    bool
	identityCalls             int
	value                     samLogonUIValue
	calls                     []string
	issued, closed            map[uintptr]int
	bufferIssued, bufferFreed int
}

func newSAMLogonUIModel(t *testing.T) *samLogonUIModel {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &samLogonUIModel{t: t, ctx: ctx, cancel: cancel, apiError: errors.New("injected native observation failure"), issued: map[uintptr]int{}, closed: map[uintptr]int{}}
}

func (m *samLogonUIModel) step(name string) error {
	m.calls = append(m.calls, name)
	if m.failed && name != "free" && !strings.HasPrefix(name, "close-") {
		m.t.Errorf("failed observation reached another operation: %s", name)
	}
	if m.cancelAt == name {
		m.failed = true
		m.cancel()
	}
	if m.failAt == name {
		m.failed = true
		return m.apiError
	}
	return nil
}

func (m *samLogonUIModel) acquire(name string, handle uintptr) (uintptr, error) {
	err := m.step(name)
	if m.zeroAt == name {
		m.failed = true
		return 0, err
	}
	if err != nil && !m.resourceOnError {
		return 0, err
	}
	m.issued[handle]++
	return handle, err
}

func (m *samLogonUIModel) operations() samLogonUIOperations {
	return samLogonUIOperations{
		identity: func() error { m.identityCalls++; return m.step(fmt.Sprintf("identity-%d", m.identityCalls)) },
		connect:  func() (uintptr, error) { return m.acquire("connect", 11) },
		openDomain: func(server uintptr) (uintptr, error) {
			require.Equal(m.t, uintptr(11), server)
			return m.acquire("domain", 22)
		},
		openUser: func(domain uintptr) (uintptr, error) {
			require.Equal(m.t, uintptr(22), domain)
			return m.acquire("user", 33)
		},
		query: func(user uintptr) (*samLogonUIValue, error) {
			require.Equal(m.t, uintptr(33), user)
			err := m.step("query")
			if m.zeroAt == "query" {
				m.failed = true
				return nil, err
			}
			if err != nil && !m.resourceOnError {
				return nil, err
			}
			m.bufferIssued++
			return &m.value, err
		},
		free: func(value *samLogonUIValue) error {
			require.Same(m.t, &m.value, value)
			m.bufferFreed++
			return m.step("free")
		},
		close: func(handle uintptr) error { m.closed[handle]++; return m.step(fmt.Sprintf("close-%d", handle)) },
	}
}

func (m *samLogonUIModel) requireReleased() {
	m.t.Helper()
	require.Equal(m.t, m.issued, m.closed, "every issued resource, including output returned with an error, must receive exactly one close attempt")
	require.Equal(m.t, m.bufferIssued, m.bufferFreed, "native response memory must receive exactly one free attempt")
}

func TestSAMLogonUIObservationCopiesOnlyValidBooleansAfterIdentityAndCleanup(t *testing.T) {
	for _, value := range []samLogonUIValue{{0, 0}, {0, 1}, {1, 0}, {1, 1}} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			m := newSAMLogonUIModel(t)
			m.value = value
			result, err := observeSAMLogonUIFlow(m.ctx, m.operations())
			require.NoError(t, err)
			require.Equal(t, &observedSAMLogonUI{PasswordIsBlank: value.PasswordIsBlank != 0, AccountDisabled: value.AccountIsDisabled != 0}, result)
			require.Equal(t, []string{"identity-1", "connect", "domain", "user", "query", "identity-2", "free", "close-33", "close-22", "close-11", "identity-3"}, m.calls)
			m.requireReleased()
		})
	}
}

func TestSAMLogonUIObservationDiscardsEveryAPICleanupAndIdentityFailure(t *testing.T) {
	for _, phase := range []string{"identity-1", "connect", "domain", "user", "query", "identity-2", "free", "close-33", "close-22", "close-11", "identity-3"} {
		for _, withOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/output=%t", phase, withOutput), func(t *testing.T) {
				m := newSAMLogonUIModel(t)
				m.failAt = phase
				m.resourceOnError = withOutput
				result, err := observeSAMLogonUIFlow(m.ctx, m.operations())
				require.Nil(t, result)
				require.ErrorIs(t, err, m.apiError)
				m.requireReleased()
			})
		}
	}
}

func TestSAMLogonUIObservationRejectsSuccessfulNullOutputsAndUnknownLayouts(t *testing.T) {
	for _, phase := range []string{"connect", "domain", "user", "query"} {
		t.Run(phase, func(t *testing.T) {
			m := newSAMLogonUIModel(t)
			m.zeroAt = phase
			result, err := observeSAMLogonUIFlow(m.ctx, m.operations())
			require.Nil(t, result)
			require.Error(t, err)
			m.requireReleased()
		})
	}
	for _, value := range []samLogonUIValue{{2, 0}, {0, 2}, {255, 1}, {1, 255}} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			m := newSAMLogonUIModel(t)
			m.value = value
			result, err := observeSAMLogonUIFlow(m.ctx, m.operations())
			require.Nil(t, result)
			require.ErrorContains(t, err, "BOOLEAN")
			require.NotContains(t, m.calls, "identity-2")
			m.requireReleased()
		})
	}
}

func TestSAMLogonUIObservationCancellationAtEveryBoundaryDiscardsResultAndJoinsCleanup(t *testing.T) {
	for _, phase := range []string{"identity-1", "connect", "domain", "user", "query", "identity-2", "free", "close-33", "close-22", "close-11", "identity-3"} {
		t.Run(phase, func(t *testing.T) {
			m := newSAMLogonUIModel(t)
			m.cancelAt = phase
			result, err := observeSAMLogonUIFlow(m.ctx, m.operations())
			require.Nil(t, result)
			require.ErrorIs(t, err, context.Canceled)
			m.requireReleased()
		})
	}
	t.Run("cleanup-error-and-cancellation", func(t *testing.T) {
		m := newSAMLogonUIModel(t)
		m.cancelAt = "free"
		m.failAt = "close-33"
		result, err := observeSAMLogonUIFlow(m.ctx, m.operations())
		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, m.apiError)
		m.requireReleased()
	})
}

func TestSAMLogonUIObservationRequiresContextAndCompleteOperations(t *testing.T) {
	for _, missing := range []struct {
		name  string
		apply func(*samLogonUIOperations)
	}{
		{"identity", func(v *samLogonUIOperations) { v.identity = nil }},
		{"connect", func(v *samLogonUIOperations) { v.connect = nil }},
		{"domain", func(v *samLogonUIOperations) { v.openDomain = nil }},
		{"user", func(v *samLogonUIOperations) { v.openUser = nil }},
		{"query", func(v *samLogonUIOperations) { v.query = nil }},
		{"free", func(v *samLogonUIOperations) { v.free = nil }},
		{"close", func(v *samLogonUIOperations) { v.close = nil }},
	} {
		t.Run(missing.name, func(t *testing.T) {
			m := newSAMLogonUIModel(t)
			api := m.operations()
			missing.apply(&api)
			result, err := observeSAMLogonUIFlow(m.ctx, api)
			require.Nil(t, result)
			require.Error(t, err)
			require.Empty(t, m.calls)
		})
	}
	t.Run("nil-context", func(t *testing.T) {
		m := newSAMLogonUIModel(t)
		result, err := observeSAMLogonUIFlow(nil, m.operations())
		require.Nil(t, result)
		require.Error(t, err)
		require.Empty(t, m.calls)
	})
	t.Run("already-canceled", func(t *testing.T) {
		m := newSAMLogonUIModel(t)
		m.cancel()
		result, err := observeSAMLogonUIFlow(m.ctx, m.operations())
		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
		require.Empty(t, m.calls)
	})
}
