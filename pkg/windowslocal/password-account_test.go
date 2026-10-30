package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type samPasswordViewModel struct {
	t                               *testing.T
	ctx                             context.Context
	cancel                          context.CancelFunc
	account                         Account
	failure                         error
	failAt, cancelAt                string
	identityCount, restrictionCount int
	changedAt                       int
	groups                          []group
	calls                           []string
}

func newSAMPasswordViewModel(t *testing.T) *samPasswordViewModel {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &samPasswordViewModel{t: t, ctx: ctx, cancel: cancel, account: Account{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}, failure: errors.New("fresh view native failure"), groups: []group{{Name: "current", SID: "S-1-5-32-545"}}}
}

func (m *samPasswordViewModel) step(name string) error {
	m.calls = append(m.calls, name)
	if m.cancelAt == name {
		m.cancel()
	}
	if m.failAt == name {
		return m.failure
	}
	return nil
}

func (m *samPasswordViewModel) operations() samPasswordAccountOperations {
	return samPasswordAccountOperations{
		restrictions: func() error { m.restrictionCount++; return m.step(fmt.Sprintf("restrictions%d", m.restrictionCount)) },
		identity: func() (Account, error) {
			m.identityCount++
			err := m.step(fmt.Sprintf("identity%d", m.identityCount))
			value := m.account
			if m.changedAt == m.identityCount {
				value.SID += "1"
			}
			return value, err
		},
		displayName: func() (string, error) { return "Current Alice", m.step("display") },
		homeDir:     func() (string, error) { return `C:\Users\alice`, m.step("home") },
		shell:       func() (string, error) { return `C:\Windows\system32\cmd.exe`, m.step("shell") },
		groups:      func() ([]group, error) { return m.groups, m.step("groups") },
	}
}

func TestSAMPasswordAccountViewIsFreshBoundCopiedAndComparable(t *testing.T) {
	m := newSAMPasswordViewModel(t)
	view, err := readSAMPasswordAccount(m.ctx, m.account, m.operations())
	require.NoError(t, err)
	require.Equal(t, m.account, view.Account())
	require.Equal(t, []string{"restrictions1", "identity1", "display", "home", "shell", "identity2", "groups", "identity3", "restrictions2", "identity4"}, m.calls)
	for field, expected := range map[string]any{"name": "alice", "uid": m.account.SID, "displayName": "Current Alice", "homeDir": `C:\Users\alice`, "shell": `C:\Windows\system32\cmd.exe`, "gids": []string{"S-1-5-32-545"}, "managed": nil} {
		value, found, err := view.GetField(field)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, expected, value)
	}
	value, _, err := view.GetField("groups")
	require.NoError(t, err)
	value.([]group)[0].Name = "outside mutation"
	value, _, err = view.GetField("groups")
	require.NoError(t, err)
	require.Equal(t, "current", value.([]group)[0].Name)
	copy := *view
	copy.groups = append([]group(nil), view.groups...)
	require.True(t, view.IsEqualTo(&copy))
	m.groups[0].Name = "changed native data"
	require.Equal(t, "current", view.groups[0].Name)
	for _, field := range []string{"identity", "display", "home", "shell", "groups"} {
		t.Run(field, func(t *testing.T) {
			changed := copy
			changed.groups = append([]group(nil), copy.groups...)
			switch field {
			case "identity":
				changed.account.SID += "1"
			case "display":
				changed.displayName = "other"
			case "home":
				changed.homeDir += "-other"
			case "shell":
				changed.shell = "other"
			case "groups":
				changed.groups[0].Name = "other"
			}
			require.False(t, view.IsEqualTo(&changed))
		})
	}
	require.False(t, view.IsEqualTo(nil))
	var absent *PasswordAccount
	require.Zero(t, absent.Account())
	_, found, err := view.GetField("unknown")
	require.False(t, found)
	require.Error(t, err)
}

func TestSAMPasswordAccountViewDiscardsEveryErrorCancellationAndIdentityDrift(t *testing.T) {
	for _, phase := range []string{"restrictions1", "identity1", "display", "home", "shell", "identity2", "groups", "identity3", "restrictions2", "identity4"} {
		for _, cancel := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%t", phase, cancel), func(t *testing.T) {
				m := newSAMPasswordViewModel(t)
				if cancel {
					m.cancelAt = phase
				} else {
					m.failAt = phase
				}
				view, err := readSAMPasswordAccount(m.ctx, m.account, m.operations())
				require.Nil(t, view)
				if cancel {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.ErrorIs(t, err, m.failure)
				}
				require.Equal(t, phase, m.calls[len(m.calls)-1], "failed observation must not run later metadata/policy operations")
			})
		}
	}
	for _, phase := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("drift-%d", phase), func(t *testing.T) {
			m := newSAMPasswordViewModel(t)
			m.changedAt = phase
			view, err := readSAMPasswordAccount(m.ctx, m.account, m.operations())
			require.Nil(t, view)
			require.ErrorIs(t, err, ErrPasswordAccountPolicyDenied)
		})
	}
}

func TestSAMPasswordAccountViewPreservesNativeGroupOrderForTemplates(t *testing.T) {
	m := newSAMPasswordViewModel(t)
	m.groups = []group{{Name: "second", SID: "S-1-5-32-546"}, {Name: "first", SID: "S-1-5-32-545"}}
	view, err := readSAMPasswordAccount(m.ctx, m.account, m.operations())
	require.NoError(t, err)
	groups, _, err := view.GetField("groups")
	require.NoError(t, err)
	require.Equal(t, m.groups, groups)
	m.groups[0], m.groups[1] = m.groups[1], m.groups[0]
	changed, err := readSAMPasswordAccount(m.ctx, m.account, m.operations())
	require.NoError(t, err)
	require.False(t, view.IsEqualTo(changed), "native order changes can affect indexed target templates and must not escape the final comparison")
}

func TestSAMPasswordAccountViewRejectsIncompleteInputsAndEmptyNativePaths(t *testing.T) {
	for _, scenario := range []string{"nil-context", "canceled", "missing-name", "missing-sid", "missing-ops", "empty-home", "empty-shell"} {
		t.Run(scenario, func(t *testing.T) {
			m := newSAMPasswordViewModel(t)
			ctx := m.ctx
			selected := m.account
			api := m.operations()
			switch scenario {
			case "nil-context":
				ctx = nil
			case "canceled":
				m.cancel()
			case "missing-name":
				selected.Name = ""
			case "missing-sid":
				selected.SID = ""
			case "missing-ops":
				api.groups = nil
			case "empty-home":
				api.homeDir = func() (string, error) { return "", nil }
			case "empty-shell":
				api.shell = func() (string, error) { return "", nil }
			}
			view, err := readSAMPasswordAccount(ctx, selected, api)
			require.Nil(t, view)
			require.Error(t, err)
		})
	}
}
