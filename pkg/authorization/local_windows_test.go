//go:build windows

package authorization

import (
	"context"
	"fmt"
	"testing"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

type windowsLocalManagedContext struct {
	auth    *local
	managed bool
	bound   bool
}

func (*windowsLocalManagedContext) Context() essh.Context { return nil }

func (this *windowsLocalManagedContext) GetField(name string) (any, bool, error) {
	if name == "authorization" {
		return this.auth, true, nil
	}
	return nil, false, fmt.Errorf("unknown field %q", name)
}

func (this *windowsLocalManagedContext) ResolveLocalWindowsUserManaged(flow configuration.FlowName, account windowslocal.Account) (bool, bool, error) {
	if flow != this.auth.flow || account != this.auth.user {
		return false, false, fmt.Errorf("wrong flow or account")
	}
	return this.managed, this.bound, nil
}

func TestWindowsLocalUserManagedContext(t *testing.T) {
	ctx := &windowsLocalManagedContext{auth: &local{user: windowslocal.Account{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}, flow: "flow"}, bound: true}
	for _, managed := range []bool{false, true} {
		ctx.managed = managed
		value, err := template.MustNewBool("{{ .authorization.user.managed }}").Render(ctx)
		require.NoError(t, err)
		require.Equal(t, managed, value)
	}
	ctx.bound = false
	value, err := template.MustNewString("{{ if .authorization.user.managed }}true{{ else }}null{{ end }}").Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "null", value)
}

func TestWindowsLocalSessionMatchesAccountSID(t *testing.T) {
	u := windowslocal.Account{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}
	for _, tc := range []struct {
		name  string
		token string
		match bool
	}{
		{"matching", `{"user":{"name":"Alice","sid":"S-1-5-21-1-2-3-1001"}}`, true},
		{"recreated account", `{"user":{"name":"alice","sid":"S-1-5-21-1-2-3-1002"}}`, false},
		{"other account", `{"user":{"name":"bob","sid":"S-1-5-21-1-2-3-1001"}}`, false},
		{"missing SID", `{"user":{"name":"alice"}}`, false},
		{"invalid", `not-json`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			match, err := localSessionMatches(context.Background(), &authorizationRestoreTestSession{token: []byte(tc.token)}, u)
			require.NoError(t, err)
			require.Equal(t, tc.match, match)
		})
	}
}

func TestWindowsLocalRestoreInvalidToken(t *testing.T) {
	authorizer := &LocalAuthorizer{flow: configuration.FlowName("flow")}
	for _, token := range []string{`not-json`, `{"user":{"name":"alice"}}`, `{"user":{"name":"alice","sid":"invalid"}}`} {
		sess := &authorizationRestoreTestSession{flow: "flow", token: []byte(token)}
		_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{})
		require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
		allow := true
		_, err = authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{AutoCleanUpAllowed: &allow})
		require.ErrorIs(t, err, ErrNoSuchAuthorization)
		require.Empty(t, sess.token)
	}
}
