//go:build unix

package authorization

import (
	"fmt"
	"testing"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

type localManagedTestContext struct {
	auth      *local
	managed   bool
	available bool
}

func (*localManagedTestContext) Context() essh.Context { return nil }

func (this *localManagedTestContext) GetField(name string) (any, bool, error) {
	if name == "authorization" {
		return this.auth, true, nil
	}
	return nil, false, fmt.Errorf("unknown field %q", name)
}

func (this *localManagedTestContext) ResolveLocalUserManaged(flow configuration.FlowName, account *user.User) (bool, bool, error) {
	if flow != this.auth.flow || account != this.auth.user {
		return false, false, fmt.Errorf("wrong flow or account")
	}
	return this.managed, this.available, nil
}

func TestLocalAuthorizationUserManagedFromCurrentFlow(t *testing.T) {
	account := &user.User{Name: "alice", Uid: 1234}
	ctx := &localManagedTestContext{auth: &local{user: account, flow: "local"}, available: true}
	for _, managed := range []bool{false, true} {
		ctx.managed = managed
		actual, err := template.MustNewBool("{{ .authorization.user.managed }}").Render(ctx)
		require.NoError(t, err)
		require.Equal(t, managed, actual)
	}
	ctx.available = false
	actual, err := template.MustNewString("{{ if .authorization.user.managed }}true{{ else }}null{{ end }}").Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "null", actual)
}
