//go:build windows

package authorization

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

type localPrincipalMappingTestContext struct {
	*principalMappingTestContext
	managed bool
	err     error
	calls   int
}

func (this *localPrincipalMappingTestContext) ResolveLocalWindowsUserManaged(configuration.FlowName, windowslocal.Account) (bool, bool, error) {
	this.calls++
	return this.managed, true, this.err
}

func TestAuthenticationWithPrincipalPreservesLocalContextCapabilities(t *testing.T) {
	lookupErr := errors.New("modeled group information unavailable")
	for _, test := range []struct {
		name      string
		managed   bool
		err       error
		principal string
	}{
		{name: "managed", managed: true, principal: "managed-alice"},
		{name: "unmanaged", principal: "unmanaged-alice"},
		{name: "lookup error", err: lookupErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := &local{flow: "flow", user: windowslocal.Account{Name: "alice", SID: "S-1-5-21-100-200-300-1001"}}
			original, err := AuthenticationOf(auth)
			require.NoError(t, err)
			ctx := &localPrincipalMappingTestContext{principalMappingTestContext: newPrincipalMappingTestContext(t, original, auth), managed: test.managed, err: test.err}
			identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(`{{ if .authorization.user.managed }}managed{{ else }}unmanaged{{ end }}-{{ .authentication.principal }}`), func(unmapped authentication.Identity) PrincipalMappingContext {
				require.Equal(t, original, unmapped)
				return ctx
			})
			require.Equal(t, 1, ctx.calls, "the concrete context's resolver must remain reachable")
			if test.err != nil {
				require.ErrorIs(t, err, test.err)
				require.Equal(t, authentication.Identity{}, identity)
			} else {
				require.NoError(t, err)
				require.Equal(t, authentication.Identity{Principal: test.principal, Issuer: "local", Subject: auth.user.SID}, identity)
			}
		})
	}
}
