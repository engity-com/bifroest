package authorization

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

// An explicitly assumed verified authentication result, not a native login or
// an account-policy implementation. The user's fields come from the shared
// account view; the principal is evaluated by AuthenticationWithPrincipal.
type accountSnapshotTestAuthorization struct {
	Authorization
	identity authentication.Identity
	account  any
}

func (accountSnapshotTestAuthorization) IsAuthorized() bool           { return true }
func (accountSnapshotTestAuthorization) Flow() configuration.FlowName { return "flow" }
func (this accountSnapshotTestAuthorization) Authentication() (authentication.Identity, error) {
	return this.identity, nil
}
func (this accountSnapshotTestAuthorization) GetField(name string, _ ContextEnabled) (any, bool, error) {
	if name == "user" {
		return this.account, true, nil
	}
	return nil, false, fmt.Errorf("unavailable assumed authorization field")
}

func TestPrincipalMappingUsesWindowsSnapshotWithoutNativeAccountAccess(t *testing.T) {
	home := `C:\Fixture\Home`
	groups := []windowslocal.AccountGroupFacts{{Name: "operators", SID: "S-1-5-32-545"}}
	facts := windowslocal.AccountFacts{Identity: windowslocal.Account{Name: "synthetic", SID: "S-1-5-21-1-2-3-1001"}, HomeDir: &home, Groups: &groups}
	account, err := windowslocal.NewAccountSnapshot(facts)
	require.NoError(t, err)
	auth := accountSnapshotTestAuthorization{identity: authentication.Identity{Principal: "synthetic", Issuer: "local", Subject: facts.Identity.SID}, account: account}
	flows := principalMappingTestFlows(`{{ if eq .authorization.user.homeDir "C:\\Fixture\\Home" }}{{ .authorization.user.name }}:{{ index .authorization.user.gids 0 }}{{ end }}`)
	contextFor := func(unmapped authentication.Identity) PrincipalMappingContext {
		return principalEvaluationTestContext{principalMappingTestContext: newPrincipalMappingTestContext(t, unmapped, auth), evaluation: template.NewEvaluation(template.EvaluationSources{})}
	}
	identity, err := AuthenticationWithPrincipal(auth, flows, contextFor)
	require.NoError(t, err)
	require.Equal(t, "synthetic:S-1-5-32-545", identity.Principal)
	require.Equal(t, auth.identity.Subject, identity.Subject)
	require.Equal(t, auth.identity.Issuer, identity.Issuer)
	facts.HomeDir = nil
	auth.account, err = windowslocal.NewAccountSnapshot(facts)
	require.NoError(t, err)
	identity, err = AuthenticationWithPrincipal(auth, flows, contextFor)
	require.ErrorIs(t, err, windowslocal.ErrAccountFieldUnavailable)
	require.Equal(t, authentication.Identity{}, identity)
}
