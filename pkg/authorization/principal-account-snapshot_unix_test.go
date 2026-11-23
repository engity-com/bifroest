//go:build unix

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestPrincipalMappingPreservesExplicitZeroUidAndRejectsMissingUnixGroups(t *testing.T) {
	uid := user.Id(0)
	groups := user.Groups{}
	facts := user.AccountFacts{Name: "explicit-zero", Uid: &uid, Groups: &groups}
	account, err := user.NewSnapshot(facts)
	require.NoError(t, err)
	auth := accountSnapshotTestAuthorization{identity: authentication.Identity{Principal: "explicit-zero", Issuer: "local", Subject: "0"}, account: account}
	flows := principalMappingTestFlows(`{{ if and (eq .authorization.user.uid 0) (eq (len .authorization.user.groups) 0) }}{{ .authorization.user.name }}{{ end }}`)
	contextFor := func(unmapped authentication.Identity) PrincipalMappingContext {
		return newPrincipalMappingTestContext(t, unmapped, auth)
	}
	identity, err := AuthenticationWithPrincipal(auth, flows, contextFor)
	require.NoError(t, err)
	require.Equal(t, auth.identity, identity)
	facts.Groups = nil
	auth.account, err = user.NewSnapshot(facts)
	require.NoError(t, err)
	identity, err = AuthenticationWithPrincipal(auth, flows, contextFor)
	require.ErrorIs(t, err, user.ErrAccountFieldUnavailable)
	require.Equal(t, authentication.Identity{}, identity)
}
