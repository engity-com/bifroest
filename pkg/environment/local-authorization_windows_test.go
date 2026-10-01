//go:build windows

package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
)

type localAuthorizationIdentityTest struct {
	authorization.Authorization
	name, sid string
}

func (this localAuthorizationIdentityTest) LocalWindowsIdentity() (string, string) {
	return this.name, this.sid
}

func TestLocalWindowsAuthorizationAccountReplacement(t *testing.T) {
	auth := localAuthorizationIdentityTest{name: "alice", sid: "S-1-5-21-1-2-3-1001"}
	require.True(t, localWindowsAuthorizationMatches(auth, "ALICE", auth.sid))
	require.False(t, localWindowsAuthorizationMatches(auth, "alice", "S-1-5-21-1-2-3-1002"))
	require.False(t, localWindowsAuthorizationMatches(auth, "alice", ""))
	// An explicitly mapped account with a different name remains possible.
	require.True(t, localWindowsAuthorizationMatches(auth, "bob", "S-1-5-21-1-2-3-1002"))
	require.True(t, localWindowsAuthorizationMatches(nil, "alice", "S-1-5-21-1-2-3-1002"))
}
