//go:build linux

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestLocalRemoteNamePasswordAndInteractiveUseMappedNativeLookup(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive"} {
		t.Run(method, func(t *testing.T) {
			auth, repo := mappedUnixAuthorizer(t)
			base := newFacadeSelectionRequest(t, "alice@node-a")
			base.password = "correct"
			var result Authorization
			var err error
			if method == "password" {
				result, err = auth.AuthorizePassword(base)
			} else {
				result, err = auth.AuthorizeInteractive(base)
			}
			require.NoError(t, err)
			require.True(t, result.IsAuthorized())
			require.Equal(t, "alice@node-a", result.Remote().User())
			require.Equal(t, []string{"alice"}, repo.passwordNames)
			require.Equal(t, []string{"alice"}, repo.lookups)
			identity, err := AuthenticationOf(result)
			require.NoError(t, err)
			require.Equal(t, "alice", identity.Principal)
			require.Equal(t, "1001", identity.Subject)
			base.password = "wrong"
			denied, err := auth.AuthorizePassword(base)
			require.NoError(t, err)
			require.False(t, denied.IsAuthorized())
			require.Equal(t, 1, sessionCount(t, base.repository))
		})
	}
}

func TestLocalRemoteNamePasswordResumeKeepsFreshNativeChecksAndNeverReplaysPassword(t *testing.T) {
	auth, repo := mappedUnixAuthorizer(t)
	base := newFacadeSelectionRequest(t, "alice@node-a")
	base.password = "correct"
	initial, err := auth.AuthorizePassword(base)
	require.NoError(t, err)
	identity, err := AuthenticationOf(initial)
	require.NoError(t, err)
	req := &resumeTestRequest{Request: base, sess: initial.FindSession(), identity: identity, credential: authentication.SessionCredential{Kind: "local", Method: "password"}, verified: true, selection: connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "Work"}}
	base.password = "DO-NOT-REPLAY"
	before := len(repo.passwordNames)
	resumed, err := auth.ResumeSession(req)
	require.NoError(t, err)
	require.Equal(t, initial.FindSession().Id(), resumed.FindSession().Id())
	require.Equal(t, 2, repo.policyCalls)
	require.Len(t, repo.passwordNames, before)
	require.Zero(t, base.prompts)
	auth.conf.RemoteName = configuration.DefaultAuthorizationRemoteName
	_, err = auth.ResumeSession(req)
	require.ErrorIs(t, err, ErrSessionResumeDenied, "removing mapping cannot bypass current account selection")
	auth.conf.RemoteName = template.MustNewString(stripRemoteSuffix)
	repo.denyPolicy = true
	_, err = auth.ResumeSession(req)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	repo.denyPolicy = false
	auth.conf.RemoteName = template.MustNewString("bob")
	repo.policyCalls = 0
	_, err = auth.ResumeSession(req)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	require.Zero(t, repo.policyCalls)
	require.Len(t, repo.passwordNames, before)
	require.Equal(t, 1, sessionCount(t, base.repository))
}
