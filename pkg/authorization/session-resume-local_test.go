//go:build unix || windows

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
)

func TestLocalSessionResumeCannotReplaceNativePasswordAccountPolicyWithLookup(t *testing.T) {
	_, req, _ := newSimpleResumeFixture(t)
	local := &LocalAuthorizer{flow: req.sess.Flow()}
	for _, method := range []string{"password", "keyboard-interactive"} {
		req.credential = authentication.SessionCredential{Kind: "local", Method: method}
		auth, err := local.ResumeSession(req)
		require.Nil(t, auth)
		require.ErrorIs(t, err, ErrSessionResumeUnavailable, "must reject before restoring a snapshot or touching native account APIs")
	}
}
