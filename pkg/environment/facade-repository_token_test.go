package environment

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

type facadeTokenTestSession struct {
	*sshTestStoredSession
	disposeCalls int
}

func (this *facadeTokenTestSession) Dispose(context.Context) (bool, error) {
	this.disposeCalls++
	return true, nil
}

func TestRepositoryFacadePreservesForeignEnvironmentTokens(t *testing.T) {
	for _, tc := range []struct {
		name    string
		repo    CloseableRepository
		token   string
		matches bool
	}{
		{name: "Unix local to dummy", repo: &DummyRepository{}, token: `{"version":2,"user":{"name":"alice","uid":1001,"killProcessesOnDispose":true},"portForwardingAllowed":true}`},
		{name: "Unix local to SSH", repo: &SshRepository{}, token: `{"version":2,"user":{"name":"alice","uid":1001,"killProcessesOnDispose":true},"portForwardingAllowed":true}`},
		{name: "Windows local to SSH", repo: &SshRepository{}, token: `{"version":2,"user":{"name":"alice","sid":"S-1-5-21-1-2-3-1001"},"portForwardingAllowed":false,"killProcessesOnDispose":true}`},
		{name: "SSH to local", repo: &LocalRepository{}, token: `{"schema":"bifroest.ssh-user-certificate/v1","state":"issued"}`},
		{name: "unknown to SSH", repo: &SshRepository{}, token: `{"schema":"unknown"}`},
		{name: "corrupt to SSH", repo: &SshRepository{}, token: `{broken`},
		{name: "Unix local version 2", repo: &LocalRepository{}, token: `{"version":2,"user":{"name":"alice","uid":1001},"portForwardingAllowed":true}`, matches: runtime.GOOS != "windows"},
		{name: "Windows local version 2", repo: &LocalRepository{}, token: `{"version":2,"user":{"name":"alice","sid":"S-1-5-21-1-2-3-1001"},"portForwardingAllowed":false}`, matches: runtime.GOOS == "windows"},
		{name: "incomplete local version 2", repo: &LocalRepository{}, token: `{"version":2,"user":{"name":"alice"},"portForwardingAllowed":true}`},
		{name: "unmarked local version 2", repo: &LocalRepository{}, token: `{"version":2,"user":{"name":"alice","uid":1001,"sid":"S-1-5-21-1-2-3-1001"}}`},
		{name: "foreign type marker", repo: &LocalRepository{}, token: `{"version":2,"user":{"name":"alice","uid":1001,"sid":"S-1-5-21-1-2-3-1001"},"portForwardingAllowed":true,"kind":"other"}`},
		{name: "unknown local version", repo: &LocalRepository{}, token: `{"version":3,"user":{"name":"alice","uid":1001,"sid":"S-1-5-21-1-2-3-1001"},"portForwardingAllowed":true}`},
		{name: "Unix local version 1", repo: &LocalRepository{}, token: `{"user":{"name":"alice","uid":1001},"portForwardingAllowed":true}`, matches: runtime.GOOS != "windows"},
		{name: "legacy Windows local", repo: &LocalRepository{}, token: `{"portForwardingAllowed":true}`, matches: runtime.GOOS == "windows"},
		{name: "SSH certificate", repo: &SshRepository{}, token: `{"schema":"bifroest.ssh-user-certificate/v1"}`, matches: true},
		{name: "dummy without token", repo: &DummyRepository{}, matches: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored := &facadeTokenTestSession{sshTestStoredSession: &sshTestStoredSession{id: session.MustNewId(), environmentToken: []byte(tc.token)}}
			facade := &RepositoryFacade{entries: map[configuration.FlowName]CloseableRepository{"test": tc.repo}}
			matches, err := facade.SessionEnvironmentMatches(t.Context(), stored)
			require.NoError(t, err)
			require.Equal(t, tc.matches, matches)
			if !tc.matches {
				_, err = facade.FindBySession(t.Context(), stored, &FindOpts{AutoCleanUpAllowed: common.P(true)})
				require.ErrorContains(t, err, "operator inspection required")
				_, err = facade.DisposeSession(t.Context(), stored)
				require.ErrorContains(t, err, "operator inspection required")
				require.Zero(t, stored.disposeCalls)
				require.Zero(t, stored.environmentTokenWrites.Load())
				raw, err := stored.EnvironmentToken(t.Context())
				require.NoError(t, err)
				require.Equal(t, []byte(tc.token), raw)
			}
		})
	}
}
