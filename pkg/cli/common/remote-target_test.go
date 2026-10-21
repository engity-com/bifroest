package common

import (
	"bytes"
	"context"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management"
)

func TestRemoteSSHConfigurationIsInvocationBound(t *testing.T) {
	var received management.Target
	app := cli.NewApplication[SSHConfigOpts]("test").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCommand(cli.NewSimpleCommand("target").WithProfiles(ProfileRemote).
			WithHandler(func(ctx context.Context, _ cli.NoOptions) error {
				var err error
				received, err = RemoteTargetFromContext(ctx)
				return err
			})).
		WithCommand(cli.NewSimpleCommand("local").WithProfiles(ProfileExecutable)).
		MustCreate()
	defer app.Close()
	base := management.Target{Host: "alias", User: "admin", Port: 2222, ExplicitPort: true}
	for _, test := range []struct {
		args []string
		path string
	}{
		{[]string{"--sshConfig=first.conf", "target"}, "first.conf"},
		{[]string{"target", "-F", "second.conf"}, "second.conf"},
		{[]string{"target"}, ""},
	} {
		ctx := ContextWithRemoteTarget(t.Context(), base)
		ctx = cli.ContextWithStdio(ctx, nil, &bytes.Buffer{}, nil)
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{ProfileRemote}}, test.args...))
		want := base
		want.SSHConfigFile = test.path
		require.Equal(t, want, received)
		original, err := RemoteTargetFromContext(ctx)
		require.NoError(t, err)
		require.Equal(t, base, original, "reading the resolved target must not mutate the supplied context")
	}
	ctx := cli.ContextWithStdio(t.Context(), nil, &bytes.Buffer{}, nil)
	require.Error(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{ProfileExecutable}}, "local", "-F", "local.conf"))
	ctx = ContextWithRemoteTarget(ctx, base)
	require.ErrorContains(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{ProfileRemote}}, "target", "--sshConfig="), "must not be empty")
}
