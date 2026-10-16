package session

import (
	"bytes"
	"context"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfSession "github.com/engity-com/bifroest/pkg/session"
)

type emptySessionRepository struct{ bfSession.Repository }

func (emptySessionRepository) FindAll(context.Context, bfSession.Consumer, *bfSession.FindOpts) error {
	return nil
}

func TestManagementSessionInvocationsKeepSeparateStreamsAndOptions(t *testing.T) {
	requirement := cli.NewSimpleApplication().WithName("bifroest").WithFallbackToStdio(false).WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewOptionalCliCodec())
	Register(requirement)
	app, err := requirement.Create()
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	for _, test := range []struct {
		args   []string
		expect string
	}{
		{[]string{"session", "ls", "--format=json"}, "[]"},
		{[]string{"session", "ls"}, "ID"},
		{[]string{"session", "ls", "--format=yaml"}, "[]"},
	} {
		var output, diagnostic bytes.Buffer
		ctx := common.ContextWithManagementAccess(context.Background(), common.ManagementAccess{Sessions: emptySessionRepository{}})
		ctx = cli.ContextWithStdio(ctx, nil, &output, &diagnostic)
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}, test.args...))
		require.Contains(t, output.String(), test.expect)
		require.Empty(t, diagnostic.String())
	}
	var output bytes.Buffer
	ctx := cli.ContextWithStdio(common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{Sessions: emptySessionRepository{}}), nil, &output, nil)
	require.Error(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}, "session", "ls", "-c", "private.yaml"))
	require.Empty(t, output.String())
}
