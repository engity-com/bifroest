package cli

import (
	"bytes"
	"context"
	"testing"

	clibase "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
)

func TestBuildsSeparateReusableApplications(t *testing.T) {
	apps, err := NewApplications(nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, apps.Close()) }()
	type executor interface {
		ParseAndExecute(context.Context, *clibase.ParseOpts, ...string) error
	}
	for _, application := range []struct {
		app  executor
		args []string
	}{
		{apps.Executable, []string{"key", "--help"}},
		{apps.Management, []string{"audit", "--help"}},
		{apps.Management, []string{"session", "--help"}},
	} {
		var output, diagnostic bytes.Buffer
		ctx := clibase.ContextWithStdio(t.Context(), nil, &output, &diagnostic)
		require.NoError(t, application.app.ParseAndExecute(ctx, nil, application.args...))
		require.NotEmpty(t, output.String()+diagnostic.String())
	}
	var output bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &output, nil)
	require.Error(t, apps.Management.ParseAndExecute(ctx, nil, "key", "generate"))
}
