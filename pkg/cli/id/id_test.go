package id

import (
	"bytes"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/stretchr/testify/require"
)

func TestIDConversionAliasAndAtomicValidation(t *testing.T) {
	app, err := cli.NewApplication[cli.NoOptions]().WithName("bifroest").WithFallbackToStdio(false).WithErrorHandlerEnabled(false).WithCommand(CreateCommands()...).Create()
	require.NoError(t, err)
	defer app.Close()
	for _, command := range []string{"convert", "parse"} {
		var output, diagnostic bytes.Buffer
		ctx := cli.ContextWithStdio(t.Context(), nil, &output, &diagnostic)
		err := app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, "id", command, "00000000-0000-0000-0000-000000000000", "1111111111111111")
		require.NoError(t, err)
		require.Equal(t, "00000000-0000-0000-0000-000000000000,1111111111111111\n00000000-0000-0000-0000-000000000000,1111111111111111\n", output.String())
		output.Reset()
		err = app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, "id", command, "1111111111111111", "not-a-uuid")
		require.Error(t, err)
		require.Empty(t, output.String())
	}
}
