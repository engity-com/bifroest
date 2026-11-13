package serve

import (
	"bytes"
	"context"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
)

type internalOptionsTestOpts struct {
	internalOptions
	Public bool `flag:"public" description:"Public test option."`
}

func TestInternalWindowsServiceFlagIsParsedButHidden(t *testing.T) {
	var modes []bool
	app := cli.NewApplication[cli.NoOptions]("bifroest", "").WithFallbackToStdio(false).WithErrorHandlerEnabled(false).WithCommand(
		cli.NewCommand[*internalOptionsTestOpts]("serve", "Runs the service.").
			WithAliases("run").
			WithHandler(func(_ context.Context, opts *internalOptionsTestOpts) error {
				modes = append(modes, opts.WindowsService)
				return nil
			}),
	).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	command, found := app.Command("serve")
	require.True(t, found)
	flag, found := command.Flag("internal.windowsService")
	require.True(t, found)
	require.False(t, flag.IsVisible())
	require.Equal(t, []string{"internal.windowsService"}, flag.Names())
	_, found = command.Flag("windowsService")
	require.False(t, found)
	for _, name := range []string{"serve", "run"} {
		var output bytes.Buffer
		ctx := cli.ContextWithStdio(t.Context(), nil, &output, &output)
		require.NoError(t, app.ParseAndExecute(ctx, nil, name, "--help"))
		require.Contains(t, output.String(), "--public")
		require.NotContains(t, output.String(), "windowsService")
		require.Empty(t, modes, "help must never enter a service runner")
	}
	for _, name := range []string{"serve", "run"} {
		for _, flags := range [][]string{nil, {"--internal.windowsService"}, {"--internal.windowsService=false"}} {
			require.NoError(t, app.ParseAndExecute(t.Context(), nil, append([]string{name}, flags...)...))
		}
	}
	require.Equal(t, []bool{false, true, false, false, true, false}, modes)
	require.Error(t, app.ParseAndExecute(t.Context(), nil, "serve", "--internal.windowsService=invalid"))
	require.Error(t, app.ParseAndExecute(t.Context(), nil, "serve", "--windowsService"))
	require.Len(t, modes, 6, "invalid or removed flags must never enter a service runner")
}
