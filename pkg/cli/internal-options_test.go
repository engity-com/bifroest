package cli

import (
	"bytes"
	"runtime"
	"testing"

	clibase "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func TestInternalWindowsServiceFlagIsPlatformBoundAndAbsentFromHelp(t *testing.T) {
	app := NewApplication[clibase.NoOptions](nil, "", nil).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	for _, name := range []string{"serve", "run"} {
		command, found := app.CommandOfProfile(name, common.ProfileExecutable)
		require.True(t, found)
		flag, found := command.Flag("internal.windowsService")
		require.Equal(t, runtime.GOOS == "windows", found)
		if found {
			require.Equal(t, "internal.windowsService", flag.Name())
			require.False(t, flag.IsVisible())
		}
		_, found = command.Flag("windowsService")
		require.False(t, found)
		var output bytes.Buffer
		ctx := clibase.ContextWithStdio(t.Context(), nil, &output, &output)
		require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, name, "--help"))
		require.Contains(t, output.String(), "--configuration")
		require.NotContains(t, output.String(), "windowsService")
	}
}
