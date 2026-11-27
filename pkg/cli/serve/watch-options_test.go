package serve

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestWatchConfigurationIsExplicitForServeAndRunAndAbsentFromOtherProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configuration.yaml")
	require.NoError(t, os.WriteFile(path, []byte("flows:\n  - name: work\n    authorization: {type: none}\n    environment: {type: dummy}\n"), 0600))
	var observed []configuration.WatchMode
	app := cli.NewApplication[cli.NoOptions]("bifroest", "").WithFallbackToStdio(false).WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithCommand(CreateCommands(nil, func(ctx context.Context, conf configuration.Configuration, _ sys.Version) error {
			require.Equal(t, path, conf.Filename)
			observed = append(observed, common.ServiceRunOptionsFromContext(ctx).Watch)
			return nil
		})...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	for _, command := range []string{"serve", "run"} {
		for _, flags := range [][]string{nil, {"--watch"}, {"--watch=true"}, {"--watch=preserve"}, {"--watch=reconnect"}, {"--watch=reuse"}, {"--watch=off"}, {"--watch=false"}, {"--watch=no"}, {"--watch=0"}} {
			args := append([]string{command, "--configuration=" + path}, flags...)
			require.NoError(t, app.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...))
		}
		var output bytes.Buffer
		ctx := cli.ContextWithStdio(t.Context(), nil, &output, &output)
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, command, "--help"))
		require.Contains(t, output.String(), "--watch")
		require.Contains(t, output.String(), "reconnect")
		require.Contains(t, output.String(), "reuse")
		require.NotContains(t, output.String(), "--watch-config")
		require.Error(t, app.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, command, "--configuration="+path, "--watch=unknown"))
		require.Error(t, app.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, command, "--configuration="+path, "--watch-config"))
		for _, profile := range []string{common.ProfileRemote, common.ProfileManagement} {
			require.Error(t, app.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: []string{profile}}, command, "--configuration="+path, "--watch"))
		}
	}
	one := []configuration.WatchMode{configuration.WatchModeOff, configuration.WatchModePreserve, configuration.WatchModePreserve, configuration.WatchModePreserve, configuration.WatchModeReconnect, configuration.WatchModeReuse, configuration.WatchModeOff, configuration.WatchModeOff, configuration.WatchModeOff, configuration.WatchModeOff}
	require.Equal(t, append(one, one...), observed)
}
