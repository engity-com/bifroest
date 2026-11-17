//go:build windows

package serve

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestExplicitWindowsServiceModeDoesNotDependOnParentHeuristics(t *testing.T) {
	active, err := windowsServiceMode(true, func() (bool, error) {
		t.Fatal("explicit SCM startup must not call the unreliable parent detector")
		return false, nil
	})
	require.NoError(t, err)
	require.True(t, active)
	for _, detected := range []bool{false, true} {
		active, err := windowsServiceMode(false, func() (bool, error) { return detected, nil })
		require.NoError(t, err)
		require.Equal(t, detected, active, "implicit startup keeps its existing detection semantics")
	}
	failure := errors.New("cannot inspect parent")
	_, err = windowsServiceMode(false, func() (bool, error) { return false, failure })
	require.ErrorIs(t, err, failure)
}

func TestRealWindowsServiceOptionsAcceptInternalStartupWithoutRunning(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "configuration.yaml")
	raw, err := yaml.Marshal(map[string]any{
		"session": map[string]string{"type": "fs", "storage": filepath.Join(root, "sessions")},
		"flows":   []map[string]any{{"name": "fixture", "authorization": map[string]string{"type": "none"}, "environment": map[string]string{"type": "dummy"}}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(config, raw, 0600))
	app := cli.NewApplication[cli.NoOptions]("bifroest", "").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithCommand(CreateCommands(nil, nil)...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	for _, name := range []string{"serve", "run"} {
		command, found := cli.FindCommandOfProfile[*opts](app, common.ProfileExecutable, name)
		require.True(t, found)
		var output bytes.Buffer
		ctx := cli.ContextWithStdio(t.Context(), nil, &output, &output)
		invocation, err := app.Parse(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, name, "--configuration="+config, "--internal.windowsService")
		require.NoError(t, err)
		flag, value := invocation.Flag("internal.windowsService")
		require.NotNil(t, flag)
		require.False(t, flag.IsVisible())
		require.Equal(t, true, value)
		parsed, found := command.OptionsFrom(invocation)
		require.True(t, found)
		require.True(t, parsed.WindowsService)
		require.NoError(t, invocation.Close())
		_, err = app.Parse(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, name, "--configuration="+config, "--windowsService")
		require.Error(t, err)
	}
}
