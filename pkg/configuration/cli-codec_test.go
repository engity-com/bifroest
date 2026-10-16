package configuration_test

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
)

type configurationCodecOptions struct {
	Configuration *configuration.Configuration `flag:"configuration" profile:"executable|remote|management|other"`
}

func TestConfigurationCodecOptionalAndInvocationOwned(t *testing.T) {
	path := writeCodecConfiguration(t)
	var resolved []*configuration.Configuration
	app := cli.NewApplication[configurationCodecOptions]("test").
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithErrorHandlerEnabled(false).
		WithFallbackToStdio(false).
		WithHandler(func(_ context.Context, options configurationCodecOptions) error {
			resolved = append(resolved, options.Configuration)
			return nil
		}).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })

	executable := &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}
	require.NoError(t, app.ParseAndExecute(t.Context(), executable))
	require.Nil(t, resolved[0])
	for range 2 {
		require.NoError(t, app.ParseAndExecute(t.Context(), executable, "--configuration="+path))
	}
	require.NotSame(t, resolved[1], resolved[2])
	require.Equal(t, path, resolved[1].Filename)
	resolved[1].Flows[0].Name = "changed"
	require.Equal(t, configuration.FlowName("test"), resolved[2].Flows[0].Name)

	require.NoError(t, os.Remove(path))
	var help bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &help, nil)
	require.NoError(t, app.ParseAndExecute(ctx, executable, "--configuration="+path, "--help"))
	require.NotEmpty(t, help.String())
	require.ErrorContains(t, app.ParseAndExecute(t.Context(), executable, "--configuration="+path), "cannot load configuration")
	require.ErrorContains(t, app.ParseAndExecute(t.Context(), executable, "--configuration="), "configuration path must not be empty")
	require.Len(t, resolved, 3)
}

func TestConfigurationCodecRequiredAndDefault(t *testing.T) {
	path := writeCodecConfiguration(t)
	type requiredOptions struct {
		Configuration *configuration.Configuration `flag:"configuration" required:"true" profile:"executable"`
	}
	var resolved *configuration.Configuration
	required := cli.NewApplication[requiredOptions]("test").
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithErrorHandlerEnabled(false).
		WithHandler(func(_ context.Context, options requiredOptions) error {
			resolved = options.Configuration
			return nil
		}).MustCreate()
	t.Cleanup(func() { require.NoError(t, required.Close()) })
	executable := &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}
	require.Error(t, required.ParseAndExecute(t.Context(), executable))
	require.Nil(t, resolved)
	require.NoError(t, required.ParseAndExecute(t.Context(), executable, "--configuration="+path))
	require.Equal(t, path, resolved.Filename)

	type defaultOptions struct {
		Configuration *configuration.Configuration `flag:"configuration" default:"configuration.yaml" profile:"executable"`
	}
	t.Chdir(filepath.Dir(path))
	withDefault := cli.NewApplication[defaultOptions]("test").
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithErrorHandlerEnabled(false).
		WithHandler(func(_ context.Context, options defaultOptions) error {
			resolved = options.Configuration
			return nil
		}).MustCreate()
	t.Cleanup(func() { require.NoError(t, withDefault.Close()) })
	require.NoError(t, withDefault.ParseAndExecute(t.Context(), executable))
	require.Equal(t, "configuration.yaml", resolved.Filename)
	require.Equal(t, configuration.FlowName("test"), resolved.Flows[0].Name)
}

func TestConfigurationCodecRejectsNonExecutableProfilesBeforeOpeningFiles(t *testing.T) {
	decoder := configuration.NewCliCodec(common.ProfileExecutable)
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	_, err := decoder.Resolve(t.Context(), nil, path)
	require.ErrorContains(t, err, "configuration files require the executable profile exclusively")
	type unprofiledOptions struct {
		Configuration *configuration.Configuration `flag:"configuration"`
	}
	unprofiled := cli.NewApplication[unprofiledOptions]("test").
		WithCodec(decoder).
		WithErrorHandlerEnabled(false).
		MustCreate()
	t.Cleanup(func() { require.NoError(t, unprofiled.Close()) })
	require.ErrorContains(t, unprofiled.ParseAndExecute(t.Context(), nil, "--configuration="+path),
		"configuration files require the executable profile exclusively")

	app := cli.NewApplication[configurationCodecOptions]("test").
		WithCodec(decoder).
		WithErrorHandlerEnabled(false).
		MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	for _, profiles := range [][]string{
		{common.ProfileManagement},
		{common.ProfileRemote},
		{"other"},
		{common.ProfileExecutable, common.ProfileManagement},
		{common.ProfileExecutable, common.ProfileRemote},
		{common.ProfileExecutable, "other"},
	} {
		err := app.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: profiles}, "--configuration="+path)
		require.ErrorContains(t, err, "configuration files require the executable profile exclusively")
	}
}

func writeCodecConfiguration(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "configuration.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`flows:
  - name: test
    authorization:
      type: none
    environment:
      type: dummy
`), 0600))
	return path
}
