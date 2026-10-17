//go:build embedded_dlv

package dlv

import (
	"context"
	"fmt"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/debug"
)

type testLoggingOptions struct {
	LogLevel     string `flag:"log.level"`
	LogColorMode string `flag:"log.colorMode"`
}

func TestDlvForwardsPositionalTargetArguments(t *testing.T) {
	commands := CreateCommands()
	require.Len(t, commands, 1)
	command, ok := commands[0].(*cli.CommandRequirement[opts])
	require.True(t, ok)
	var received []opts
	var logging testLoggingOptions
	// Exercise the actual command factory and codecs without launching a debugger.
	command.WithHandler(func(_ context.Context, options opts) error {
		received = append(received, options)
		return nil
	})
	app := cli.NewApplication[testLoggingOptions]().
		WithName("test").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithInitializeHandler(func(_ context.Context, options testLoggingOptions) error {
			logging = options
			return nil
		}).
		WithCommand(commands...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	defaultAddr := fmt.Sprintf(":%d", debug.DlvPort)
	for _, test := range []struct {
		name    string
		args    []string
		want    opts
		logging testLoggingOptions
	}{
		{"kubernetes-imp", []string{"dlv", "--log.colorMode=always", "--log.level=DEBUG", "--", "imp", "--log.colorMode=always", "--log.level=DEBUG"},
			opts{Addr: defaultAddr, Args: []string{"imp", "--log.colorMode=always", "--log.level=DEBUG"}},
			testLoggingOptions{LogLevel: "DEBUG", LogColorMode: "always"}},
		{"kubernetes-imp-wait", []string{"dlv", "--wait", "--log.colorMode=always", "--log.level=DEBUG", "--", "imp", "--log.colorMode=always", "--log.level=DEBUG"},
			opts{Addr: defaultAddr, Wait: true, Args: []string{"imp", "--log.colorMode=always", "--log.level=DEBUG"}},
			testLoggingOptions{LogLevel: "DEBUG", LogColorMode: "always"}},
		{"target-flags-and-spaces", []string{"dlv", "--addr=127.0.0.1:0", "--wait", "--log.level=INFO", "--", "imp", "--addr=target-address", "--wait=false", "--log.level=target-level", "argument with spaces", "--"},
			opts{Addr: "127.0.0.1:0", Wait: true, Args: []string{"imp", "--addr=target-address", "--wait=false", "--log.level=target-level", "argument with spaces", "--"}},
			testLoggingOptions{LogLevel: "INFO"}},
		{"reset-options", []string{"dlv", "--", "version"}, opts{Addr: defaultAddr, Args: []string{"version"}}, testLoggingOptions{}},
		{"optional-target", []string{"dlv"}, opts{Addr: defaultAddr}, testLoggingOptions{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := len(received)
			require.NoError(t, app.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, test.args...))
			require.Len(t, received, before+1)
			require.Equal(t, test.want, received[before])
			require.Equal(t, test.logging, logging)
		})
	}
	for _, profile := range []string{common.ProfileRemote, common.ProfileManagement} {
		before := len(received)
		require.Error(t, app.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: []string{profile}}, "dlv", "--", "imp"))
		require.Len(t, received, before)
	}
}
