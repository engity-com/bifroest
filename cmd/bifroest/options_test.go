package main

import (
	"bytes"
	"testing"

	clibase "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/cli/common"
)

func TestExecutableSSHConfigFlagIsRemoteOnlyAndHelpDoesNotReadIt(t *testing.T) {
	app := cli.NewApplication[opts](versionV, "", nil).MustCreate()
	defer app.Close()
	var output bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &output, nil)
	require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileRemote}},
		"--sshConfig=missing.conf", "flow", "ls", "--help"))
	require.Contains(t, output.String(), "--sshConfig")
	require.Contains(t, output.String(), "-F")
	output.Reset()
	require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, "flow", "ls", "--help"))
	require.NotContains(t, output.String(), "--sshConfig")
	require.NotContains(t, output.String(), "-F")
}
