package recording

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func TestRecordingCLIReusesSchemaAndKeepsSensitiveOutputGated(t *testing.T) {
	fixture := createRecordingFixture(t)
	requirement := cli.NewSimpleApplication().WithName("bifroest").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false)
	Register(t.Context(), requirement, common.UsageExecutable)
	app, err := requirement.Create()
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	invoke := func(args ...string) (string, error) {
		var output bytes.Buffer
		ctx := cli.ContextWithStdio(context.Background(), nil, &output, nil)
		err := app.ParseAndExecute(ctx, nil, args...)
		return output.String(), err
	}
	trust := "--expectedProducerId=" + fixture.identity.ProducerId().String()
	clear := fixture.clear
	encrypted := fixture.encrypted
	output, err := invoke("recording", "export", trust, clear)
	require.ErrorContains(t, err, "--with-sensitive")
	require.Empty(t, output)
	output, err = invoke("recording", "verify", trust, clear, "--format=json")
	require.NoError(t, err)
	require.Contains(t, output, `"scope":"full"`)
	output, err = invoke("recording", "export", trust, "--with-sensitive", clear)
	require.NoError(t, err)
	require.Contains(t, output, "sensitive terminal output")
	output, err = invoke("recording", "export", trust, "--with-sensitive", "--decryptionIdentityFile="+fixture.identityFile, encrypted)
	require.NoError(t, err)
	require.Contains(t, output, "sensitive terminal output")
	output, err = invoke("recording", "play", trust, "--with-sensitive", "--speed=100", clear)
	require.NoError(t, err)
	require.Contains(t, output, "sensitive terminal output")
	output, err = invoke("recording", "inspect", trust, clear)
	require.NoError(t, err)
	require.True(t, strings.Contains(output, `"verificationScope":"full"`))
}

func TestRecordingCLIRejectsUntrustedAndUnsafeOutput(t *testing.T) {
	fixture := createRecordingFixture(t)
	var output bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
	require.ErrorContains(t, doRecordingExport(t.Context(), &recordingExportOpts{file: fixture.clear, output: "-", withSensitive: true}, &output), "--expectedProducerId")
	require.Empty(t, output.String())
	require.ErrorContains(t, doRecordingExport(t.Context(), &recordingExportOpts{
		file: fixture.encrypted, output: fixture.identityFile, force: true, withSensitive: true,
		expectedProducerId: fixture.identity.ProducerId().String(), decryptionIdentityFiles: []string{fixture.identityFile},
	}, cli.StdoutOfContext(ctx)), "must not replace private key")
}
