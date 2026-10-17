package recording

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestRecordingCLIReusesSchemaAndKeepsSensitiveOutputGated(t *testing.T) {
	fixture := createRecordingFixture(t)
	requirement := cli.NewSimpleApplication().WithName("bifroest").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable))
	requirement.WithCommand(CreateCommands()...)
	app, err := requirement.Create()
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	invoke := func(args ...string) (string, error) {
		var output bytes.Buffer
		ctx := cli.ContextWithStdio(context.Background(), nil, &output, nil)
		err := app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...)
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
	require.ErrorContains(t, doRecordingExport(t.Context(), exportCommandOptions{
		recordingContentOptions: recordingContentOptions{File: fixture.clear, WithSensitiveOpts: common.WithSensitiveOpts{WithSensitive: true}},
		Output:                  "-",
	}, &output), "--expectedProducerId")
	require.Empty(t, output.String())
	require.ErrorContains(t, doRecordingExport(t.Context(), exportCommandOptions{
		recordingContentOptions: recordingContentOptions{
			File: fixture.encrypted, WithSensitiveOpts: common.WithSensitiveOpts{WithSensitive: true},
			ExpectedProducerID: fixture.identity.ProducerId().String(), DecryptionIdentityFilesOpts: common.DecryptionIdentityFilesOpts{DecryptionIdentityFiles: []string{fixture.identityFile}},
		},
		Output: fixture.identityFile, Force: true,
	}, cli.StdoutOfContext(ctx)), "must not replace private key")
}

func TestConfiguredRecordingUsesResolvedConfigurationWithoutReloading(t *testing.T) {
	fixture := createRecordingFixture(t)
	conf, _ := configureRecordingFixture(t, fixture)
	require.NoError(t, os.Remove(conf.Filename))
	options := common.ExecutableConfigurationOpts{Configuration: conf}

	var output bytes.Buffer
	require.NoError(t, doRecordingVerify(t.Context(), verifyCommandOptions{
		ExecutableConfigurationOpts: options, File: "default", RecordingID: fixture.id.String(), Format: format.Json,
	}, &output))
	require.Contains(t, output.String(), `"scope":"full"`)
	output.Reset()
	require.NoError(t, doRecordingExport(t.Context(), exportCommandOptions{
		recordingContentOptions: recordingContentOptions{
			ExecutableConfigurationOpts: options, File: "default", RecordingID: fixture.id.String(),
			WithSensitiveOpts: common.WithSensitiveOpts{WithSensitive: true},
		},
		Output: "-",
	}, &output))
	require.Contains(t, output.String(), "sensitive terminal output")
	output.Reset()
	require.NoError(t, doRecordingPlay(t.Context(), playCommandOptions{
		recordingContentOptions: recordingContentOptions{
			ExecutableConfigurationOpts: options, File: "default", RecordingID: fixture.id.String(),
			WithSensitiveOpts: common.WithSensitiveOpts{WithSensitive: true},
		},
		Speed: 100,
	}, &output))
	require.Equal(t, "sensitive terminal output\n", output.String())
}
