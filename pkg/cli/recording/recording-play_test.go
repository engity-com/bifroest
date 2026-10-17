package recording

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func newRecordingPlaybackTestApplication(t *testing.T) *cli.Application[cli.NoOptions] {
	t.Helper()
	app := cli.NewSimpleApplication("test").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithCommand(CreateCommands()...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	return app
}

func TestRecordingContentDoesNotAppendToInputOrDecryptionIdentity(t *testing.T) {
	for _, command := range []string{"play", "export"} {
		for _, encrypted := range []bool{false, true} {
			for _, target := range []string{"input", "decryption-identity"} {
				for _, alias := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/encrypted=%t/%s/alias=%t", command, encrypted, target, alias), func(t *testing.T) {
						fixture := createRecordingFixture(t)
						input := fixture.clear
						if encrypted {
							input = fixture.encrypted
						}
						path := input
						if target == "decryption-identity" {
							path = fixture.identityFile
						}
						args := []string{"recording", command, input, "--with-sensitive",
							"--expectedProducerId=" + fixture.identity.ProducerId().String(),
							"--decryptionIdentityFile=" + fixture.identityFile,
						}
						if command == "play" {
							args = append(args, "--speed=100")
						}
						assertRecordingRejectsAppend(t, args, path, alias)
					})
				}
			}
		}
	}
}

func TestConfiguredRecordingContentProtectsFinalOutput(t *testing.T) {
	for _, command := range []string{"play", "export"} {
		for _, target := range []string{"input", "signing-identity", "configuration", "other-recording", "session-storage"} {
			for _, alias := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/alias=%t", command, target, alias), func(t *testing.T) {
					fixture := createRecordingFixture(t)
					conf, input := configureRecordingFixture(t, fixture)
					path := input
					switch target {
					case "signing-identity":
						path = fixture.signingIdentityFile
					case "configuration":
						path = conf.Filename
					case "other-recording":
						path = filepath.Join(conf.Auditlogs[0].Recording.Directory, "keep-evidence")
						require.NoError(t, os.WriteFile(path, []byte("preserve recording repository"), 0600))
					case "session-storage":
						root := conf.Session.V.(*configuration.SessionFs).Storage
						require.NoError(t, os.MkdirAll(root, 0700))
						path = filepath.Join(root, "keep-session")
						require.NoError(t, os.WriteFile(path, []byte("preserve session storage"), 0600))
					}
					args := []string{"recording", command, "default", fixture.id.String(),
						"--with-sensitive", "--configuration=" + conf.Filename,
					}
					if command == "play" {
						args = append(args, "--speed=100")
					}
					assertRecordingRejectsAppend(t, args, path, alias)
				})
			}
		}
	}
}

func assertRecordingRejectsAppend(t *testing.T, args []string, path string, alias bool) {
	t.Helper()
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	outputPath := path
	if alias {
		outputPath = filepath.Join(t.TempDir(), "output-alias")
		if err := os.Link(path, outputPath); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
	}
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = output.Close() })
	ctx := cli.ContextWithStdio(t.Context(), nil, output, nil)
	err = newRecordingPlaybackTestApplication(t).ParseAndExecute(ctx,
		&cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...)
	require.NoError(t, output.Close())
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.True(t, bytes.Equal(before, after), "command modified protected file %s", path)
	require.Error(t, err)
}

func TestRecordingPlayAllowsSafeFileAndPropagatesOutputFailure(t *testing.T) {
	fixture := createRecordingFixture(t)
	args := []string{"recording", "play", fixture.clear, "--with-sensitive", "--speed=100",
		"--expectedProducerId=" + fixture.identity.ProducerId().String(),
	}
	app := newRecordingPlaybackTestApplication(t)
	opts := &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}
	path := filepath.Join(t.TempDir(), "playback.txt")
	output, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = output.Close() })
	ctx := cli.ContextWithStdio(t.Context(), nil, output, nil)
	require.NoError(t, app.ParseAndExecute(ctx, opts, args...))
	require.NoError(t, output.Close())
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "sensitive terminal output\n", string(content))

	ctx = cli.ContextWithStdio(t.Context(), nil, failedPlaybackOutput{}, nil)
	require.ErrorIs(t, app.ParseAndExecute(ctx, opts, args...), io.ErrClosedPipe)
}

func TestRemoteRecordingPlayProtectsLocalDecryptionIdentity(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			fixture := createRecordingFixture(t)
			input := fixture.clear
			if encrypted {
				input = fixture.encrypted
			}
			artifact, err := os.ReadFile(input)
			require.NoError(t, err)
			before, err := os.ReadFile(fixture.identityFile)
			require.NoError(t, err)
			target, done := recordingArtifactTestServer(t, fixture.id, fixture.identity.ProducerId().String(), artifact)
			output, err := os.OpenFile(fixture.identityFile, os.O_WRONLY|os.O_APPEND, 0)
			require.NoError(t, err)
			t.Cleanup(func() { _ = output.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			ctx = common.ContextWithRemoteTarget(ctx, target)
			ctx = cli.ContextWithStdio(ctx, nil, output, nil)
			err = newRecordingPlaybackTestApplication(t).ParseAndExecute(ctx,
				&cli.ParseOpts{Profiles: []string{common.ProfileRemote}},
				"recording", "play", "default", fixture.id.String(), "--with-sensitive", "--speed=100",
				"--expectedProducerId="+fixture.identity.ProducerId().String(),
				"--decryptionIdentityFile="+fixture.identityFile)
			require.NoError(t, output.Close())
			after, readErr := os.ReadFile(fixture.identityFile)
			require.NoError(t, readErr)
			require.True(t, bytes.Equal(before, after), "remote playback modified the local private key")
			require.Error(t, err)
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("SSH artifact server did not finish")
			}
		})
	}
}

type failedPlaybackOutput struct{}

func (failedPlaybackOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRecordingPlayDoesNotExposeExportDestinationFlags(t *testing.T) {
	app := newRecordingPlaybackTestApplication(t)
	for _, profile := range []string{common.ProfileExecutable, common.ProfileRemote, common.ProfileManagement} {
		t.Run(profile, func(t *testing.T) {
			var help bytes.Buffer
			ctx := cli.ContextWithStdio(t.Context(), nil, &help, nil)
			opts := &cli.ParseOpts{Profiles: []string{profile}}
			require.NoError(t, app.ParseAndExecute(ctx, opts, "recording", "play", "--help"))
			require.NotContains(t, help.String(), "--output")
			require.NotContains(t, help.String(), "--force")
			for _, flag := range []string{"--output=ignored.cast", "--force"} {
				err := app.ParseAndExecute(ctx, opts, "recording", "play", flag)
				require.ErrorContains(t, err, "unknown flag")
			}
		})
	}
}
