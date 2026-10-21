package recording

import (
	"bytes"
	"os"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func TestRecordingMetadataDoesNotAppendToSelectedArtifact(t *testing.T) {
	for _, command := range []string{"ls", "show"} {
		t.Run(command, func(t *testing.T) {
			fixture := createRecordingFixture(t)
			conf, input := configureRecordingFixture(t, fixture)
			before, err := os.ReadFile(input)
			require.NoError(t, err)
			output, err := os.OpenFile(input, os.O_WRONLY|os.O_APPEND, 0)
			require.NoError(t, err)
			t.Cleanup(func() { _ = output.Close() })
			ctx := cli.ContextWithStdio(t.Context(), nil, output, nil)
			args := []string{"recording", command, "default", "--configuration=" + conf.Filename, "--format=json"}
			if command == "show" {
				args = append(args, fixture.id.String())
			}
			err = newRecordingTestApplication(t).ParseAndExecute(ctx,
				&cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...)
			require.NoError(t, output.Close())
			after, readErr := os.ReadFile(input)
			require.NoError(t, readErr)
			require.True(t, bytes.Equal(before, after), "metadata command modified its signed Recording input")
			require.Error(t, err)
		})
	}
}
