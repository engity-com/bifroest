package recording

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func TestRecordingInspectRejectsUnsafeUnsupportedAndUntrustedInputs(t *testing.T) {
	fixture := createRecordingFixture(t)
	unsupported := filepath.Join(t.TempDir(), "unsupported")
	require.NoError(t, os.WriteFile(unsupported, []byte("unsupported recording format"), 0600))
	for _, path := range []string{filepath.Dir(unsupported), unsupported, fixture.clear} {
		var output bytes.Buffer
		err := doRecordingInspect(t.Context(), &recordingInspectOpts{file: path, expectedProducerId: strings.Repeat("1", 64)}, &output)
		require.Error(t, err)
		require.Empty(t, output.Bytes())
	}
	alias := filepath.Join(t.TempDir(), "input-link")
	if err := os.Symlink(fixture.clear, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var output bytes.Buffer
	require.Error(t, doRecordingInspect(t.Context(), &recordingInspectOpts{file: alias}, &output))
	require.Empty(t, output.Bytes())
}

func TestRecordingExportCleansSnapshotsAfterVerificationFailure(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "wrong-producer"
		if encrypted {
			name = "missing-decryption-key"
		}
		t.Run(name, func(t *testing.T) {
			fixture := createRecordingFixture(t)
			input, producer := fixture.clear, strings.Repeat("1", 64)
			if encrypted {
				input, producer = fixture.encrypted, fixture.identity.ProducerId().String()
			}
			directory := t.TempDir()
			setRecordingSnapshotTestDirectory(t, directory)
			var output bytes.Buffer
			err := doRecordingExport(t.Context(), exportCommandOptions{
				recordingContentOptions: recordingContentOptions{
					File: input, ExpectedProducerID: producer, WithSensitiveOpts: common.WithSensitiveOpts{WithSensitive: true},
				},
				Output: "-",
			}, &output)
			require.Error(t, err)
			require.Empty(t, output.Bytes())
			entries, err := os.ReadDir(directory)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}
