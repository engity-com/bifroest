package recording

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestRecordingInspectWindowsDeniesInputMutationBeforeOutput(t *testing.T) {
	fixture := createRecordingFixture(t)
	original, err := os.ReadFile(fixture.clear)
	require.NoError(t, err)
	var output bytes.Buffer
	checked := false
	err = doRecordingInspect(t.Context(), &recordingInspectOpts{
		file: fixture.clear, expectedProducerId: fixture.identity.ProducerId().String(),
		beforeWrite: func() {
			checked = true
			file, err := os.OpenFile(fixture.clear, os.O_WRONLY|os.O_APPEND, 0)
			if file != nil {
				require.NoError(t, file.Close())
			}
			require.ErrorIs(t, err, windows.ERROR_SHARING_VIOLATION)
			require.ErrorIs(t, os.Remove(fixture.clear), windows.ERROR_SHARING_VIOLATION)
			require.Empty(t, output.Bytes(), "publication must follow the final input check")
		},
	}, &output)
	require.NoError(t, err)
	require.True(t, checked)
	var inspection recordingInspectOutput
	require.NoError(t, json.Unmarshal(output.Bytes(), &inspection))
	require.True(t, inspection.Signature.Valid)
	require.True(t, inspection.Signature.Trusted)
	current, err := os.ReadFile(fixture.clear)
	require.NoError(t, err)
	require.Equal(t, original, current)
	// Inspection releases its read handle rather than leaving the input locked.
	writer, err := os.OpenFile(fixture.clear, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
}
