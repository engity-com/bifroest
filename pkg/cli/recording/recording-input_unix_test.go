//go:build unix

package recording

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordingInspectRejectsChangedInputBeforeOutput(t *testing.T) {
	fixture := createRecordingFixture(t)
	var output bytes.Buffer
	err := doRecordingInspect(t.Context(), &recordingInspectOpts{
		file: fixture.clear, expectedProducerId: fixture.identity.ProducerId().String(),
		beforeWrite: func() {
			file, err := os.OpenFile(fixture.clear, os.O_WRONLY|os.O_APPEND, 0)
			require.NoError(t, err)
			_, err = file.Write([]byte("changed"))
			require.NoError(t, err)
			require.NoError(t, file.Close())
		},
	}, &output)
	require.Error(t, err)
	require.Empty(t, output.Bytes())
}
