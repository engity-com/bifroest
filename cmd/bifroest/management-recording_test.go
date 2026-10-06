package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management"
)

func TestManagementRecordingInspectionKeepsEncryptedContentPrivate(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	for _, test := range []struct {
		path      string
		encrypted bool
		scope     string
	}{
		{fixture.nativeClearPath, false, "full"},
		{fixture.nativeEncryptedPath, true, "outer"},
	} {
		file, initial, err := openRecordingInput(test.path)
		require.NoError(t, err)
		view, err := management.InspectRecording(t.Context(), "default", file, initial.Size(), fixture.identity.ProducerId())
		require.NoError(t, err)
		require.NoError(t, file.Close())
		require.Equal(t, test.encrypted, view.Encrypted)
		require.Equal(t, test.scope, view.VerificationScope)
		require.Equal(t, fixture.recordingId.String(), view.ID)
		var output bytes.Buffer
		require.NoError(t, management.WriteRecordingDetail(&output, management.FormatJSON, view))
		require.NotContains(t, output.String(), "sensitive terminal output")
	}
}
