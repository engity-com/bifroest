package main

import (
	"bytes"
	goos "os"
	"path/filepath"
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

func TestRecordingShowIgnoresUnrelatedCorruptArtifact(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	root := t.TempDir()
	sealed := filepath.Join(root, "recordings", "sealed")
	require.NoError(t, goos.MkdirAll(sealed, 0700))
	content, err := goos.ReadFile(fixture.nativeClearPath)
	require.NoError(t, err)
	require.NoError(t, goos.WriteFile(filepath.Join(sealed, fixture.recordingId.String()+".bcast"), content, 0600))
	require.NoError(t, goos.WriteFile(filepath.Join(sealed, "11111111-1111-4111-8111-111111111111.bcast"), []byte("corrupt"), 0600))
	configPath := filepath.Join(root, "configuration.yaml")
	configuration := "auditlog:\n  - enabled: false\n    identityFile: " + fixture.signingIdentityPath + "\n    recording:\n      enabled: true\n      directory: " + filepath.Join(root, "recordings") + "\nflows:\n  - name: flow\n    authorization:\n      type: simple\n    environment:\n      type: dummy\n"
	require.NoError(t, goos.WriteFile(configPath, []byte(configuration), 0600))
	_, err = inspectLocalRecordings(t.Context(), configPath, "default")
	require.Error(t, err)
	view, err := inspectLocalRecording(t.Context(), configPath, "default", fixture.recordingId)
	require.NoError(t, err)
	require.Equal(t, fixture.recordingId.String(), view.ID)
}
