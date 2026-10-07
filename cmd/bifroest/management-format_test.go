package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/audit"
	"github.com/engity-com/bifroest/pkg/cli/recording"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestVerificationCommandsSupportJSONAndYAML(t *testing.T) {
	fixture := recording.newRecordingExportTestFixture(t)
	var recordingJSON bytes.Buffer
	require.NoError(t, recording.doRecordingVerify(&recording.recordingVerifyOpts{
		file: fixture.nativeEncryptedPath, expectedProducerId: fixture.identity.ProducerId().String(), format: "json",
	}, &recordingJSON))
	var status management.VerificationView
	require.NoError(t, json.Unmarshal(recordingJSON.Bytes(), &status))
	require.True(t, status.Verified)
	require.Equal(t, "outer", status.Scope)

	directory := t.TempDir()
	auditlog := audit.createAuditCliTestJournal(t, directory, "default", "test.format")
	ref := audit.writeAuditCliTestConfiguration(t, directory, auditlog)
	var auditJSON bytes.Buffer
	require.NoError(t, audit.doAuditVerifyOutput(&audit.auditVerifyOpts{configuration: ref, auditlog: "default", format: "json"}, &auditJSON))
	require.NoError(t, json.Unmarshal(auditJSON.Bytes(), &status))
	require.Equal(t, "full", status.Scope)
}

func TestAuditlogExportRejectsMisleadingFormatFlag(t *testing.T) {
	app := kingpin.New("bifroest", "test").Terminate(func(int) {})
	parent, options := management.RegisterAuditlogCommands(app, nil, nil, t.Context(), &bytes.Buffer{}, true)
	previous := audit.remoteAuditEventsOpts
	audit.remoteAuditEventsOpts = options
	defer func() { audit.remoteAuditEventsOpts = previous }()
	audit.registerAuditArtifactCommands(parent)
	_, err := app.Parse([]string{"auditlog", "export", "default", "--format=yaml"})
	require.ErrorContains(t, err, "fixed JSON Lines output")
}
