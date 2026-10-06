package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management"
)

func TestVerificationCommandsSupportJSONAndYAML(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	var recordingJSON bytes.Buffer
	require.NoError(t, doRecordingVerify(&recordingVerifyOpts{
		file: fixture.nativeEncryptedPath, expectedProducerId: fixture.identity.ProducerId().String(), format: "json",
	}, &recordingJSON))
	var status management.VerificationView
	require.NoError(t, json.Unmarshal(recordingJSON.Bytes(), &status))
	require.True(t, status.Verified)
	require.Equal(t, "outer", status.Scope)

	directory := t.TempDir()
	auditlog := createAuditCliTestJournal(t, directory, "default", "test.format")
	ref := writeAuditCliTestConfiguration(t, directory, auditlog)
	var auditJSON bytes.Buffer
	require.NoError(t, doAuditVerifyOutput(&auditVerifyOpts{configuration: ref, auditlog: "default", format: "json"}, &auditJSON))
	require.NoError(t, json.Unmarshal(auditJSON.Bytes(), &status))
	require.Equal(t, "full", status.Scope)
}

func TestAuditlogExportRejectsMisleadingFormatFlag(t *testing.T) {
	app := kingpin.New("bifroest", "test").Terminate(func(int) {})
	parent, options := management.RegisterAuditlogCommands(app, nil, nil, t.Context(), &bytes.Buffer{}, true)
	previous := remoteAuditEventsOpts
	remoteAuditEventsOpts = options
	defer func() { remoteAuditEventsOpts = previous }()
	registerAuditArtifactCommands(parent)
	_, err := app.Parse([]string{"auditlog", "export", "default", "--format=yaml"})
	require.ErrorContains(t, err, "fixed JSON Lines output")
}
