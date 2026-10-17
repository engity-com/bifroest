package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditCLIControlsSensitiveExportAcrossInvocations(t *testing.T) {
	configured := createAuditCliTestJournal(t, t.TempDir(), "default", "test.event")
	configurationPath := writeAuditCliTestConfiguration(t, t.TempDir(), configured)
	app := newAuditCliTestApplication(t)

	for _, invocation := range []struct {
		args        []string
		contains    string
		notContains string
	}{
		{[]string{"audit", "verify", "default", "-c", configurationPath}, "verified", "confidential-flow"},
		{[]string{"audit", "export", "default", "-c", configurationPath}, "test.event", "confidential-flow"},
		{[]string{"audit", "export", "default", "-c", configurationPath, "--with-sensitive"}, "confidential-flow", ""},
		{[]string{"audit", "ls", "-c", configurationPath, "--format=json"}, "default", "confidential-flow"},
	} {
		var output bytes.Buffer
		require.NoError(t, runAuditCliTestCommand(t, app, &output, invocation.args...))
		require.Contains(t, output.String(), invocation.contains)
		if invocation.notContains != "" {
			require.NotContains(t, output.String(), invocation.notContains)
		}
	}
}

func TestAuditExportsKeepOnlyPublicEventFieldsByDefault(t *testing.T) {
	configured := createAuditCliTestJournal(t, t.TempDir(), "default", "test.public")
	path := writeAuditCliTestConfiguration(t, t.TempDir(), configured)
	app := newAuditCliTestApplication(t)
	for _, command := range []string{"export", "decrypt", "merge"} {
		var output bytes.Buffer
		require.NoError(t, runAuditCliTestCommand(t, app, &output, "audit", command, "default", "--configuration="+path))
		var record map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(output.Bytes(), &record))
		require.Len(t, record, 9)
		for _, field := range []string{"auditlog", "producerId", "segmentSequence", "segmentRecordIndex", "id", "recordedAt", "event", "previousHash", "hash"} {
			require.Contains(t, record, field)
		}
		var event map[string]string
		require.NoError(t, json.Unmarshal(record["event"], &event))
		require.Equal(t, map[string]string{"name": "test.public", "domain": "session", "outcome": "success"}, event)
	}
}
