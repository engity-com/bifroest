package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestManagementAuditEventsKeepSensitiveBoundary(t *testing.T) {
	directory := t.TempDir()
	configured := createAuditCliTestJournal(t, directory, "default", "test.management")
	ref := writeAuditCliTestConfiguration(t, directory, configured)
	conf := ref.Get()
	expected := auditCliTestProducerId(t, configured.IdentityFile)
	for _, test := range []struct {
		withSensitive bool
		flowPresent   bool
	}{
		{false, false},
		{true, true},
	} {
		records, err := management.ReadAuditEvents(t.Context(), conf, "default", expected, test.withSensitive, nil)
		require.NoError(t, err)
		require.Len(t, records, 1)
		var output bytes.Buffer
		require.NoError(t, management.WriteAuditEvents(&output, management.FormatJSON, records, management.AuditEventFilter{Name: "test.management"}, test.withSensitive))
		var decoded []audit.VerifiedRecord
		require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
		require.Len(t, decoded, 1)
		require.Equal(t, test.flowPresent, decoded[0].Event.Flow != "")
	}
}
