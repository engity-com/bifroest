package management

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuditlogListAndDetailFormats(t *testing.T) {
	conf := &configuration.Configuration{Auditlogs: configuration.Auditlogs{{Name: "restricted", Enabled: true, IdentityFile: "private-signing-key"}}}
	var output bytes.Buffer
	require.NoError(t, ListAuditlogs(&output, FormatJSON, conf))
	var rows []AuditlogSummary
	require.NoError(t, json.Unmarshal(output.Bytes(), &rows))
	require.Len(t, rows, 1)
	require.Equal(t, "restricted", rows[0].Name.String())
	output.Reset()
	require.NoError(t, ShowAuditlog(&output, FormatYAML, conf, "restricted"))
	require.NotContains(t, output.String(), "private-signing-key")
	require.Contains(t, output.String(), "***redacted***")
	require.ErrorContains(t, ShowAuditlog(&output, FormatTable, conf, "absent"), "does not exist")
}

func TestAuditlogDetailsRedactNestedDeliveryPassword(t *testing.T) {
	conf := &configuration.Configuration{Auditlogs: configuration.Auditlogs{{
		Name: "remote", Targets: configuration.AuditlogTargets{{
			Name: "archive", V: &configuration.AuditlogTargetWebdav{
				Endpoint: "https://archive.example.org/", Username: template.MustNewString("archive-user"),
				Password: template.MustNewString("archive-secret"),
			},
		}},
	}}}
	for _, format := range []Format{FormatTable, FormatJSON, FormatYAML} {
		var output bytes.Buffer
		require.NoError(t, ShowAuditlog(&output, format, conf, "remote"))
		require.Contains(t, output.String(), "***redacted***")
		require.NotContains(t, output.String(), "archive-secret")
	}
}
