package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	cliformat "github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuditlogListAndDetailFormats(t *testing.T) {
	conf := &configuration.Configuration{Auditlogs: configuration.Auditlogs{{Name: "restricted", Enabled: true, IdentityFile: "private-signing-key"}}}
	var output bytes.Buffer
	require.NoError(t, ListAuditlogs(&output, cliformat.Json, conf))
	var rows []model.AuditlogSummary
	require.NoError(t, json.Unmarshal(output.Bytes(), &rows))
	require.Len(t, rows, 1)
	require.Equal(t, "restricted", rows[0].Name.String())
	output.Reset()
	require.NoError(t, ShowAuditlog(&output, cliformat.Yaml, conf, "restricted"))
	require.NotContains(t, output.String(), "private-signing-key")
	require.Contains(t, output.String(), "***redacted***")
	require.ErrorContains(t, ShowAuditlog(&output, cliformat.Text, conf, "absent"), "does not exist")
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
	for _, selected := range []cliformat.Format{cliformat.Text, cliformat.Json, cliformat.Yaml} {
		var output bytes.Buffer
		require.NoError(t, ShowAuditlog(&output, selected, conf, "remote"))
		require.Contains(t, output.String(), "***redacted***")
		require.NotContains(t, output.String(), "archive-secret")
	}
}
