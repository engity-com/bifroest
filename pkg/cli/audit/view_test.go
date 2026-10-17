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

func TestAuditlogDetailsKeepDeclaredDeliveryTargetNamesAndTypes(t *testing.T) {
	target := func(name configuration.AuditlogTargetName) configuration.AuditlogTarget {
		return configuration.AuditlogTarget{Name: name, V: &configuration.AuditlogTargetWebdav{
			Endpoint: "https://archive.example.org/", Username: template.MustNewString("private-archive-user"),
			Password: template.MustNewString("private-archive-password"),
		}}
	}
	conf := &configuration.Configuration{Auditlogs: configuration.Auditlogs{{
		Name: "default", Targets: configuration.AuditlogTargets{target("audit-archive")},
		Recording: configuration.AuditlogRecording{Targets: configuration.AuditlogRecordingTargets{
			Mode: configuration.AuditlogRecordingTargetsModeCustom, Targets: configuration.AuditlogTargets{target("recording-archive")},
		}},
	}}}
	for _, selected := range []cliformat.Format{cliformat.Text, cliformat.Json, cliformat.Yaml, cliformat.Cbor, cliformat.WireCbor} {
		var output bytes.Buffer
		require.NoError(t, ShowAuditlog(&output, selected, conf, "default"))
		require.NotContains(t, output.String(), "private-")
		require.NotContains(t, output.String(), "archive.example.org")
		require.Contains(t, output.String(), "audit-archive")
		require.Contains(t, output.String(), "recording-archive")
		require.Contains(t, output.String(), "webdav")
	}
	var output bytes.Buffer
	require.NoError(t, ShowAuditlog(&output, cliformat.Json, conf, "default"))
	var settings map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &settings))
	require.Equal(t, "default", settings["name"])
	entry := settings["targets"].([]any)[0].(map[string]any)
	require.Equal(t, "audit-archive", entry["name"])
	require.Equal(t, "webdav", entry["type"])
	entry = settings["recording"].(map[string]any)["targets"].([]any)[0].(map[string]any)
	require.Equal(t, "recording-archive", entry["name"])
	require.Equal(t, "webdav", entry["type"])
}
