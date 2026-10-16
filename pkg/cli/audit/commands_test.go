package audit

import (
	"bytes"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/echocat/cli4g/codec"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestAuditCLIReusesSchemaAndControlsSensitiveExport(t *testing.T) {
	configured := createAuditCliTestJournal(t, t.TempDir(), "default", "test.event")
	configurationPath := writeAuditCliTestConfiguration(t, t.TempDir(), configured)
	requirement := cli.NewSimpleApplication().WithName("bifroest").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithCodec(codec.NewDateTime().WithFormats(time.RFC3339), "rfc3339")
	requirement.WithCommand(CreateCommands()...)
	app, err := requirement.Create()
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()

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
		ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, invocation.args...))
		require.Contains(t, output.String(), invocation.contains)
		if invocation.notContains != "" {
			require.NotContains(t, output.String(), invocation.notContains)
		}
	}
}
