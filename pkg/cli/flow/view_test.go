package flow

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestFlowDetailsRedactArbitraryStringsInEveryFormat(t *testing.T) {
	secret := "embedded-bearer-token"
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "production", Auditlog: "default",
		Environment: configuration.Environment{
			V: &configuration.EnvironmentDocker{
				Image:        template.MustNewString("registry.example.org/team/" + secret),
				ShellCommand: template.MustNewStrings("sh", "-c", "use "+secret),
			},
			Variables: configuration.EnvironmentVariables{"TOKEN": template.MustNewString(secret)},
		},
	}}}
	for _, selected := range []format.Format{format.Text, format.Json, format.Yaml, format.Cbor} {
		var output bytes.Buffer
		require.NoError(t, ShowFlow(&output, selected, conf, "production", false))
		require.NotContains(t, output.String(), secret)
		require.Contains(t, output.String(), "***redacted***")
	}
	var unredacted bytes.Buffer
	require.NoError(t, ShowFlow(&unredacted, format.Json, conf, "production", true))
	require.Contains(t, unredacted.String(), secret)
}
