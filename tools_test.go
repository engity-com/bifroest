package bifroest

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestToolVersionsUseTheEmbeddedCanonicalCatalog(t *testing.T) {
	raw, err := os.ReadFile("mise.tools.yaml")
	require.NoError(t, err)
	var catalog map[string]string
	require.NoError(t, yaml.Unmarshal(raw, &catalog))
	for _, name := range []string{"node", "bun", "go", "go_licenses", "syft"} {
		require.Equal(t, catalog["tool_version_"+name], ToolVersion(name))
	}
	require.Panics(t, func() { ToolVersion("missing") })
}
