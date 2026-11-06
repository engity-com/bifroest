package configuration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFlowDisplayTitleFallsBackToNameWithoutChangingItsIdentifier(t *testing.T) {
	flow := Flow{Name: "docker"}
	require.Equal(t, "docker", flow.GetTitle())
	flow.Title = "  Development container  "
	require.Equal(t, "Development container", flow.GetTitle())
	require.Equal(t, FlowName("docker"), flow.Name)
	flow.Title = " \t "
	require.Equal(t, "docker", flow.GetTitle())
}
func TestFlowTitleYAMLIsOptionalPlainBoundedText(t *testing.T) {
	for _, title := range []string{"Development container", "Entwicklung", ""} {
		var flow Flow
		require.NoError(t, yaml.Unmarshal([]byte("name: docker\ntitle: '"+title+"'\n"), &flow))
		require.NotEmpty(t, flow.GetTitle())
	}
	for _, value := range []string{"title: 5", "title: [a]", "title: \"bad\\nvalue\"", "title: '" + strings.Repeat("x", 256) + "'"} {
		var flow Flow
		require.Error(t, yaml.Unmarshal([]byte("name: docker\n"+value+"\n"), &flow))
	}
}
